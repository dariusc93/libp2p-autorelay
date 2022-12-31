pub mod utils;

use core::task::{Context, Poll};
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use libp2p::core::transport::ListenerId;
use libp2p::core::{connection::ConnectionId, ConnectedPoint, Multiaddr, PeerId};
use libp2p::multiaddr::Protocol;
use libp2p::relay::v2::client::Event as RelayClientEvent;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, DialError, NetworkBehaviour,
    PollParameters,
};
use log::{info, trace, warn};
use rand::seq::SliceRandom;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::Duration;
use wasm_timer::{Instant, Interval};

#[derive(Debug, Clone)]
pub enum Event {
    ReservationSelected {
        peer_id: PeerId,
        addrs: Vec<Multiaddr>,
    },
    ReservationRemoved {
        peer_id: PeerId,
        listener: ListenerId,
    },
    Added {
        peer_id: PeerId,
        addr: Vec<Multiaddr>,
    },
    FindCandidate(UnboundedSender<(PeerId, Vec<Multiaddr>)>),
    CandidateLimitReached {
        current: usize,
        limit: usize,
    },
    ReservationLimitReached {
        current: usize,
        limit: usize,
    },
}

type NetworkBehaviourAction = swarm::NetworkBehaviourAction<Event, DummyConnectionHandler>;

#[derive(Debug, Copy, Clone)]
pub struct RelayLimits {
    pub min_candidates: usize,
    pub max_candidates: usize,
    pub min_reservation: usize,
    pub max_reservation: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            min_candidates: 1,
            max_candidates: 20,
            min_reservation: 1,
            max_reservation: 2,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
//note: Should only really be used internally to determine nat status
//      if autonat is used, otherwise this can be ignored
//TODO: Determine if this is something we should listen on?
pub enum Nat {
    Public,
    Private,
    #[default]
    Unknown,
}

#[allow(dead_code)]
//Note: `candidates_without_addr` is not in use but is meant to be used for fetching from
//      kad providers (or just sending peers through channels that will be used as a relay)
pub struct AutoRelay {
    events: VecDeque<NetworkBehaviourAction>,

    pending_candidates: HashMap<PeerId, Vec<Multiaddr>>,

    candidates_without_addr: HashSet<PeerId>,

    candidates: HashMap<PeerId, Vec<Multiaddr>>,

    candidates_rtt: HashMap<PeerId, [Duration; 3]>,

    candidates_connection: HashMap<ConnectionId, Multiaddr>,

    reservation: HashMap<PeerId, HashMap<ListenerId, Multiaddr>>,

    pending_reservation_peer: HashSet<PeerId>,

    channel: Option<UnboundedReceiver<(PeerId, Vec<Multiaddr>)>>,

    // Will have a delay start, but will be used to find candidates that might be used
    interval: Interval,

    provider_interval: Option<Interval>,

    // Note: In case we should ignore any relays, such as some who have had bad connection,
    //       ping, not reliable in some, or might want to temporarily ignore
    // If the value is `None` the peer will remain blacklisted
    // TODO: add logic to handle duration, if any
    blacklist: HashMap<PeerId, Option<Duration>>,

    // Used to check for the nat status. If we are not behind a NAT, then a relay probably should not be used
    // since a direct connection could be established
    // TODO: Investigate if the status changes when port mapping is done
    nat_status: Nat,

    limits: RelayLimits,
}

impl Default for AutoRelay {
    fn default() -> Self {
        Self {
            events: Default::default(),
            pending_candidates: Default::default(),
            candidates_without_addr: Default::default(),
            candidates: Default::default(),
            candidates_rtt: Default::default(),
            candidates_connection: Default::default(),
            channel: None,
            reservation: Default::default(),
            pending_reservation_peer: Default::default(),
            blacklist: Default::default(),
            interval: Interval::new_at(
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            provider_interval: None,
            nat_status: Nat::Unknown,
            limits: Default::default(),
        }
    }
}

impl AutoRelay {
    pub fn limits(&self) -> RelayLimits {
        self.limits
    }

    pub fn candidates_amount(&self) -> usize {
        self.candidates.len()
    }

    pub fn reservation_amount(&self) -> usize {
        self.reservation.len()
    }

    // Used to manually add a relay candidate
    pub fn add_static_relay(&mut self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
        //TODO: Maybe strip invalid protocols from address?
        if addr
            .iter()
            .any(|proto| matches!(proto, Protocol::P2pCircuit | Protocol::P2p(_)))
        {
            anyhow::bail!("address contained an invalid protocol");
        }

        info!("Attempting to add {peer_id} as a static relay");

        //TODO: If address contains a dns, maybe we should resolve it?
        if let Entry::Occupied(entry) = self.pending_candidates.entry(peer_id) {
            if entry.get().contains(&addr) {
                anyhow::bail!("Address is already pending");
            }
        }

        if let Entry::Occupied(entry) = self.candidates.entry(peer_id) {
            if entry.get().contains(&addr) {
                anyhow::bail!("Address is already added");
            }
        }

        trace!("Connecting to {:?}", addr);

        let new_addr = addr.clone().with(Protocol::P2p(peer_id.into()));

        let handler = self.new_handler();

        //Thought: Should we set with a new peer instead and have the condition set to always in the event we are connected but the peer somehow was not
        //         apart of the list here?
        self.events.push_back(NetworkBehaviourAction::Dial {
            opts: DialOpts::unknown_peer_id().address(new_addr).build(),
            handler,
        });

        self.pending_candidates
            .entry(peer_id)
            .or_default()
            .push(addr);

        Ok(())
    }

    pub fn list_candidates(&self) -> impl Iterator<Item = &PeerId> {
        self.candidates.keys()
    }

    pub fn list_candidates_addr(&self) -> impl Iterator<Item = Vec<Multiaddr>> + '_ {
        self.candidates.iter().map(|(peer, addrs)| {
            addrs
                .iter()
                .cloned()
                .map(|addr| addr.with(Protocol::P2p((*peer).into())))
                .collect::<Vec<_>>()
        })
    }

    pub fn list_reservation_peers(&self) -> impl Iterator<Item = &PeerId> + '_ {
        self.reservation.keys()
    }

    pub fn in_candidate_threshold(&self) -> bool {
        self.candidates.len() >= self.limits.min_candidates
            && self.candidates.len() <= self.limits.max_candidates
    }

    pub fn out_of_candidate_threshold(&self) -> bool {
        self.candidates.len() < self.limits.min_candidates
            || self.candidates.len() > self.limits.max_candidates
    }

    pub fn in_reservation_threshold(&self) -> bool {
        self.reservation.len() >= self.limits.min_reservation
            && self.reservation.len() <= self.limits.max_reservation
    }

    pub fn avg_rtt(&self, peer_id: PeerId) -> Option<u128> {
        let rtts = self.candidates_rtt.get(&peer_id).copied()?;
        let avg: u128 = rtts.iter().map(|duration| duration.as_millis()).sum();
        // used in case we cant produce a full avg
        let div = rtts.iter().filter(|i| !i.is_zero()).count() as u128;
        let avg = avg / div;
        Some(avg)
    }

    #[allow(dead_code)]
    //TODO: Maybe ignore for now?
    pub(crate) fn change_nat(&mut self, nat: Nat) {
        self.nat_status = nat;
        //TODO: If nat change to public to probably disconnect relay
        //      but if it change to private to attempt to utilize a relay
    }

    pub fn select_candidate(&mut self, peer_id: PeerId) {
        // We remove to prevent duplications
        if let Some(addrs) = self.candidates.get(&peer_id).cloned() {
            if self.pending_reservation_peer.insert(peer_id) {
                self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                    Event::ReservationSelected { peer_id, addrs },
                ));
            }
        }
    }

    pub fn find_candidates(&mut self, blacklist: bool) {
        if blacklist {
            for peer_id in self.candidates.keys() {
                self.blacklist.insert(*peer_id, None);
            }
        }

        self.candidates.clear();
        self.candidates_rtt.clear();

        let (tx, rx) = unbounded();

        self.channel = Some(rx);

        self.provider_interval = Some(Interval::new_at(
            Instant::now() + Duration::from_secs(1),
            Duration::from_secs(5),
        ));

        self.events
            .push_back(NetworkBehaviourAction::GenerateEvent(Event::FindCandidate(
                tx,
            )));
    }

    // This will select a candidate with the lowest ping
    //NOTE: Might have a function that would randomize the selection
    //      rather than relying on low rtt but it might be better this
    //      way
    pub fn select_candidate_low_rtt(&mut self) {
        if self.candidates.len() < self.limits.min_candidates {
            warn!("Candidates are below threshold");
            return;
        }

        if self.reservation.len() >= self.limits.max_reservation {
            warn!("Reservation is at its threshold. Will not continue with select");
            return;
        }

        let mut best_candidate = None;
        let mut last_rtt: Option<Duration> = None;

        for peer_id in self.candidates.keys() {
            if self.reservation.contains_key(peer_id)
                || self.blacklist.contains_key(peer_id)
                || self.pending_reservation_peer.contains(peer_id)
            {
                continue;
            }
            let Some(avg_rtt) = self.avg_rtt(*peer_id) else {
                continue;
            };

            if let Some(current) = last_rtt.as_mut() {
                if avg_rtt < current.as_millis() {
                    *current = Duration::from_millis(avg_rtt as _);
                    best_candidate = Some(*peer_id);
                }
            } else {
                last_rtt = Some(Duration::from_millis(avg_rtt as _));
                best_candidate = Some(*peer_id);
            }
        }

        //Note/TODO: If rtt is high for the best candidate it then it might be best to eject all
        //      candidates and fill up the map with new ones?

        let Some(peer_id) = best_candidate else {
            warn!("No candidate was found");
            return;
        };

        if self.pending_reservation_peer.contains(&peer_id) {
            return;
        }

        if self.reservation.get(&peer_id).is_some() {
            return;
        }

        self.select_candidate(peer_id);
    }

    pub fn select_candidate_random(&mut self) {
        if self.candidates.len() < self.limits.min_candidates {
            warn!("Candidates are below threshold");
            return;
        }

        if self.reservation.len() >= self.limits.max_reservation {
            warn!("Reservation is at its threshold. Will not continue with selection");
            return;
        }

        let mut rng = rand::thread_rng();

        let list = self.candidates.keys().copied().collect::<Vec<_>>();

        let Some(candidate) = list
            .choose(&mut rng) else {
                return;
            };

        if self.reservation.get(candidate).is_some() {
            return;
        }

        self.select_candidate(*candidate);
    }

    pub fn set_candidate_rtt(&mut self, peer_id: PeerId, rtt: Duration) {
        if self.candidates.contains_key(&peer_id) {
            self.candidates_rtt
                .entry(peer_id)
                .and_modify(|r| {
                    r.rotate_left(1);
                    r[2] = rtt;
                })
                .or_insert([Duration::from_millis(0), Duration::from_millis(0), rtt]);
        }
    }

    pub fn inject_candidate(&mut self, peer_id: PeerId, addrs: Vec<Multiaddr>) {
        let candidates_size = self.candidates.len();

        if candidates_size >= self.limits.max_candidates || self.blacklist.contains_key(&peer_id) {
            return;
        }

        let mut filtered_addrs = vec![];

        for addr in addrs {
            if let Some(protocol) = addr.iter().next() {
                // Not sure of any use case where a loopback is used as a relay so this will get filtered
                // but do we want to also check the private ip? For now it will be done but maybe
                // allow a configuration to accept it for internal use?

                //TODO: Cleanup logic for checking for unroutable addresses
                let ip = match protocol {
                    // Checking for private ip here since IpAddr doesnt allow us to do that
                    Protocol::Ip4(ip) if !ip.is_private() => IpAddr::V4(ip),
                    Protocol::Ip6(ip) => IpAddr::V6(ip),
                    _ => continue,
                };
                //TODO: Use IpAddr::is_global once stable
                if ip.is_loopback() {
                    continue;
                }
            }
            filtered_addrs.push(addr);
        }

        match self.candidates.entry(peer_id) {
            Entry::Vacant(entry) => {
                entry.insert(filtered_addrs.clone());
                self.events
                    .push_back(NetworkBehaviourAction::GenerateEvent(Event::Added {
                        peer_id,
                        addr: filtered_addrs,
                    }));
            }
            Entry::Occupied(mut entry) => {
                *entry.get_mut() = filtered_addrs;
            }
        };
    }

    //Note: Maybe import the relay behaviour here so we can poll the events ourselves rather than injecting it into this behaviour
    pub fn inject_relay_client_event(&mut self, event: RelayClientEvent) {
        match event {
            RelayClientEvent::ReservationReqAccepted { relay_peer_id, .. } => {
                info!("Reservation accepted with {relay_peer_id}");
            }
            RelayClientEvent::ReservationReqFailed {
                relay_peer_id,
                error,
                ..
            } => {
                let listeners = self.reservation.remove(&relay_peer_id);
                self.candidates.remove(&relay_peer_id);
                self.blacklist.insert(relay_peer_id, None);
                log::error!("Reservation request failed for {relay_peer_id}: {error}");
                if let Some(listeners) = listeners {
                    for (id, _) in listeners {
                        self.events.push_back(NetworkBehaviourAction::GenerateEvent(
                            Event::ReservationRemoved {
                                peer_id: relay_peer_id,
                                listener: id,
                            },
                        ));
                    }
                }
            }
            e => info!("Relay Client Event: {e:?}"),
        }
    }
}

impl NetworkBehaviour for AutoRelay {
    type ConnectionHandler = DummyConnectionHandler;
    type OutEvent = Event;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        DummyConnectionHandler
    }

    fn inject_connection_established(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        _failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        //Note: Because we are not able to obtain the protocols of the connected peer
        //      here, we will not be able to every peer injected into this event as
        //      a candidate. Instead, we will rely on listening on the swarm
        //      and injecting the peer information here if they support v2 relay STOP protocol
        if let Entry::Occupied(mut entry) = self.pending_candidates.entry(*peer_id) {
            if let ConnectedPoint::Dialer { address, .. } = endpoint {
                let addresses = entry.get_mut();

                let (_, address_without_peer) = extract_peer_id_from_multiaddr(address.clone());
                if !addresses.contains(&address_without_peer) {
                    return;
                }

                if let Some(index) = addresses.iter().position(|x| *x == address_without_peer) {
                    addresses.swap_remove(index);
                    if addresses.is_empty() {
                        entry.remove();
                    }
                }

                self.candidates_connection
                    .insert(*connection_id, address.clone());

                self.candidates
                    .entry(*peer_id)
                    .or_default()
                    .push(address_without_peer.clone());

                self.events
                    .push_back(NetworkBehaviourAction::GenerateEvent(Event::Added {
                        peer_id: *peer_id,
                        addr: vec![address_without_peer],
                    }))
            }
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        id: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: Self::ConnectionHandler,
        _remaining_established: usize,
    ) {
        if let Entry::Occupied(mut entry) = self.candidates.entry(*peer_id) {
            let addresses = entry.get_mut();

            if let Some(address) = self.candidates_connection.remove(id) {
                if let Some(pos) = addresses.iter().position(|a| *a == address) {
                    addresses.swap_remove(pos);
                }

                //TODO: Check to determine if we have a reservation and if so
                //      to send an event and begin the process of finding another candidates
                if addresses.is_empty() {
                    entry.remove();
                }
            }
        }
    }

    fn inject_event(&mut self, _peer_id: PeerId, _connection: ConnectionId, _event: void::Void) {}

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        if !addr
            .iter()
            .any(|proto| matches!(proto, Protocol::P2pCircuit | Protocol::P2p(_)))
        {
            // We want to make sure that we only collect addresses that contained p2p and p2p-circuit protocols
            return;
        }

        let mut addr = addr.clone();

        //not sure if we want to store the p2p protocol but for now strip it out
        let Some(Protocol::P2p(_)) = addr.pop() else {
            return;
        };

        let Some(Protocol::P2pCircuit) = addr.pop() else {
            return;
        };

        let Some(peer_id) = peer_id_from_multiaddr(addr.clone()) else {
            return;
        };

        if let Some(listeners) = self.reservation.get(&peer_id) {
            if listeners.contains_key(&id) {
                return;
            }
        }

        self.pending_reservation_peer.remove(&peer_id);

        match self.reservation.entry(peer_id) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().insert(id, addr.clone());
            }
            Entry::Vacant(entry) => {
                let mut listeners = HashMap::new();
                listeners.insert(id, addr.clone());
                entry.insert(listeners);
            }
        };
    }

    fn inject_expired_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {
        //TODO
    }

    fn inject_listener_closed(&mut self, _id: ListenerId, _reason: Result<(), &std::io::Error>) {
        //TODO
    }

    fn inject_listener_error(&mut self, _id: ListenerId, _: &(dyn std::error::Error + 'static)) {}

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        error: &DialError,
    ) {
        if let Some(peer_id) = peer_id {
            if let Entry::Occupied(mut entry) = self.pending_candidates.entry(peer_id) {
                let addresses = entry.get_mut();

                match error {
                    DialError::Transport(multiaddrs) => {
                        for (addr, _) in multiaddrs {
                            let (peer, maddr) = extract_peer_id_from_multiaddr(addr.clone());
                            if let Some(peer) = peer {
                                if peer != peer_id {
                                    //Note: Unlikely to happen but a precaution
                                    //TODO: Maybe panic here if there is ever a mismatch to note as a bug
                                    warn!("PeerId mismatch. {peer} != {peer_id}");
                                }
                            }

                            if let Some(pos) = addresses.iter().position(|a| *a == maddr) {
                                addresses.swap_remove(pos);
                            }
                        }
                    }
                    _e => {}
                }

                if addresses.is_empty() {
                    entry.remove();
                }
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<swarm::NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        while let Poll::Ready(Some(_)) = self.interval.poll_next_unpin(cx) {
            if self.in_candidate_threshold() && !self.in_reservation_threshold() {
                self.select_candidate_low_rtt();
            }
        }

        let mut provider_interval = std::mem::take(&mut self.provider_interval);

        let mut closed = false;

        if let Some(interval) = provider_interval.as_mut() {
            while let Poll::Ready(Some(_)) = interval.poll_next_unpin(cx) {
                //TODO: Probably change logic to use `inject_candidate` while polling the swarm
                //      than sending through a channel
                let mut channel = std::mem::take(&mut self.channel);

                if let Some(rx) = channel.as_mut() {
                    loop {
                        match rx.poll_next_unpin(cx) {
                            Poll::Ready(Some((peer_id, addrs))) => {
                                if !self.candidates.contains_key(&peer_id) {
                                    self.inject_candidate(peer_id, addrs)
                                }
                            }
                            Poll::Ready(None) => {
                                closed = true;
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                }

                if !closed {
                    if let Some(rx) = channel {
                        self.channel = Some(rx);
                    }
                }
            }
        }

        if !closed {
            if let Some(interval) = provider_interval {
                self.provider_interval = Some(interval);
            }
        }

        Poll::Pending
    }
}

pub(crate) fn peer_id_from_multiaddr(addr: Multiaddr) -> Option<PeerId> {
    let (peer, _) = extract_peer_id_from_multiaddr(addr);
    peer
}

#[allow(dead_code)]
pub(crate) fn extract_peer_id_from_multiaddr(mut addr: Multiaddr) -> (Option<PeerId>, Multiaddr) {
    match addr.pop() {
        Some(Protocol::P2p(hash)) => match PeerId::from_multihash(hash) {
            Ok(id) => (Some(id), addr),
            _ => (None, addr),
        },
        _ => (None, addr),
    }
}
