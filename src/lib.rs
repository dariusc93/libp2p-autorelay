pub mod utils;

use core::task::{Context, Poll};
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use libp2p::core::transport::ListenerId;
use libp2p::core::Endpoint;
use libp2p::core::Multiaddr;
use libp2p::identity::PeerId;
use libp2p::multiaddr::Protocol;
use libp2p::relay::client::Event as RelayClientEvent;
use libp2p::swarm::derive_prelude::NewListener;
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, PollParameters, ToSwarm,
};
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, DialFailure, ExpiredListenAddr, ListenOpts,
    ListenerClosed, ListenerError, NetworkBehaviour, NewListenAddr, THandler, THandlerInEvent,
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
    FindCandidates,
    FindProviders(UnboundedSender<(PeerId, Vec<Multiaddr>)>),
}

#[derive(Debug, Copy, Clone)]
pub struct RelayLimits {
    pub max_candidates: usize,
    pub max_reservation: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_candidates: 20,
            max_reservation: 1,
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

#[derive(Debug, Clone)]
pub struct Reservsation {
    pub peer_id: PeerId,
    pub addr: Vec<Multiaddr>,
}

#[allow(dead_code)]
//Note: `candidates_without_addr` is not in use but is meant to be used for fetching from
//      kad providers (or just sending peers through channels that will be used as a relay)
pub struct Behaviour {
    events: VecDeque<ToSwarm<<Self as NetworkBehaviour>::ToSwarm, THandlerInEvent<Self>>>,

    pending_candidates: HashMap<PeerId, Vec<ConnectionId>>,

    candidates_without_addr: HashSet<PeerId>,

    candidates: HashMap<PeerId, Vec<Multiaddr>>,

    candidates_rtt: HashMap<PeerId, [Duration; 3]>,

    candidates_connection: HashMap<ConnectionId, Multiaddr>,

    reservations: HashMap<ListenerId, Reservsation>,

    pending_reservation: HashMap<PeerId, ListenerId>,

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
    nat_status: Nat,

    running: bool,

    limits: RelayLimits,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            events: Default::default(),
            pending_candidates: Default::default(),
            candidates_without_addr: Default::default(),
            candidates: Default::default(),
            candidates_rtt: Default::default(),
            candidates_connection: Default::default(),
            channel: None,
            reservations: Default::default(),
            pending_reservation: Default::default(),
            blacklist: Default::default(),
            interval: Interval::new_at(
                Instant::now() + Duration::from_secs(10),
                Duration::from_secs(5),
            ),
            provider_interval: None,
            running: false,
            nat_status: Nat::Unknown,
            limits: Default::default(),
        }
    }
}

impl Behaviour {
    pub fn limits(&self) -> RelayLimits {
        self.limits
    }

    pub fn candidates_amount(&self) -> usize {
        self.candidates.len()
    }

    pub fn nat_status(&mut self) -> Nat {
        self.nat_status
    }

    pub fn set_nat(&mut self, nat: Nat) {
        self.nat_status = nat;
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

        if let Entry::Occupied(entry) = self.candidates.entry(peer_id) {
            if entry.get().contains(&addr) {
                anyhow::bail!("Address is already added");
            }
        }

        let opts = DialOpts::peer_id(peer_id)
            .addresses(vec![addr])
            .condition(PeerCondition::Disconnected)
            .build();

        let connection_id = opts.connection_id();

        self.events.push_back(ToSwarm::Dial { opts });

        self.pending_candidates
            .entry(peer_id)
            .or_default()
            .push(connection_id);

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

    pub fn list_reservation(&self) -> impl Iterator<Item = &Reservsation> + '_ {
        self.reservations.values()
    }

    pub fn in_candidate_threshold(&self) -> bool {
        !self.candidates.is_empty() && self.candidates.len() <= self.limits.max_candidates
    }

    pub fn in_reservation_threshold(&self) -> bool {
        !self.reservations.is_empty() && self.reservations.len() <= self.limits.max_reservation
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
        if self
            .list_reservation()
            .any(|reservation| reservation.peer_id == peer_id)
        {
            return;
        }

        if self.pending_reservation.contains_key(&peer_id) {
            return;
        }

        if let Some(addrs) = self.candidates.get(&peer_id).cloned() {
            let addrs = addrs
                .iter()
                .map(|addr| {
                    let mut addr = addr.clone();
                    if !matches!(addr.iter().last(), Some(Protocol::P2pCircuit)) {
                        addr.push(Protocol::P2pCircuit);
                    }
                    addr
                })
                .collect::<Vec<_>>();

            for addr in addrs {
                let opts = ListenOpts::new(addr);
                let listener_id = opts.listener_id();

                if let Entry::Vacant(entry) = self.pending_reservation.entry(peer_id) {
                    entry.insert(listener_id);
                    self.events.push_back(ToSwarm::ListenOn { opts });
                }
            }
        }
    }

    #[allow(dead_code)]
    fn remove_reservation(&mut self, peer_id: PeerId) {
        if !self.candidates.contains_key(&peer_id) {
            return;
        }

        for (listener_id, _) in self
            .reservations
            .iter()
            .filter(|(_, reservation)| reservation.peer_id == peer_id)
        {
            self.events
                .push_back(ToSwarm::RemoveListener { id: *listener_id });
        }
    }

    pub fn remove_all_reservation(&mut self) {
        for listener_id in self.reservations.keys() {
            self.events
                .push_back(ToSwarm::RemoveListener { id: *listener_id });
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
            .push_back(ToSwarm::GenerateEvent(Event::FindProviders(tx)));
    }

    // This will select a candidate with the lowest ping
    //NOTE: Might have a function that would randomize the selection
    //      rather than relying on low rtt but it might be better this
    //      way
    pub fn select_candidate_low_rtt(&mut self) {
        if !matches!(self.nat_status, Nat::Private) {
            return;
        }

        if self.candidates.is_empty() {
            warn!("No candidates available");
            return;
        }

        if self.reservations.len() >= self.limits.max_reservation {
            warn!("Reservation is at its threshold. Will not continue with select");
            return;
        }

        let mut best_candidate = None;
        let mut last_rtt: Option<Duration> = None;

        for peer_id in self.candidates.keys() {
            if self
                .reservations
                .iter()
                .any(|(_, reservation)| reservation.peer_id.eq(peer_id))
                || self.blacklist.contains_key(peer_id)
                || self.pending_reservation.contains_key(peer_id)
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

        if self.pending_reservation.contains_key(&peer_id) {
            return;
        }

        if self
            .reservations
            .iter()
            .any(|(_, reservation)| reservation.peer_id.eq(&peer_id))
        {
            return;
        }

        self.select_candidate(peer_id);
    }

    pub fn select_candidate_random(&mut self) {
        if !matches!(self.nat_status, Nat::Private) {
            return;
        }

        if self.candidates.is_empty() {
            warn!("No candidates available");
            return;
        }

        if self.reservations.len() >= self.limits.max_reservation {
            warn!("Reservation is at its threshold. Will not continue with selection");
            return;
        }

        let mut rng = rand::thread_rng();

        let list = self.candidates.keys().copied().collect::<Vec<_>>();

        let Some(candidate) = list
            .choose(&mut rng) else {
                return;
            };

        if self
            .reservations
            .iter()
            .any(|(_, r)| r.peer_id == *candidate)
        {
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
        if !matches!(self.nat_status, Nat::Private) {
            return;
        }

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
                let listeners = self
                    .reservations
                    .iter()
                    .filter(|(_, reservation)| reservation.peer_id == relay_peer_id)
                    .map(|(listener_id, _)| listener_id)
                    .copied()
                    .collect::<Vec<_>>();

                self.blacklist.insert(relay_peer_id, None);

                log::error!("Reservation request failed for {relay_peer_id}: {error}");
                for id in listeners {
                    if self.reservations.remove(&id).is_none() {
                        continue;
                    }
                    self.events.push_back(ToSwarm::RemoveListener { id });
                }
            }
            e => info!("Relay Client Event: {e:?}"),
        }
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = DummyConnectionHandler;
    type ToSwarm = Event;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(DummyConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer_id: PeerId,
        address: &Multiaddr,
        endpoint: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        if let Entry::Occupied(mut e) = self.pending_candidates.entry(peer_id) {
            if matches!(endpoint, Endpoint::Dialer) {
                let entry = e.get_mut();
                if let Some(index) = entry.iter().position(|id| connection_id.eq(id)) {
                    entry.remove(index);

                    self.candidates
                        .entry(peer_id)
                        .or_default()
                        .push(address.clone());

                    self.candidates_connection
                        .insert(connection_id, address.clone());
                }

                if entry.is_empty() {
                    e.remove();
                }
            }
        }
        Ok(DummyConnectionHandler)
    }
    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        _event: swarm::THandlerOutEvent<Self>,
    ) {
    }

    #[allow(clippy::collapsible_match)]
    fn on_swarm_event(&mut self, event: swarm::FromSwarm<Self::ConnectionHandler>) {
        match event {
            swarm::FromSwarm::ConnectionClosed(ConnectionClosed {
                peer_id,
                connection_id,
                ..
            }) => {
                if let Entry::Occupied(mut entry) = self.candidates.entry(peer_id) {
                    let addresses = entry.get_mut();

                    if let Some(address) = self.candidates_connection.remove(&connection_id) {
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
            swarm::FromSwarm::DialFailure(DialFailure {
                peer_id,
                error: _,
                connection_id,
            }) => {
                if let Some(peer_id) = peer_id {
                    if let Entry::Occupied(mut entry) = self.pending_candidates.entry(peer_id) {
                        let connections = entry.get_mut();

                        connections.retain(|id| *id != connection_id);

                        if connections.is_empty() {
                            entry.remove();
                        }
                    }
                }
            }
            swarm::FromSwarm::NewListener(NewListener { listener_id: _ }) => {}
            swarm::FromSwarm::NewListenAddr(NewListenAddr { listener_id, addr }) => {
                if !addr
                    .iter()
                    .any(|proto| matches!(proto, Protocol::P2pCircuit | Protocol::P2p(_)))
                {
                    // We want to make sure that we only collect addresses that contained p2p and p2p-circuit protocols
                    return;
                }

                dbg!(addr);

                let peer_id = match self
                    .pending_reservation
                    .iter()
                    .find(|(_, id)| listener_id.eq(id))
                {
                    Some((peer_id, _)) => *peer_id,
                    None => {
                        return;
                    }
                };

                self.pending_reservation.remove(&peer_id);

                match self.reservations.entry(listener_id) {
                    Entry::Occupied(mut entry) => {
                        let reservation = entry.get_mut();
                        debug_assert_eq!(peer_id, reservation.peer_id);
                        if !reservation.addr.contains(addr) {
                            reservation.addr.push(addr.clone());
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(Reservsation {
                            peer_id,
                            addr: vec![addr.clone()],
                        });
                    }
                }
            }
            swarm::FromSwarm::ExpiredListenAddr(ExpiredListenAddr { listener_id, .. }) => {
                if let Entry::Occupied(entry) = self.reservations.entry(listener_id) {
                    entry.remove();
                }
            }
            swarm::FromSwarm::ListenerError(ListenerError {
                listener_id,
                err: _,
            }) => {
                let peer_id = match self
                    .pending_reservation
                    .iter()
                    .find(|(_, id)| listener_id.eq(id))
                {
                    Some((peer_id, _)) => *peer_id,
                    None => {
                        return;
                    }
                };

                self.pending_reservation.remove(&peer_id);

                // Incase `FromSwarm::ListenerError` is emitted for an existing listener
                if let Entry::Occupied(entry) = self.reservations.entry(listener_id) {
                    entry.remove();
                }
            }
            swarm::FromSwarm::ListenerClosed(ListenerClosed {
                listener_id,
                reason: _,
            }) => {
                if let Entry::Occupied(entry) = self.reservations.entry(listener_id) {
                    entry.remove();
                }
            }
            _ => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<swarm::ToSwarm<Event, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        if matches!(self.nat_status, Nat::Public) && !self.reservations.is_empty() {
            self.remove_all_reservation();
        }

        if matches!(self.nat_status, Nat::Private) {
            while let Poll::Ready(Some(_)) = self.interval.poll_next_unpin(cx) {
                if self.candidates.is_empty() {
                    self.events
                        .push_back(ToSwarm::GenerateEvent(Event::FindCandidates));
                }
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
        }

        Poll::Pending
    }
}

#[allow(dead_code)]
pub(crate) fn peer_id_from_multiaddr(addr: Multiaddr) -> Option<PeerId> {
    let (peer, _) = extract_peer_id_from_multiaddr(addr);
    peer
}

#[allow(dead_code)]
pub(crate) fn extract_peer_id_from_multiaddr(mut addr: Multiaddr) -> (Option<PeerId>, Multiaddr) {
    match addr.pop() {
        Some(Protocol::P2p(peer_id)) => (Some(peer_id), addr),
        _ => (None, addr),
    }
}
