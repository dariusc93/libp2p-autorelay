use std::{
    collections::{HashMap, HashSet},
    io,
    str::FromStr,
    time::Duration,
};

use libipld::{
    multihash::{Code, MultihashDigest},
    Cid, IpldCodec,
};

use clap::Parser;
use futures::{channel::mpsc::UnboundedSender, future::Either, StreamExt};
use libp2p::{
    autonat::Behaviour as Autonat,
    core::{
        muxing::StreamMuxerBox,
        transport::{timeout::TransportTimeout, Boxed, OrTransport},
        upgrade::Version,
    },
    dns::{DnsConfig, ResolverConfig},
    identify::{self, Behaviour as Identify, Info},
    identity::{self, Keypair},
    kad::{
        record::Key, store::MemoryStore, GetProvidersOk, Kademlia, KademliaEvent, QueryId,
        QueryResult,
    },
    multiaddr::Protocol,
    noise,
    ping::{self, Behaviour as Ping},
    relay::client::{Behaviour as RelayClient, Transport as ClientTransport},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp::{async_io::Transport as AsyncTcpTransport, Config as GenTcpConfig},
    Multiaddr, PeerId, Transport,
};

use libp2p_quic::{async_std::Transport as AsyncQuicTransport, Config as QuicConfig};

use libp2p_autorelay::Behaviour as AutoRelay;

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    relay_client: RelayClient,
    autorelay: AutoRelay,
    autonat: Autonat,
    identify: Identify,
    ping: Ping,
    kad: Toggle<Kademlia<MemoryStore>>,
}

#[derive(Debug, Parser)]
#[clap(name = "libp2p client")]
struct Opts {
    /// Fixed value to generate deterministic peer id.
    #[clap(long)]
    secret_key_seed: Option<u8>,

    #[clap(long)]
    candidates: Vec<Multiaddr>,

    /// Disables kad protocol
    #[clap(long)]
    disable_kad: bool,

    /// Bootstrap DHT
    #[clap(long)]
    bootstrap: bool,

    /// Random walk
    #[clap(long)]
    random_walk: bool,

    /// Relay Providers
    #[clap(long)]
    relay_providers: bool,
}

#[async_std::main]
#[allow(deprecated)]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let opts = Opts::parse();

    let local_keypair = match opts.secret_key_seed {
        Some(seed) => generate_ed25519(seed),
        None => Keypair::generate_ed25519(),
    };

    let local_peer_id = PeerId::from(local_keypair.public());

    println!("Local Node: {local_peer_id}");

    let (relay_transport, relay_client) = libp2p::relay::client::new(local_peer_id);

    let transport = build_transport(local_keypair.clone(), relay_transport)?;

    let behaviour = Behaviour {
        autonat: Autonat::new(local_peer_id, Default::default()),
        ping: Ping::new(Default::default()),
        identify: Identify::new({
            let mut config =
                identify::Config::new("/autorelay/0.1.0".to_string(), local_keypair.public());
            config.push_listen_addr_updates = true;
            config
        }),
        // upnp: Toggle::from((opts.upnp).then_some(libp2p_nat::Behaviour::new().await?)),
        relay_client,
        autorelay: AutoRelay::default(),
        kad: Toggle::from((!opts.disable_kad).then_some({
            let store = MemoryStore::new(local_peer_id);
            Kademlia::new(local_peer_id, store)
        })),
    };

    let mut swarm = SwarmBuilder::with_async_std_executor(transport, behaviour, local_peer_id)
        .dial_concurrency_factor(10_u8.try_into().expect("Always greater than 0"))
        .build();

    for addr in [
        "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
        "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
    ] {
        swarm.listen_on(addr)?;
    }

    for addr in opts.candidates {
        if addr
            .iter()
            .any(|proto| matches!(proto, Protocol::P2pCircuit))
        {
            continue;
        }

        if !addr
            .iter()
            .last()
            .map(|proto| matches!(proto, Protocol::P2p(_)))
            .unwrap_or_default()
        {
            continue;
        }

        let (peer_id, addr) = extract_peer_id_from_multiaddr(addr);
        let peer_id = peer_id.expect("Require p2p protocol in multiaddr");

        swarm
            .behaviour_mut()
            .autorelay
            .add_static_relay(peer_id, addr)?;
    }

    if !opts.disable_kad {
        // Use libp2p bootstrap for now
        // TODO: Make apart of cli options for bootstrap
        let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
        for peer_id in [
            "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        ]
        .iter()
        .filter_map(|p| p.parse().ok())
        {
            if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
                kad.add_address(&peer_id, bootaddr.clone());
            }
        }

        if opts.bootstrap {
            // TODO: Give option to use providers instead of bootstrapping (and randomly walking DHT)
            swarm
                .behaviour_mut()
                .kad
                .as_mut()
                .map(|kad| kad.bootstrap());
        }

        if opts.random_walk {
            swarm
                .behaviour_mut()
                .kad
                .as_mut()
                .map(|kad| kad.get_closest_peers(PeerId::random()));
        }

        if opts.relay_providers {
            swarm.behaviour_mut().autorelay.find_candidates(false);
        }
    }

    let mut relay_timer = wasm_timer::Interval::new(Duration::from_secs(5)).fuse();

    let mut addr_filter = HashSet::new();
    let mut provider_query: HashMap<QueryId, UnboundedSender<(PeerId, Vec<Multiaddr>)>> =
        HashMap::new();

    loop {
        futures::select! {
            _ = relay_timer.next() => {
                let autorelay = &mut swarm.behaviour_mut().autorelay;
                if autorelay.in_candidate_threshold() && !autorelay.in_reservation_threshold() {
                    autorelay.select_candidate_low_rtt();
                } else {
                    for reservation in autorelay.list_reservation() {
                        for addr in &reservation.addr {
                            println!("{}", addr.clone().with(Protocol::P2p(reservation.peer_id)));
                        }
                    }
                }
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        //Note: Multiple addresses are shown when listening due to the dial concurrency factor
                        if addr_filter.insert(address.clone()) {
                            println!("Listening on {address}");
                        }
                    }
                    SwarmEvent::Behaviour(event) => match event {
                        BehaviourEvent::RelayClient(event) => {
                            log::debug!("{event:?}");
                            swarm.behaviour_mut().autorelay.inject_relay_client_event(event);
                        }
                        BehaviourEvent::Autorelay(libp2p_autorelay::Event::FindProviders(tx)) => {
                            if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
                                let cid = ns_to_cid("/libp2p/relay");
                                let key = Key::from(cid.hash().to_bytes());
                                let id = kad.get_providers(key);
                                provider_query.insert(id, tx);
                            }
                        }
                        BehaviourEvent::Identify(identify::Event::Received {
                            peer_id,
                            info:
                                Info {
                                    protocols,
                                    listen_addrs,
                                    ..
                                },
                        }) => {
                            if !opts.relay_providers && protocols
                                    .iter()
                                    .any(|p| libp2p::relay::HOP_PROTOCOL_NAME.eq(p)) {
                                swarm
                                    .behaviour_mut()
                                    .autorelay
                                    .inject_candidate(peer_id, listen_addrs)
                            }
                        }
                        BehaviourEvent::Ping(ping::Event {
                            peer,
                            result: Result::Ok(rtt),
                            ..
                        }) => {
                            swarm.behaviour_mut().autorelay.set_candidate_rtt(peer, rtt);
                        },
                        BehaviourEvent::Kad(KademliaEvent::OutboundQueryProgressed {
                            id,
                            result,
                            step,
                            ..
                        }) => match result {
                            QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
                                key: _,
                                providers: _,
                            })) => {
                                // if let Entry::Occupied(entry) =
                                //     provider_query.entry(id)
                                // {
                                //     // if !providers.is_empty() {
                                //     //     let tx = entry.get().clone();
                                //     //     for provider in providers {
                                //     //         let _ = tx.unbounded_send((provider, swarm.behaviour_mut()));
                                //     //     }
                                //     // }
                                // }
                            }
                            QueryResult::GetProviders(Ok(
                                GetProvidersOk::FinishedWithNoAdditionalRecord { .. },
                            )) => {
                                if step.last {
                                    if let Some(tx) = provider_query.remove(&id) {
                                        tx.close_channel();
                                    }
                                }
                            }
                            _ => {}
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }
}

pub fn build_transport(
    keypair: Keypair,
    relay: ClientTransport,
) -> io::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let noise_config = noise::Config::new(&keypair).unwrap();

    let multiplex_upgrade = libp2p::yamux::Config::default();

    let quic_transport = AsyncQuicTransport::new(QuicConfig::new(&keypair));

    let transport = AsyncTcpTransport::new(GenTcpConfig::default().nodelay(true).port_reuse(true));

    let transport_timeout = TransportTimeout::new(transport, Duration::from_secs(30));

    let transport = futures::executor::block_on(DnsConfig::custom(
        transport_timeout,
        ResolverConfig::cloudflare(),
        Default::default(),
    ))?;

    let transport = OrTransport::new(relay, transport)
        .upgrade(Version::V1)
        .authenticate(noise_config)
        .multiplex(multiplex_upgrade)
        .timeout(Duration::from_secs(30))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        .boxed();

    let transport = OrTransport::new(quic_transport, transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    Ok(transport)
}
fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;
    identity::Keypair::ed25519_from_bytes(bytes).expect("Keypair is valid")
}

#[allow(dead_code)]
fn peer_id_from_multiaddr(addr: Multiaddr) -> Option<PeerId> {
    let (peer, _) = extract_peer_id_from_multiaddr(addr);
    peer
}

#[allow(dead_code)]
fn extract_peer_id_from_multiaddr(mut addr: Multiaddr) -> (Option<PeerId>, Multiaddr) {
    match addr.pop() {
        Some(Protocol::P2p(id)) => (Some(id), addr),
        _ => (None, addr),
    }
}

pub fn ns_to_cid(string: &str) -> Cid {
    let hash = Code::Sha2_256.digest(string.as_bytes());
    Cid::new_v1(IpldCodec::Raw.into(), hash)
}

pub fn cid_to_ns(cid: Cid) -> String {
    format!("/provider/{cid}")
}
