use std::iter::IntoIterator;
use std::io;
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};
use std::collections::{hash_map, HashMap};
use std::marker::PhantomData;
use std::fmt::Debug;

#[macro_use]
extern crate log;

#[macro_use]
extern crate futures;
use futures::{stream, Future, Sink, Stream};

extern crate net2;
use net2::UdpBuilder;

extern crate bytes;

extern crate tokio;
use tokio::net::UdpSocket;
use tokio::reactor::Handle;

extern crate tokio_io;

extern crate tokio_timer;
use tokio_timer::Timer;

extern crate rand;
use rand::{thread_rng, Rng};

extern crate nanocurrency_protocol;
use nanocurrency_protocol::*;

#[macro_use]
extern crate nanocurrency_types;
use nanocurrency_types::Network;

mod udp_framed;

// In seconds.
const KEEPALIVE_INTERVAL: u64 = 60;
const KEEPALIVE_CUTOFF: u64 = KEEPALIVE_INTERVAL * 5;

pub fn addr_to_ipv6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(addr) => SocketAddrV6::new(addr.ip().to_ipv6_mapped(), addr.port(), 0, 0),
        SocketAddr::V6(addr) => addr,
    }
}

struct IgnoreErrors<S: Stream, E> where S::Error: Debug {
    inner: S,
    err_phantom: PhantomData<E>,
}

impl<S: Stream, E: Debug> Stream for IgnoreErrors<S, E> where S::Error: Debug {
    type Item = S::Item;
    type Error = E;

    fn poll(&mut self) -> Result<futures::Async<Option<S::Item>>, E> {
        loop {
            match self.inner.poll() {
                Ok(x) => return Ok(x),
                Err(err) => debug!("ignoring error: {:?}", err),
            }
        }
    }
}

fn ignore_errors<S: Stream, E>(stream: S) -> IgnoreErrors<S, E> where S::Error: Debug {
    IgnoreErrors {
        inner: stream,
        err_phantom: PhantomData,
    }
}

pub struct PeerInfo {
    pub last_heard_from: Instant,
    pub network_version: u8,
}

#[derive(Default)]
pub struct PeeringManagerState {
    peers: HashMap<SocketAddrV6, PeerInfo>,
    rand_peers: RefCell<Vec<SocketAddrV6>>,
    new_peer_backoff: HashMap<SocketAddrV6, Instant>,
}

impl PeeringManagerState {
    pub fn get_rand_peers(&self, peers_out: &mut [SocketAddrV6]) {
        let mut thread_rng = thread_rng();
        let mut rand_peers = RefCell::borrow_mut(&self.rand_peers);
        for peer_out in peers_out.iter_mut().take(self.peers.len()) {
            if self.peers.is_empty() {
                break;
            }
            rand_peers.extend(self.peers.keys());
            thread_rng.shuffle(&mut rand_peers);
            *peer_out = rand_peers.pop().unwrap();
        }
    }

    pub fn num_peers(&self) -> usize {
        self.peers.len()
    }

    fn contacted(&mut self, addr: SocketAddr, header: &MessageHeader) {
        let addr = addr_to_ipv6(addr);
        match self.peers.entry(addr) {
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().last_heard_from = Instant::now();
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(PeerInfo {
                    last_heard_from: Instant::now(),
                    network_version: header.version,
                });
            }
        }
    }
}

#[derive(Clone)]
pub struct PeeringManagerBuilder<F, I, II>
where
    I: Iterator<Item = (Message, SocketAddr)>,
    II: IntoIterator<Item = (Message, SocketAddr), IntoIter = I>,
    F: Fn(&PeeringManagerState, MessageHeader, Message, SocketAddr) -> II + 'static,
{
    use_official_peers: bool,
    custom_peers: Vec<SocketAddr>,
    listen_addr: SocketAddr,
    network: Network,
    message_handler: F,
}

impl<F, I, II> PeeringManagerBuilder<F, I, II>
where
    I: Iterator<Item = (Message, SocketAddr)>,
    II: IntoIterator<Item = (Message, SocketAddr), IntoIter = I>,
    F: Fn(&PeeringManagerState, MessageHeader, Message, SocketAddr) -> II + 'static,
{
    pub fn new(message_handler: F) -> PeeringManagerBuilder<F, I, II> {
        PeeringManagerBuilder {
            use_official_peers: true,
            custom_peers: Vec::new(),
            listen_addr: "[::]:7075".parse().unwrap(),
            network: Network::Live,
            message_handler,
        }
    }

    pub fn use_official_peers(mut self, value: bool) -> Self {
        self.use_official_peers = value;
        self
    }

    pub fn custom_peers(mut self, value: Vec<SocketAddr>) -> Self {
        self.custom_peers = value;
        self
    }

    pub fn listen_addr(mut self, value: SocketAddr) -> Self {
        self.listen_addr = value;
        self
    }

    pub fn network(mut self, value: Network) -> Self {
        self.network = value;
        self
    }

    pub fn run(self) -> io::Result<Box<Future<Item = (), Error = ()>>> {
        let mut configured_peers: Vec<SocketAddrV6> = Vec::new();
        if self.use_official_peers {
            let official_domain = match self.network {
                Network::Live => Some("rai.raiblocks.net:7075"),
                Network::Beta => Some("rai-beta.raiblocks.net:7075"),
                Network::Test => None,
            };
            if let Some(official_domain) = official_domain {
                configured_peers.extend(official_domain.to_socket_addrs()?.map(addr_to_ipv6));
            }
        }
        configured_peers.extend(self.custom_peers.into_iter().map(addr_to_ipv6));
        let state_base = PeeringManagerState::default();
        let state_base = Rc::new(RefCell::new(state_base));
        let socket = UdpBuilder::new_v6()?
            .only_v6(false)?
            .bind(self.listen_addr)?;
        let socket = UdpSocket::from_std(socket, &Handle::current())?;
        let (sink, stream) = udp_framed::UdpFramed::new(socket, NanoCurrencyCodec).split();
        let network = self.network;
        let message_handler = self.message_handler;
        let state_rc = state_base.clone();
        let process_message = move |((header, msg), src)| {
            let _: &MessageHeader = &header;
            if header.network != network {
                warn!("ignoring message from {:?} network", header.network);
                return stream::iter_ok(Vec::new().into_iter());
            }
            let mut state = state_rc.borrow_mut();
            state.contacted(src, &header);
            trace!("got message from {:?}: {:?}", src, msg);
            let mut output_messages = Vec::new();
            match msg {
                Message::Keepalive(new_peers) => {
                    let state = &mut state;
                    output_messages.extend(new_peers.to_vec().into_iter().filter_map(
                        move |new_peer| {
                            match state.new_peer_backoff.entry(new_peer) {
                                hash_map::Entry::Occupied(mut entry) => {
                                    let entry = entry.get_mut();
                                    if *entry
                                        > Instant::now() - Duration::from_secs(KEEPALIVE_CUTOFF)
                                    {
                                        return None;
                                    }
                                    *entry = Instant::now();
                                }
                                hash_map::Entry::Vacant(entry) => {
                                    entry.insert(Instant::now());
                                }
                            }
                            if state.peers.contains_key(&new_peer) {
                                return None;
                            }
                            let ip = new_peer.ip().clone();
                            if ip.octets().iter().all(|&x| x == 0) {
                                return None;
                            }
                            if new_peer.port() == 0 {
                                return None;
                            }
                            if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
                                return None;
                            }
                            let mut rand_peers = [zero_v6_addr!(); 8];
                            state.get_rand_peers(&mut rand_peers);
                            Some((
                                (network, Message::Keepalive(rand_peers)),
                                SocketAddr::V6(new_peer),
                            ))
                        },
                    ));
                }
                _ => {}
            }
            output_messages.extend(
                (message_handler)(&state, header, msg, src)
                    .into_iter()
                    .map(|(m, a)| ((network, m), a)),
            );
            stream::iter_ok::<_, io::Error>(output_messages)
        };
        let process_messages = stream.map(process_message).flatten();
        let state_rc = state_base.clone();
        let timer = Timer::default();
        let keepalive = stream::once(Ok(()))
            .chain(timer.interval(Duration::from_secs(KEEPALIVE_INTERVAL)))
            .map(move |_| {
                let mut state = state_rc.borrow_mut();
                let last_heard_cutoff = Instant::now() - Duration::from_secs(KEEPALIVE_CUTOFF);
                state
                    .new_peer_backoff
                    .retain(|_, ts| *ts > last_heard_cutoff);
                state
                    .peers
                    .retain(|_, info| info.last_heard_from > last_heard_cutoff);
                debug!("peers: {:?}", state.peers.keys());
                let mut keepalives = Vec::with_capacity(state.peers.len());
                for addr in state
                    .peers
                    .iter()
                    .map(|(a, _)| a)
                    .chain(configured_peers.iter())
                {
                    let mut rand_peers = [zero_v6_addr!(); 8];
                    state.get_rand_peers(&mut rand_peers);
                    keepalives.push((
                        (network, Message::Keepalive(rand_peers)),
                        SocketAddr::V6(*addr),
                    ));
                }
                stream::iter_ok::<_, io::Error>(keepalives.into_iter())
            })
            .flatten();
        Ok(Box::new(
            sink.send_all(
                ignore_errors::<_, io::Error>(process_messages).select(ignore_errors(keepalive)),
            ).map(|_| ())
                .map_err(|_| ()),
        ))
    }
}
