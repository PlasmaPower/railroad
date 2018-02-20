use std::cell::RefCell;
use std::collections::hash_map;
use std::collections::HashMap;
use std::time::Instant;
use std::rc::Rc;
use std::io;
use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::time::Duration;

use tokio_core::net::UdpSocket;
use tokio_core::reactor::Handle;

use tokio_timer::Timer;

use futures::{stream, Future, Sink, Stream};
use futures::sync::mpsc;

use rand::{thread_rng, Rng};

use utils::ignore_errors;
use udp_framed;

use common::Network;
use rai_codec::*;

const IPV4_RESERVED_ADDRESSES: &[(u32, u32)] = &[
    (0x00000000, 0x00ffffff), // rfc 1700
    (0x7f000000, 0x7fffffff), // loopback
    (0xc0000200, 0xc00002ff), // rfc 5737
    (0xc6336400, 0xc63364ff), // rfc 5737
    (0xcb007100, 0xcb0071ff), // rfc 5737
    (0xe0000000, 0xefffffff), // multicast
    (0xf0000000, 0xffffffff), // rfc 6890
];

// In seconds.
const KEEPALIVE_INTERVAL: u64 = 60;
const KEEPALIVE_CUTOFF: u64 = KEEPALIVE_INTERVAL * 5;

fn to_ipv6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(addr) => SocketAddrV6::new(addr.ip().to_ipv6_mapped(), addr.port(), 0, 0),
        SocketAddr::V6(addr) => addr,
    }
}

struct PeerInfo {
    last_heard_from: Instant,
}

impl Default for PeerInfo {
    fn default() -> PeerInfo {
        PeerInfo {
            last_heard_from: Instant::now(),
        }
    }
}

struct NodeInfo {
    peers: HashMap<SocketAddrV6, PeerInfo>,
    rand_peers: RefCell<Vec<SocketAddrV6>>,
    new_peer_backoff: HashMap<SocketAddrV6, Instant>,
}

impl NodeInfo {
    fn get_rand_peers(&self, peers_out: &mut [SocketAddrV6]) {
        let mut thread_rng = thread_rng();
        let mut rand_peers = RefCell::borrow_mut(&self.rand_peers);
        for peer_out in peers_out.iter_mut() {
            if self.peers.is_empty() {
                break;
            }
            rand_peers.extend(self.peers.keys());
            thread_rng.shuffle(&mut rand_peers);
            *peer_out = rand_peers.pop().unwrap();
        }
    }

    fn contacted(&mut self, addr: SocketAddr) {
        let addr = to_ipv6(addr);
        match self.peers.entry(addr) {
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().last_heard_from = Instant::now();
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(PeerInfo::default());
            }
        }
    }
}

pub struct NodeConfig {
    pub peers: Vec<SocketAddr>,
    pub listen_addr: SocketAddr,
    pub network: Network,
}

pub fn run(conf: NodeConfig, handle: Handle) -> impl Future<Item = (), Error = io::Error> {
    let node_base = Rc::new(RefCell::new(NodeInfo {
        peers: conf.peers
            .into_iter()
            .map(to_ipv6)
            .map(|a| (a, PeerInfo::default()))
            .collect(),
        rand_peers: Default::default(),
        new_peer_backoff: HashMap::new(),
    }));
    let (sink, stream) = udp_framed::new(
        UdpSocket::bind(&conf.listen_addr, &handle).expect("Failed to listen for peers"),
        RaiBlocksCodec,
    ).split();
    let network = conf.network;
    let node_rc = node_base.clone();
    let process_messages = stream
        .map(move |(src, header, msg)| -> Box<Stream<Item=(SocketAddr, Network, Message), Error=io::Error>> {
            if header.network != network {
                warn!("Ignoring message from {:?} network", header.network);
                return Box::new(stream::empty());
            }
            let mut node = node_rc.borrow_mut();
            node.contacted(src);
            trace!("Got message from {:?}: {:?}", src, msg);
            match msg {
                Message::Keepalive(new_peers) => {
                    let node_rc = node_rc.clone();
                    let to_send = new_peers.to_vec()
                        .into_iter()
                        .filter_map(move |new_peer| {
                            let mut node = node_rc.borrow_mut();
                            match node.new_peer_backoff.entry(new_peer) {
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
                            if node.peers.contains_key(&new_peer) {
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
                            if let Some(ip) = ip.to_ipv4() {
                                let ip: u32 = ip.into();
                                for &(start, end) in IPV4_RESERVED_ADDRESSES.iter() {
                                    if ip >= start && ip <= end {
                                        return None;
                                    }
                                }
                            }
                            // TODO some IPv6 reserved addresses missing
                            let mut rand_peers = [default_addr!(); 8];
                            node.get_rand_peers(&mut rand_peers);
                            Some((SocketAddr::V6(new_peer), network, Message::Keepalive(rand_peers)))
                        });
                    Box::new(stream::iter_ok(to_send)) as _
                }
                Message::Block(block) | Message::ConfirmReq(block) => {
                    debug!("Got block: {:?} (work_valid {})", block.get_hash(), block.work_valid(network));
                    let mut peers = vec![default_addr!(); (node.peers.len() as f64).sqrt() as usize];
                    node.get_rand_peers(&mut peers);
                    let to_send = peers.into_iter().map(move |peer| {
                        (SocketAddr::V6(peer), network, Message::Block(block.clone()))
                    });
                    Box::new(stream::iter_ok(to_send)) as _
                }
                Message::ConfirmAck { .. } => {
                    // TODO processing
                    // TODO rebroadcasting
                    Box::new(stream::empty()) as _
                }
            }
        })
        .flatten();
    let timer = Timer::default();
    let node_rc = node_base.clone();
    let keepalive = stream::once(Ok(()))
        .chain(timer.interval(Duration::from_secs(KEEPALIVE_INTERVAL)))
        .map(move |_| {
            let mut node = node_rc.borrow_mut();
            let last_heard_cutoff = Instant::now() - Duration::from_secs(KEEPALIVE_CUTOFF);
            node.new_peer_backoff
                .retain(|_, ts| *ts > last_heard_cutoff);
            node.peers
                .retain(|_, info| info.last_heard_from > last_heard_cutoff);
            debug!("Peers: {:?}", node.peers.keys());
            let mut keepalives = Vec::with_capacity(node.peers.len());
            for (addr, _) in node.peers.iter() {
                let mut rand_peers = [default_addr!(); 8];
                node.get_rand_peers(&mut rand_peers);
                keepalives.push((SocketAddr::V6(*addr), network, Message::Keepalive(rand_peers)));
            }
            stream::iter_ok::<_, io::Error>(keepalives.into_iter())
        })
        .flatten();
    let sock_channel = mpsc::channel(2048);
    let sock_send = sock_channel.0.clone();
    handle.spawn(
        sock_send
            .send_all(ignore_errors(process_messages))
            .map(|_| ())
            .map_err(|_| ()),
    );
    let sock_send = sock_channel.0.clone();
    handle.spawn(
        sock_send
            .send_all(ignore_errors(keepalive))
            .map(|_| ())
            .map_err(|_| ()),
    );
    sink.send_all(
        sock_channel
            .1
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "failed to receive")),
    ).map(|_| ())
}
