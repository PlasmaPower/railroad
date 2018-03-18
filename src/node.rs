use std::net::SocketAddr;
use std::collections::HashMap;

use futures::Future;

use nanocurrency_types::*;
use nanocurrency_protocol::*;
use nanocurrency_peering::{PeeringManagerBuilder, PeeringManagerState};

pub struct NodeConfig {
    pub custom_peers: Vec<SocketAddr>,
    pub use_official_peers: bool,
    pub vote_weights: HashMap<Account, u128>,
    pub listen_addr: SocketAddr,
    pub network: Network,
}

pub fn run(conf: NodeConfig) -> Box<Future<Item = (), Error = ()>> {
    let network = conf.network;
    let message_handler =
        move |peering: &PeeringManagerState, _header, message, _src| {
            let mut output = Vec::new();
            match message {
                Message::Keepalive(_) => {}
                Message::Publish(block) | Message::ConfirmReq(block) => {
                    if block.work_valid(network) {
                        debug!("Got block: {:?}", block.get_hash());
                        let mut peers =
                            vec![zero_v6_addr!(); (peering.num_peers() as f64).sqrt() as usize];
                        peering.get_rand_peers(&mut peers);
                        output.extend(peers.into_iter().map(move |peer| {
                            (Message::Publish(block.clone()), SocketAddr::V6(peer))
                        }));
                    }
                }
                Message::ConfirmAck { .. } => {
                    // TODO processing
                    // TODO rebroadcasting
                }
            }
            output.into_iter()
        };
    PeeringManagerBuilder::new(message_handler)
        .use_official_peers(conf.use_official_peers)
        .custom_peers(conf.custom_peers)
        .listen_addr(conf.listen_addr)
        .network(conf.network)
        .run()
        .expect("Failed to start node")
}
