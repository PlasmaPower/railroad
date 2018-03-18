#![feature(i128_type)]

use std::net::SocketAddr;
use std::process;
use std::collections::HashMap;

extern crate blake2;
extern crate digest;

extern crate byteorder;

extern crate clap;
use clap::Arg;

extern crate env_logger;
#[macro_use]
extern crate log;

extern crate futures;
use futures::future;
extern crate tokio;
use tokio::executor::current_thread;
extern crate net2;
extern crate tokio_io;
extern crate tokio_timer;

extern crate rand;

extern crate curve25519_dalek;
extern crate ed25519_dalek;

extern crate bytes;

#[macro_use]
extern crate nanocurrency_types;
use nanocurrency_types::Network;

extern crate nanocurrency_protocol;

extern crate nanocurrency_peering;

#[macro_use]
mod node;

fn main() {
    env_logger::init();
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("Lee Bousfield <ljbousfield@gmail.com>")
        .arg(
            Arg::with_name("disable_official_peers")
                .long("disable-official-peers")
                .help("Disable connecting to the official nodes by default"),
        )
        .arg(
            Arg::with_name("peer")
                .short("p")
                .long("peer")
                .value_name("PEER")
                .multiple(true)
                .help("Connect to a specific peer (must include port)"),
        )
        .arg(
            Arg::with_name("peering_listen_address")
                .short("l")
                .long("peering-listen-address")
                .value_name("ADDR")
                .help("Listen on a specific address (must include port)"),
        )
        .arg(
            Arg::with_name("network")
                .long("network")
                .value_name("NET")
                .default_value("live")
                .possible_values(&["live", "beta", "test"])
                .help("The rai network to connect to"),
        )
        .get_matches();
    let mut custom_peers: Vec<SocketAddr> = Vec::new();
    let network = match matches.value_of("network").unwrap() {
        "live" => Network::Live,
        "beta" => Network::Beta,
        "test" => Network::Test,
        _ => unreachable!(),
    };
    let use_official_peers = !matches.is_present("disable_official_peers");
    if let Some(peers) = matches.values_of("peer") {
        for node in peers {
            match node.parse() {
                Ok(node) => custom_peers.push(node),
                Err(err) => {
                    eprintln!("Failed to parse custom peer {:?}: {}", node, err);
                    process::exit(1);
                }
            }
        }
    }
    let mut listen_addr = "[::]:7075".parse().unwrap();
    if let Some(addr) = matches.value_of("listen_addr") {
        match addr.parse() {
            Ok(addr) => listen_addr = addr,
            Err(err) => {
                eprintln!("Failed to parse listen address: {}", err);
                process::exit(1);
            }
        }
    }
    // TODO improve
    let mut vote_weights = HashMap::new();
    vote_weights.insert(
        "xrb_3arg3asgtigae3xckabaaewkx3bzsh7nwz7jkmjos79ihyaxwphhm6qgjps4"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_1stofnrxuz3cai7ze75o174bpm7scwj9jn3nxsn8ntzg784jf1gzn1jjdkou"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_1q3hqecaw15cjt7thbtxu3pbzr1eihtzzpzxguoc37bj1wc5ffoh7w74gi6p"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_3dmtrrws3pocycmbqwawk6xs7446qxa36fcncush4s1pejk16ksbmakis78m"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_3hd4ezdgsp15iemx7h81in7xz5tpxi43b6b41zn3qmwiuypankocw3awes5k"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_1awsn43we17c1oshdru4azeqjz9wii41dy8npubm4rg11so7dx3jtqgoeahy"
            .parse()
            .unwrap(),
        1,
    );
    vote_weights.insert(
        "xrb_1anrzcuwe64rwxzcco8dkhpyxpi8kd7zsjc1oeimpc3ppca4mrjtwnqposrs"
            .parse()
            .unwrap(),
        1,
    );
    let node_config = node::NodeConfig {
        network,
        use_official_peers,
        custom_peers,
        listen_addr,
        vote_weights,
    };
    current_thread::block_on_all(future::lazy(|| node::run(node_config)))
        .expect("Failed to run node");
}
