#![feature(conservative_impl_trait)]
#![feature(i128_type)]

use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::process;

extern crate blake2;
extern crate digest;

extern crate byteorder;

extern crate clap;
use clap::Arg;

extern crate env_logger;
#[macro_use]
extern crate log;

#[macro_use]
extern crate futures;
#[macro_use]
extern crate tokio_core;
use tokio_core::reactor::Core;
extern crate tokio_timer;

extern crate rand;

extern crate ed25519_dalek;
extern crate curve25519_dalek;

mod common;
use common::Network;
#[macro_use]
mod utils;
mod udp_framed;
mod rai_codec;
mod node;

#[cfg(test)]
mod tests;

fn main() {
    env_logger::init();
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("Lee Bousfield <ljbousfield@gmail.com>")
        .arg(
            Arg::with_name("disable_official_nodes")
                .long("disable-official-nodes")
                .help("Disable connecting to the official nodes"),
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
                .default_value("main")
                .possible_values(&["main", "beta", "test"])
                .help("The rai network to connect to")
        )
        .get_matches();
    let mut peers: Vec<SocketAddr> = Vec::new();
    let network = match matches.value_of("network").unwrap() {
        "main" => Network::Main,
        "beta" => Network::Beta,
        "test" => Network::Test,
        _ => unreachable!(),
    };
    let use_official_nodes = !matches.is_present("disable_official_nodes") && network != Network::Test;
    if use_official_nodes {
        for mut node in "rai.raiblocks.net:7075"
            .to_socket_addrs()
            .expect("Failed to lookup official node IPs")
        {
            peers.push(node);
        }
    }
    if let Some(custom_peers) = matches.values_of("peer") {
        for node in custom_peers {
            match node.parse() {
                Ok(node) => peers.push(node),
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
    let mut core = Core::new().expect("Failed to create tokio core");
    let node_config = node::NodeConfig { network, peers, listen_addr };
    let handle = core.handle();
    core.run(node::run(node_config, handle))
        .expect("Failed to run node");
}
