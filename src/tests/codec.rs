use std::net::SocketAddr;
use std::net::SocketAddrV6;
use std::net::Ipv4Addr;

use tokio_io::codec::{Decoder, Encoder};

use common::*;
use rai_codec::{Message, Network, RaiBlocksCodec};

/// A list of blocks for testing
fn get_test_blocks() -> Vec<Block> {
    let header = BlockHeader {
        signature: Signature::from_bytes(&[1u8; 64] as _).unwrap(),
        work: 4,
    };
    vec![
        Block {
            header: header.clone(),
            inner: BlockInner::Send {
                previous: BlockHash([2; 32]),
                destination: Account([3; 32]),
                balance: 1234567890_1234567890_u128,
            },
        },
        Block {
            header: header.clone(),
            inner: BlockInner::Receive {
                previous: BlockHash([2; 32]),
                source: BlockHash([3; 32]),
            },
        },
        Block {
            header: header.clone(),
            inner: BlockInner::Open {
                source: BlockHash([2; 32]),
                account: Account([3; 32]),
                representative: Account([4; 32]),
            },
        },
        Block {
            header,
            inner: BlockInner::Change {
                previous: BlockHash([2; 32]),
                representative: Account([3; 32]),
            },
        },
    ]
}

fn encode_decode(msg: Message) {
    let mut codec = RaiBlocksCodec;
    let mut bytes = Vec::new();
    let addr = SocketAddr::V6(SocketAddrV6::new(
        Ipv4Addr::new(11, 22, 33, 44).to_ipv6_mapped(),
        2468,
        0,
        0,
    ));
    let network = Network::Beta;
    assert_eq!(
        codec.encode((addr.clone(), network, msg.clone()), &mut bytes),
        addr
    );
    let decode = codec
        .decode(&addr, &bytes)
        .expect("Failed to decode generated message");
    assert_eq!(decode.0, addr);
    assert_eq!(decode.1.network, network);
    assert_eq!(decode.2, msg);
}

#[test]
fn keepalive() {
    let mut addrs = [default_addr!(); 8];
    addrs[0] = SocketAddrV6::new(Ipv4Addr::new(22, 33, 44, 55).to_ipv6_mapped(), 1357, 0, 0);
    addrs[7] = SocketAddrV6::new(Ipv4Addr::new(44, 55, 66, 77).to_ipv6_mapped(), 3579, 0, 0);
    encode_decode(Message::Keepalive(addrs));
}

#[test]
fn blocks() {
    for block in get_test_blocks() {
        encode_decode(Message::Block(block.clone()));
    }
}

#[test]
fn confirm_req() {
    for block in get_test_blocks() {
        encode_decode(Message::ConfirmReq(block.clone()));
    }
}

#[test]
fn confirm_ack() {
    for block in get_test_blocks() {
        encode_decode(Message::ConfirmAck {
            account: Account([5; 32]),
            signature: Signature::from_bytes(&[6u8; 64] as _).unwrap(),
            sequence: 123456,
            block: block.clone(),
        });
    }
}
