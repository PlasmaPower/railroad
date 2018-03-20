use std::net::SocketAddrV6;
use std::net::Ipv4Addr;

use tokio_io::codec::{Decoder, Encoder};

use bytes::BytesMut;

use nanocurrency_types::*;

use Message;
use NanoCurrencyCodec;

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
            header: header.clone(),
            inner: BlockInner::Change {
                previous: BlockHash([2; 32]),
                representative: Account([3; 32]),
            },
        },
        Block {
            header: header.clone(),
            inner: BlockInner::State {
                previous: BlockHash([2; 32]),
                link: [3; 32],
                account: Account([4; 32]),
                representative: Account([5; 32]),
                balance: 1234567890_1234567890_u128,
            },
        },
    ]
}

fn encode_decode(msg: Message) -> Message {
    let mut codec = NanoCurrencyCodec;
    let mut bytes = BytesMut::new();
    let network = Network::Beta;
    assert!(codec.encode((network, msg.clone()), &mut bytes).is_ok());
    let decode = codec
        .decode(&mut bytes)
        .expect("Failed to decode generated message")
        .expect("Codec returned no message");
    assert_eq!(decode.0.network, network);
    assert_eq!(decode.1, msg);
    decode.1
}

#[test]
fn keepalive() {
    let mut addrs = [zero_v6_addr!(); 8];
    addrs[0] = SocketAddrV6::new(Ipv4Addr::new(22, 33, 44, 55).to_ipv6_mapped(), 1357, 0, 0);
    addrs[7] = SocketAddrV6::new(Ipv4Addr::new(44, 55, 66, 77).to_ipv6_mapped(), 3579, 0, 0);
    encode_decode(Message::Keepalive(addrs));
}

#[test]
fn blocks() {
    for block in get_test_blocks() {
        let msg = encode_decode(Message::Publish(block.clone()));
        if let Message::Publish(msg_block) = msg {
            assert_eq!(block.header, msg_block.header);
        } else {
            unreachable!();
        }
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
