use std::io;
use std::io::prelude::*;
use std::io::Cursor;
use std::net;
use std::net::SocketAddr;
use std::net::SocketAddrV6;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

use tokio_core;

use common::*;

const NET_VERSION: u8 = 0x07;
const NET_VERSION_MAX: u8 = 0x07;
const NET_VERSION_MIN: u8 = 0x01;

// Note: this does not include the message type.
// That's wrapped into the Message enum.
#[allow(dead_code)]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MessageHeader {
    pub network: Network,
    pub version_max: u8,
    pub version: u8,
    pub version_min: u8,
    pub extensions: u16,
}

#[derive(Debug, PartialEq, Clone)]
pub enum Message {
    Keepalive([SocketAddrV6; 8]),
    Block(Block),
    ConfirmReq(Block),
    ConfirmAck {
        account: Account,
        signature: Signature,
        sequence: u64,
        block: Block,
    },
}

pub struct RaiBlocksCodec;

// Message types:
// invalid      0
// not_a_type   1
// keepalive    2
// publish      3
// confirm_req  4
// confirm_ack  5
//
// Bootstrap message types:
// bulk_pull    6
// bulk_push    7
// frontier_req 8

impl RaiBlocksCodec {
    pub fn read_block<C: io::Read>(
        cursor: &mut C,
        block_ty: u8,
    ) -> io::Result<Block> {
        let inner = match block_ty {
            2 => {
                // send
                let mut previous = BlockHash::default();
                cursor.read_exact(&mut previous.0)?;
                let mut destination = Account::default();
                cursor.read_exact(&mut destination.0)?;
                let balance = cursor.read_u128::<BigEndian>()?;
                BlockInner::Send {
                    previous,
                    destination,
                    balance,
                }
            }
            3 => {
                // receieve
                let mut previous = BlockHash::default();
                cursor.read_exact(&mut previous.0)?;
                let mut source = BlockHash::default();
                cursor.read_exact(&mut source.0)?;
                BlockInner::Receive { previous, source }
            }
            4 => {
                // open
                let mut source = BlockHash::default();
                cursor.read_exact(&mut source.0)?;
                let mut representative = Account::default();
                cursor.read_exact(&mut representative.0)?;
                let mut account = Account::default();
                cursor.read_exact(&mut account.0)?;
                BlockInner::Open {
                    source,
                    representative,
                    account,
                }
            }
            5 => {
                // change
                let mut previous = BlockHash::default();
                cursor.read_exact(&mut previous.0)?;
                let mut representative = Account::default();
                cursor.read_exact(&mut representative.0)?;
                BlockInner::Change {
                    previous,
                    representative,
                }
            }
            6 => {
                // utx
                let mut account = Account::default();
                cursor.read_exact(&mut account.0)?;
                let mut previous = BlockHash::default();
                cursor.read_exact(&mut previous.0)?;
                let mut representative = Account::default();
                cursor.read_exact(&mut representative.0)?;
                let balance = cursor.read_u128::<BigEndian>()?;
                let mut link = [0u8; 32];
                cursor.read_exact(&mut link)?;
                BlockInner::Utx {
                    account,
                    previous,
                    representative,
                    balance,
                    link,
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unrecognized block type",
                ))
            }
        };
        let mut signature = [0u8; 64];
        cursor.read_exact(&mut signature)?;
        let signature = Signature::from_bytes(&signature).unwrap();
        let work = cursor.read_u64::<LittleEndian>()?;
        let header = BlockHeader { signature, work };
        Ok(Block { header, inner })
    }

    pub fn block_type_num(block: &Block) -> u8 {
        match block.inner {
            BlockInner::Send { .. } => 2,
            BlockInner::Receive { .. } => 3,
            BlockInner::Open { .. } => 4,
            BlockInner::Change { .. } => 5,
            BlockInner::Utx { .. } => 6,
        }
    }

    /// Does NOT include block type
    pub fn write_block(buf: &mut Vec<u8>, block: Block) {
        match block.inner {
            BlockInner::Send {
                previous,
                destination,
                balance,
            } => {
                buf.extend(previous.0.iter());
                buf.extend(destination.0.iter());
                buf.write_u128::<BigEndian>(balance).unwrap();
            }
            BlockInner::Receive { previous, source } => {
                buf.extend(previous.0.iter());
                buf.extend(source.0.iter());
            }
            BlockInner::Open {
                source,
                representative,
                account,
            } => {
                buf.extend(source.0.iter());
                buf.extend(representative.0.iter());
                buf.extend(account.0.iter());
            }
            BlockInner::Change {
                previous,
                representative,
            } => {
                buf.extend(previous.0.iter());
                buf.extend(representative.0.iter());
            }
            BlockInner::Utx {
                account,
                previous,
                representative,
                balance,
                link,
            } => {
                buf.extend(account.0.iter());
                buf.extend(previous.0.iter());
                buf.extend(representative.0.iter());
                buf.write_u128::<BigEndian>(balance).unwrap();
                buf.extend(link.iter());
            }
        };
        buf.extend(block.header.signature.to_bytes().iter());
        buf.write_u64::<LittleEndian>(block.header.work).unwrap();
    }

    pub fn network_magic_byte(network: Network) -> u8 {
        match network {
            Network::Test => b'A',
            Network::Beta => b'B',
            Network::Main => b'C',
        }
    }
}

impl tokio_core::net::UdpCodec for RaiBlocksCodec {
    type In = (SocketAddr, MessageHeader, Message);
    type Out = (SocketAddr, Network, Message);

    fn decode(&mut self, src: &SocketAddr, buf: &[u8]) -> io::Result<Self::In> {
        let mut cursor = Cursor::new(buf);
        if cursor.read_u8()? != b'R' {
            return Err(io::Error::new(io::ErrorKind::Other, "invalid magic number"));
        }
        let network = match cursor.read_u8()? {
            b'A' => Network::Test,
            b'B' => Network::Beta,
            b'C' => Network::Main,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "invalid network indicator",
                ))
            }
        };
        let version_max = cursor.read_u8()?;
        let version = cursor.read_u8()?;
        let version_min = cursor.read_u8()?;
        let msg_type = cursor.read_u8()?;
        let extensions = cursor.read_u16::<LittleEndian>()?;
        if version_min > NET_VERSION_MAX || version_max < NET_VERSION_MIN {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "unsupported peer version",
            ));
        }
        let header = MessageHeader {
            network,
            version_max,
            version,
            version_min,
            extensions,
        };
        let message = match msg_type {
            2 => {
                // keepalive
                let mut peers = [default_addr!(); 8];
                let _ = (|| -> io::Result<()> {
                    for peer in peers.iter_mut() {
                        let mut ip_bytes: [u8; 16] = [0; 16];
                        for byte in ip_bytes.iter_mut() {
                            *byte = cursor.read_u8()?;
                        }
                        let port = cursor.read_u16::<LittleEndian>()?;
                        *peer = SocketAddrV6::new(net::Ipv6Addr::from(ip_bytes), port, 0, 0);
                    }
                    Ok(())
                })();
                Message::Keepalive(peers)
            }
            3 => {
                // block
                let ty = (header.extensions & 0x0f00) >> 8;
                Message::Block(Self::read_block(&mut cursor, ty as u8)?)
            }
            4 => {
                // confirm_req
                let ty = (header.extensions & 0x0f00) >> 8;
                Message::ConfirmReq(Self::read_block(&mut cursor, ty as u8)?)
            }
            5 => {
                // confirm_ack
                let ty = (header.extensions & 0x0f00) >> 8;
                let mut account = Account::default();
                cursor.read_exact(&mut account.0)?;
                let mut signature = [0u8; 64];
                cursor.read_exact(&mut signature)?;
                let signature = Signature::from_bytes(&signature).unwrap();
                let sequence = cursor.read_u64::<LittleEndian>()?;
                let block = Self::read_block(&mut cursor, ty as u8)?;
                Message::ConfirmAck {
                    account,
                    signature,
                    sequence,
                    block,
                }
            }
            6 | 7 | 8 => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "bootstrap message sent over UDP",
                ))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "unrecognized message type",
                ))
            }
        };
        Ok((*src, header, message))
    }

    fn encode(&mut self, msg: Self::Out, buf: &mut Vec<u8>) -> SocketAddr {
        buf.push(b'R');
        buf.push(Self::network_magic_byte(msg.1));
        buf.push(NET_VERSION_MAX);
        buf.push(NET_VERSION);
        buf.push(NET_VERSION_MIN);
        match msg.2 {
            Message::Keepalive(peers) => {
                buf.push(2);
                buf.extend(&[0, 0]); // extensions
                for peer in peers.iter() {
                    buf.extend(peer.ip().octets().iter());
                    buf.write_u16::<LittleEndian>(peer.port()).unwrap();
                }
            }
            Message::Block(block) => {
                buf.push(3);
                let type_num = Self::block_type_num(&block) as u16;
                buf.write_u16::<LittleEndian>((type_num & 0x0f) << 8)
                    .unwrap();
                Self::write_block(buf, block);
            }
            Message::ConfirmReq(block) => {
                buf.push(4);
                let type_num = Self::block_type_num(&block) as u16;
                buf.write_u16::<LittleEndian>((type_num & 0x0f) << 8)
                    .unwrap();
                Self::write_block(buf, block);
            }
            Message::ConfirmAck {
                account,
                signature,
                sequence,
                block,
            } => {
                buf.push(5);
                let type_num = Self::block_type_num(&block) as u16;
                buf.write_u16::<LittleEndian>((type_num & 0x0f) << 8)
                    .unwrap();
                buf.extend(account.0.iter());
                buf.extend(signature.to_bytes().iter());
                buf.write_u64::<LittleEndian>(sequence).unwrap();
                Self::write_block(buf, block);
            }
        }
        msg.0
    }
}
