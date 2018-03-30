#![feature(i128_type)]

use std::fmt;
use std::str;
use std::iter;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::convert::AsRef;

extern crate blake2;
use blake2::Blake2b;
extern crate digest;
use digest::{Input, VariableOutput};

extern crate byteorder;
use byteorder::{BigEndian, ByteOrder, LittleEndian};

extern crate num_bigint;
use num_bigint::BigInt;
extern crate num_traits;
use num_traits::cast::ToPrimitive;

extern crate ed25519_dalek;
pub use ed25519_dalek::Signature;
use ed25519_dalek::PublicKey;

extern crate hex;

extern crate serde;
use serde::de::Error as SerdeError;

#[macro_use]
extern crate serde_derive;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Network {
    Test,
    Beta,
    Live,
}

#[macro_export]
macro_rules! zero_v6_addr {
    () => { ::std::net::SocketAddrV6::new(::std::net::Ipv6Addr::from([0u8; 16]), 0, 0, 0) };
}

fn write_hex(f: &mut fmt::Formatter, bytes: &[u8]) -> fmt::Result {
    for b in bytes.iter() {
        write!(f, "{:02X}", b)?;
    }
    Ok(())
}

struct InternalHexVisitor {
    byte_len: usize,
}

impl InternalHexVisitor {
    fn new(byte_len: usize) -> Self {
        InternalHexVisitor { byte_len }
    }
}

impl<'de> serde::de::Visitor<'de> for InternalHexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(
            formatter,
            "a hex string representing {} bytes",
            self.byte_len
        )
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        if (v.len() / 2) == self.byte_len {
            let bytes = hex::decode(&v)
                .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(&v), &self))?;
            // Should always be true, but just in case.
            if bytes.len() == self.byte_len {
                return Ok(bytes);
            }
        }
        Err(E::invalid_length(v.len(), &self))
    }
}

trait InternalFromHex: Sized {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>;
}

impl InternalFromHex for Signature {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(InternalHexVisitor::new(64))
            .and_then(|bytes| {
                Signature::from_bytes(&bytes).map_err(|_| {
                    D::Error::invalid_value(
                        serde::de::Unexpected::Bytes(&bytes),
                        &"a valid ed25519 signature",
                    )
                })
            })
    }
}

impl InternalFromHex for u64 {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(InternalHexVisitor::new(8))
            .map(|bytes| BigEndian::read_u64(&bytes))
    }
}

impl InternalFromHex for [u8; 32] {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(InternalHexVisitor::new(32))
            .map(|bytes| {
                let mut arr = [0u8; 32];
                arr.clone_from_slice(&bytes);
                arr
            })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct BlockHeader {
    #[serde(deserialize_with = "InternalFromHex::from_hex")] pub signature: Signature,
    #[serde(deserialize_with = "InternalFromHex::from_hex")] pub work: u64,
}

#[derive(Default, PartialEq, Eq, Clone)]
pub struct BlockHash(pub [u8; 32]);

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl Hash for BlockHash {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

pub const ACCOUNT_LOOKUP: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";

#[derive(Default, PartialEq, Eq, Clone)]
pub struct Account(pub [u8; 32]);

impl Account {
    pub fn as_pubkey(&self) -> PublicKey {
        PublicKey::from_bytes(&self.0).unwrap()
    }
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self, f)
    }
}

impl fmt::Display for Account {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "xrb_")?;
        let mut reverse_chars = Vec::<u8>::new();
        let mut check_hash = Blake2b::new(5).unwrap();
        check_hash.process(&self.0 as &[u8]);
        let mut check = [0u8; 5];
        check_hash.variable_result(&mut check).unwrap();
        let mut ext_addr = self.0.to_vec();
        ext_addr.extend(check.iter().rev());
        let mut ext_addr = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ext_addr);
        for _ in 0..60 {
            let n: BigInt = (&ext_addr) % 32; // lower 5 bits
            reverse_chars.push(ACCOUNT_LOOKUP[n.to_usize().unwrap()]);
            ext_addr = ext_addr >> 5;
        }
        let s = reverse_chars
            .iter()
            .rev()
            .map(|&c| c as char)
            .collect::<String>();
        write!(f, "{}", s)
    }
}

impl Into<PublicKey> for Account {
    fn into(self) -> PublicKey {
        self.as_pubkey()
    }
}

#[derive(Debug)]
pub enum AccountParseError {
    IncorrectLength,
    MissingPrefix,
    InvalidCharacter(char),
    InvalidChecksum,
}

impl FromStr for Account {
    type Err = AccountParseError;

    fn from_str(s: &str) -> Result<Account, AccountParseError> {
        let mut s_chars = s.chars();
        let mut ext_pubkey = BigInt::default();
        if !(&mut s_chars).take(4).eq("xrb_".chars()) {
            return Err(AccountParseError::MissingPrefix);
        }
        let mut i = 4;
        for ch in s_chars {
            if i >= 64 {
                return Err(AccountParseError::IncorrectLength);
            }
            let lookup = ACCOUNT_LOOKUP.iter().position(|&c| (c as char) == ch);
            let byte = match lookup {
                Some(p) => p as u8,
                None => {
                    return Err(AccountParseError::InvalidCharacter(ch));
                }
            };
            ext_pubkey = ext_pubkey << 5;
            ext_pubkey = ext_pubkey + byte;
            i += 1;
        }
        if i != 64 {
            return Err(AccountParseError::IncorrectLength);
        }
        let ext_pubkey = ext_pubkey.to_bytes_le().1;
        let ext_pubkey: Vec<u8> = iter::repeat(0)
            .take(37 - ext_pubkey.len())
            .chain(ext_pubkey.into_iter().rev())
            .collect();
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.clone_from_slice(&ext_pubkey[..32]);
        let mut checksum_given = [0u8; 5];
        checksum_given.clone_from_slice(&ext_pubkey[32..]);
        let mut checksum_calc = [0u8; 5];
        let mut hasher = Blake2b::new(checksum_calc.len()).unwrap();
        hasher.process(&pubkey_bytes as &[u8]);
        hasher
            .variable_result(&mut checksum_calc as &mut [u8])
            .unwrap();
        if checksum_given
            .into_iter()
            .rev()
            .ne(checksum_calc.into_iter())
        {
            return Err(AccountParseError::InvalidChecksum);
        }
        Ok(Account(pubkey_bytes))
    }
}

impl Hash for Account {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq, Clone)] // , Deserialize
//#[serde(tag = "type")]
//#[serde(rename_all = "lowercase")]
pub enum BlockInner {
    Send {
        previous: BlockHash,
        destination: Account,
        /// The balance of the account *after* the send.
        balance: u128,
    },
    Receive {
        previous: BlockHash,
        /// The block we're receiving.
        source: BlockHash,
    },
    /// The first "receive" in an account chain.
    /// Creates the account, and sets the representative.
    Open {
        /// The block we're receiving.
        source: BlockHash,
        representative: Account,
        account: Account,
    },
    /// Changes the representative for an account.
    Change {
        previous: BlockHash,
        representative: Account,
    },
    /// A universal transaction which contains the account state.
    State {
        account: Account,
        previous: BlockHash,
        representative: Account,
        balance: u128,
        /// Link field contains source block_hash if receiving, destination account if sending
        //#[serde(deserialize_with = "InternalFromHex::from_hex")]
        link: [u8; 32],
    },
}

impl Hash for BlockInner {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match *self {
            BlockInner::Send {
                ref previous,
                ref destination,
                ref balance,
            } => {
                previous.hash(state);
                destination.hash(state);
                let mut buf = [0u8; 16];
                BigEndian::write_u128(&mut buf, *balance);
                state.write(&buf);
            }
            BlockInner::Receive {
                ref previous,
                ref source,
            } => {
                previous.hash(state);
                source.hash(state);
            }
            BlockInner::Open {
                ref source,
                ref representative,
                ref account,
            } => {
                source.hash(state);
                representative.hash(state);
                account.hash(state);
            }
            BlockInner::Change {
                ref previous,
                ref representative,
            } => {
                previous.hash(state);
                representative.hash(state);
            }
            BlockInner::State {
                ref account,
                ref previous,
                ref representative,
                ref balance,
                ref link,
            } => {
                state.write(&[0u8; 31]);
                state.write(&[6u8]); // block type code
                account.hash(state);
                previous.hash(state);
                representative.hash(state);
                let mut buf = [0u8; 16];
                BigEndian::write_u128(&mut buf, *balance);
                state.write(&buf);
                state.write(link);
            }
        }
    }
}

struct DigestHasher<'a, D: 'a>(&'a mut D);

impl<'a, D: digest::Input + 'a> Hasher for DigestHasher<'a, D> {
    fn write(&mut self, input: &[u8]) {
        self.0.process(input);
    }

    fn finish(&self) -> u64 {
        unimplemented!()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum BlockRoot {
    Block(BlockHash),
    Account(Account),
}

impl AsRef<[u8; 32]> for BlockRoot {
    fn as_ref(&self) -> &[u8; 32] {
        match *self {
            BlockRoot::Block(BlockHash(ref bytes)) => bytes,
            BlockRoot::Account(Account(ref bytes)) => bytes,
        }
    }
}

impl Into<[u8; 32]> for BlockRoot {
    fn into(self) -> [u8; 32] {
        match self {
            BlockRoot::Block(BlockHash(bytes)) => bytes,
            BlockRoot::Account(Account(bytes)) => bytes,
        }
    }
}

impl BlockInner {
    pub fn get_hash(&self) -> BlockHash {
        let mut hasher = Blake2b::new(32).expect("Unsupported hash length");
        self.hash(&mut DigestHasher(&mut hasher));
        let mut output = BlockHash::default();
        hasher
            .variable_result(&mut output.0)
            .expect("Incorrect hash length");
        output
    }

    pub fn previous(&self) -> Option<&BlockHash> {
        match *self {
            BlockInner::Send { ref previous, .. } => Some(previous),
            BlockInner::Receive { ref previous, .. } => Some(previous),
            BlockInner::Change { ref previous, .. } => Some(previous),
            BlockInner::Open { .. } => None,
            BlockInner::State { ref previous, .. } => {
                let is_zero = previous.0.iter().all(|&x| x == 0);
                if is_zero {
                    None
                } else {
                    Some(previous)
                }
            }
        }
    }

    pub fn root_bytes(&self) -> &[u8; 32] {
        match *self {
            BlockInner::Send { ref previous, .. } => &previous.0,
            BlockInner::Receive { ref previous, .. } => &previous.0,
            BlockInner::Change { ref previous, .. } => &previous.0,
            BlockInner::Open { ref account, .. } => &account.0,
            BlockInner::State { ref account, .. } => {
                self.previous().map(|h| &h.0).unwrap_or(&account.0)
            }
        }
    }

    pub fn into_root(self) -> BlockRoot {
        match self {
            BlockInner::Send { previous, .. } => BlockRoot::Block(previous),
            BlockInner::Receive { previous, .. } => BlockRoot::Block(previous),
            BlockInner::Change { previous, .. } => BlockRoot::Block(previous),
            BlockInner::Open { account, .. } => BlockRoot::Account(account),
            BlockInner::State {
                account, previous, ..
            } => {
                let prev_is_zero = previous.0.iter().all(|&x| x == 0);
                if prev_is_zero {
                    BlockRoot::Account(account)
                } else {
                    BlockRoot::Block(previous)
                }
            }
        }
    }

    pub fn size(&self) -> usize {
        match *self {
            BlockInner::Send { .. } => 32 + 32 + 16,
            BlockInner::Receive { .. } => 32 + 32,
            BlockInner::Change { .. } => 32 + 32,
            BlockInner::Open { .. } => 32 + 32 + 32,
            BlockInner::State { .. } => 32 + 32 + 32 + 16 + 32,
        }
    }
}

#[derive(Debug, Clone)] // , Deserialize
pub struct Block {
    /*#[serde(flatten)]*/ pub inner: BlockInner,
    /*#[serde(flatten)]*/ pub header: BlockHeader,
}

impl Block {
    pub fn get_hash(&self) -> BlockHash {
        self.inner.get_hash()
    }

    pub fn previous(&self) -> Option<&BlockHash> {
        self.inner.previous()
    }

    pub fn root_bytes(&self) -> &[u8; 32] {
        self.inner.root_bytes()
    }

    pub fn into_root(self) -> BlockRoot {
        self.inner.into_root()
    }

    pub fn work_threshold(&self, network: Network) -> u64 {
        match network {
            Network::Live | Network::Beta => 0xffffffc000000000,
            Network::Test => 0xff00000000000000,
        }
    }

    pub fn work_value(&self) -> u64 {
        let mut buf = [0u8; 8];
        let mut hasher = Blake2b::new(buf.len()).expect("Unsupported hash length");
        LittleEndian::write_u64(&mut buf, self.header.work);
        hasher.process(&buf);
        hasher.process(self.root_bytes() as _);
        hasher.variable_result(&mut buf).unwrap();
        LittleEndian::read_u64(&buf as _)
    }

    pub fn work_valid(&self, network: Network) -> bool {
        self.work_value() > self.work_threshold(network)
    }

    pub fn size(&self) -> usize {
        // inner + sig + work
        self.inner.size() + 64 + 8
    }
}

impl Hash for Block {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq(&other.inner)
    }
}

impl Eq for Block {}

#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub account: Account,
    pub signature: Signature,
    pub sequence: u64,
    pub block: Block,
}

impl Hash for Vote {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.block.get_hash().0);
        let mut seq_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut seq_bytes, self.sequence);
        state.write(&seq_bytes);
    }
}

impl Vote {
    pub fn get_hash(&self) -> [u8; 32] {
        let mut hasher = Blake2b::new(32).expect("Unsupported hash length");
        self.hash(&mut DigestHasher(&mut hasher));
        let mut output = [0u8; 32];
        hasher
            .variable_result(&mut output)
            .expect("Incorrect hash length");
        output
    }

    pub fn verify(&self) -> bool {
        self.account
            .as_pubkey()
            .verify::<Blake2b>(&self.get_hash(), &self.signature)
    }
}
