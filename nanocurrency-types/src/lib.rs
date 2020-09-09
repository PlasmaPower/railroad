use std::borrow::Cow;
use std::convert::AsRef;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter;
use std::str;
use std::str::FromStr;

extern crate blake2;
use blake2::{Blake2b, VarBlake2b};
extern crate digest;
use digest::{Input, VariableOutput};

extern crate byteorder;
use byteorder::{BigEndian, ByteOrder, LittleEndian};

extern crate num_bigint;
use num_bigint::BigInt;
extern crate num_traits;
use num_traits::cast::ToPrimitive;

extern crate ed25519_dalek;
use ed25519_dalek::PublicKey;
pub use ed25519_dalek::Signature;

extern crate hex;

extern crate serde;
use serde::de::Error as SerdeError;
use serde::de::Visitor as serdeVisitor;
use serde::Deserialize;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate serde_json;

#[cfg(test)]
mod tests;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Network {
    Test,
    Beta,
    Live,
}

#[macro_export]
macro_rules! zero_v6_addr {
    () => {
        ::std::net::SocketAddrV6::new(::std::net::Ipv6Addr::from([0u8; 16]), 0, 0, 0)
    };
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
        if v.len() > self.byte_len * 2 {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut hex_string = Cow::Borrowed(v);
        if v.len() < self.byte_len * 2 {
            let mut new_string = String::with_capacity(self.byte_len * 2);
            for _ in 0..(self.byte_len * 2 - v.len()) {
                new_string.push('0');
            }
            new_string.extend(v.chars());
            hex_string = Cow::Owned(new_string);
        }
        let bytes = hex::decode((&hex_string).as_bytes())
            .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(&v), &self))?;
        assert_eq!(
            bytes.len(),
            self.byte_len,
            "Hex decoding produced unexpected length"
        );
        Ok(bytes)
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

impl InternalFromHex for u128 {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(InternalHexVisitor::new(16))
            .map(|bytes| BigEndian::read_u128(&bytes))
    }
}

impl InternalFromHex for BlockHash {
    fn from_hex<'de, D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer
            .deserialize_str(InternalHexVisitor::new(32))
            .map(|bytes| {
                let mut hash = BlockHash([0u8; 32]);
                hash.0.clone_from_slice(&bytes);
                hash
            })
    }
}

trait InternalToHex {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
}

impl InternalToHex for Signature {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode_upper(&self.to_bytes() as &[u8]))
    }
}

impl InternalToHex for u64 {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = [0u8; 8];
        BigEndian::write_u64(&mut bytes, *self);
        serializer.serialize_str(&hex::encode(&bytes))
    }
}

impl InternalToHex for u128 {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut bytes = [0u8; 16];
        BigEndian::write_u128(&mut bytes, *self);
        serializer.serialize_str(&hex::encode_upper(&bytes))
    }
}

impl InternalToHex for BlockHash {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode_upper(&self.0))
    }
}

impl InternalToHex for [u8; 32] {
    fn to_hex<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode_upper(&self))
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BlockHeader {
    #[serde(deserialize_with = "InternalFromHex::from_hex")]
    #[serde(serialize_with = "InternalToHex::to_hex")]
    pub signature: Signature,
    #[serde(deserialize_with = "InternalFromHex::from_hex")]
    #[serde(serialize_with = "InternalToHex::to_hex")]
    pub work: u64,
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
        write!(f, "nano_")?;
        let mut reverse_chars = Vec::<u8>::new();
        let mut check_hash = VarBlake2b::new(5).unwrap();
        check_hash.input(&self.0 as &[u8]);
        let mut ext_addr = self.0.to_vec();
        check_hash.variable_result(|b| ext_addr.extend(b.iter().rev()));
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

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum AccountParseError {
    IncorrectLength,
    MissingPrefix,
    InvalidCharacter(char),
    InvalidChecksum,
}

impl fmt::Display for AccountParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AccountParseError::IncorrectLength => write!(f, "incorrect length"),
            AccountParseError::MissingPrefix => write!(f, "missing prefix"),
            AccountParseError::InvalidCharacter(c) => write!(f, "invalid character: {:?}", c),
            AccountParseError::InvalidChecksum => write!(f, "invalid checksum"),
        }
    }
}

impl FromStr for Account {
    type Err = AccountParseError;

    fn from_str(s: &str) -> Result<Account, AccountParseError> {
        let mut s_chars = s.chars();
        let mut ext_pubkey = BigInt::default();
        if s.starts_with("xrb_") {
            (&mut s_chars).take(4).count();
        } else if s.starts_with("nano_") {
            (&mut s_chars).take(5).count();
        } else {
            return Err(AccountParseError::MissingPrefix);
        }
        let mut i = 0;
        for ch in s_chars {
            if i >= 60 {
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
        if i != 60 {
            return Err(AccountParseError::IncorrectLength);
        }
        let ext_pubkey = ext_pubkey.to_bytes_le().1;
        if ext_pubkey.len() > 37 {
            // First character is not a 1 or a 3,
            // which causes the pubkey to be too long.
            return Err(AccountParseError::IncorrectLength);
        }
        let ext_pubkey: Vec<u8> = iter::repeat(0)
            .take(37 - ext_pubkey.len())
            .chain(ext_pubkey.into_iter().rev())
            .collect();
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.clone_from_slice(&ext_pubkey[..32]);
        let mut checksum_given = [0u8; 5];
        checksum_given.clone_from_slice(&ext_pubkey[32..]);
        let mut hasher = VarBlake2b::new(5).unwrap();
        hasher.input(&pubkey_bytes as &[u8]);
        let mut matches = false;
        hasher.variable_result(|checksum_calc| {
            matches = checksum_given.iter().rev().eq(checksum_calc.into_iter());
        });
        if matches {
            Ok(Account(pubkey_bytes))
        } else {
            Err(AccountParseError::InvalidChecksum)
        }
    }
}

impl Hash for Account {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

fn serde_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr,
    T::Err: fmt::Display,
    D: serde::de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_str(&s).map_err(serde::de::Error::custom)
}

fn serde_to_str<T: ToString, S: serde::ser::Serializer>(
    value: &T,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn deserialize_link<'de, D: serde::de::Deserializer<'de>>(
    deserializer: D,
) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(deserializer)?;
    if s.starts_with("xrb_") || s.starts_with("nano_") {
        Account::from_str(&s)
            .map_err(serde::de::Error::custom)
            .map(|a| a.0)
    } else {
        let visitor = InternalHexVisitor::new(32);
        let mut bytes = [0u8; 32];
        bytes.clone_from_slice(&visitor.visit_str(&s)?);
        Ok(bytes)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Deserialize, Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum BlockInner {
    Send {
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        previous: BlockHash,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        destination: Account,
        /// The balance of the account *after* the send.
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        balance: u128,
    },
    Receive {
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        previous: BlockHash,
        /// The block we're receiving.
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        source: BlockHash,
    },
    /// The first "receive" in an account chain.
    /// Creates the account, and sets the representative.
    Open {
        /// The block we're receiving.
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        source: BlockHash,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        representative: Account,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        account: Account,
    },
    /// Changes the representative for an account.
    Change {
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        previous: BlockHash,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        representative: Account,
    },
    /// A universal transaction which contains the account state.
    State {
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        account: Account,
        #[serde(deserialize_with = "InternalFromHex::from_hex")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
        previous: BlockHash,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        representative: Account,
        #[serde(deserialize_with = "serde_from_str")]
        #[serde(serialize_with = "serde_to_str")]
        balance: u128,
        /// Link field contains source block_hash if receiving, destination account if sending
        #[serde(deserialize_with = "deserialize_link")]
        #[serde(serialize_with = "InternalToHex::to_hex")]
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
        self.0.input(input);
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

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum BlockType {
    Send,
    Receive,
    Open,
    Change,
    State,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum BlockTypeCodeError {
    Invalid,
    NotABlock,
    Unknown,
}

impl BlockType {
    pub fn name(self) -> &'static str {
        match self {
            BlockType::Send => "send",
            BlockType::Receive => "receive",
            BlockType::Open => "open",
            BlockType::Change => "change",
            BlockType::State => "state",
        }
    }

    pub fn size(self) -> usize {
        match self {
            BlockType::Send => 32 + 32 + 16,
            BlockType::Receive => 32 + 32,
            BlockType::Open => 32 + 32 + 32,
            BlockType::Change => 32 + 32,
            BlockType::State => 32 + 32 + 32 + 16 + 32,
        }
    }

    pub fn to_type_code(self) -> u8 {
        self.into()
    }

    pub fn from_type_code(code: u8) -> Result<BlockType, BlockTypeCodeError> {
        match code {
            0 => Err(BlockTypeCodeError::Invalid),
            1 => Err(BlockTypeCodeError::NotABlock),
            2 => Ok(BlockType::Send),
            3 => Ok(BlockType::Receive),
            4 => Ok(BlockType::Open),
            5 => Ok(BlockType::Change),
            6 => Ok(BlockType::State),
            _ => Err(BlockTypeCodeError::Unknown),
        }
    }
}

impl Into<u8> for BlockType {
    fn into(self) -> u8 {
        match self {
            BlockType::Send => 2,
            BlockType::Receive => 3,
            BlockType::Open => 4,
            BlockType::Change => 5,
            BlockType::State => 6,
        }
    }
}

impl fmt::Display for BlockType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl BlockInner {
    pub fn get_hash(&self) -> BlockHash {
        let mut hasher = VarBlake2b::new(32).expect("Unsupported hash length");
        self.hash(&mut DigestHasher(&mut hasher));
        let mut output = BlockHash::default();
        hasher.variable_result(|b| output.0.copy_from_slice(b));
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

    pub fn ty(&self) -> BlockType {
        match *self {
            BlockInner::Send { .. } => BlockType::Send,
            BlockInner::Receive { .. } => BlockType::Receive,
            BlockInner::Change { .. } => BlockType::Change,
            BlockInner::Open { .. } => BlockType::Open,
            BlockInner::State { .. } => BlockType::State,
        }
    }

    pub fn size(&self) -> usize {
        self.ty().size()
    }
}

pub fn work_threshold(network: Network) -> u64 {
    match network {
        Network::Live | Network::Beta => 0xffffffc000000000,
        Network::Test => 0xff00000000000000,
    }
}

pub fn work_value(root: &[u8], work: u64) -> u64 {
    let mut hasher = VarBlake2b::new(8).expect("Unsupported hash length");
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, work);
    hasher.input(&buf);
    hasher.input(root);
    let mut val = 0;
    hasher.variable_result(|b| val = LittleEndian::read_u64(b));
    val
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Block {
    #[serde(flatten)]
    pub inner: BlockInner,
    #[serde(flatten)]
    pub header: BlockHeader,
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

    #[deprecated]
    /// Use global work_threshold function instead
    pub fn work_threshold(&self, network: Network) -> u64 {
        work_threshold(network)
    }

    pub fn work_value(&self) -> u64 {
        work_value(self.root_bytes() as _, self.header.work)
    }

    pub fn work_valid(&self, network: Network) -> bool {
        self.work_value() > work_threshold(network)
    }

    pub fn ty(&self) -> BlockType {
        self.inner.ty()
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

/// What the vote is for.
/// Note: internally, the official node can have mixed types in a vote.
/// However, over the wire, this isn't possible.
#[derive(Debug, Clone, PartialEq)]
pub enum VoteInner {
    Block(Block),
    Hashes(Vec<BlockHash>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Vote {
    pub account: Account,
    pub signature: Signature,
    pub sequence: u64,
    pub inner: VoteInner,
}

const VOTE_HASH_PREFIX: &[u8] = b"vote ";

impl Hash for Vote {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.inner {
            VoteInner::Block(block) => {
                state.write(&block.get_hash().0);
            }
            VoteInner::Hashes(hashes) => {
                state.write(&VOTE_HASH_PREFIX);
                for hash in hashes {
                    state.write(&hash.0);
                }
            }
        }
        let mut seq_bytes = [0u8; 8];
        LittleEndian::write_u64(&mut seq_bytes, self.sequence);
        state.write(&seq_bytes);
    }
}

impl Vote {
    pub fn get_hash(&self) -> [u8; 32] {
        let mut hasher = VarBlake2b::new(32).expect("Unsupported hash length");
        self.hash(&mut DigestHasher(&mut hasher));
        let mut output = [0u8; 32];
        hasher.variable_result(|b| output.copy_from_slice(b));
        output
    }

    pub fn verify(&self) -> bool {
        self.account
            .as_pubkey()
            .verify::<Blake2b>(&self.get_hash(), &self.signature)
            .is_ok()
    }
}
