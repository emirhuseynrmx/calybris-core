//! OpenTimestamps proofs: a checkpoint's digest committed to the Bitcoin
//! blockchain through free public calendar servers.
//!
//! An RFC 3161 token is only as good as the authority that signed it. An
//! OpenTimestamps proof needs no authority: it is a chain of hash operations
//! from the stamped digest to the Merkle root of a Bitcoin block, so anyone
//! with that block's header can check it, and backdating it means redoing the
//! proof of work of every block since. Calendars aggregate submissions for
//! free and commit to them in a transaction every few hours; until then the
//! proof holds only a promise.
//!
//! That promise is not evidence, and this module keeps the difference
//! explicit. A proof goes through three states, and only the last dates
//! anything:
//!
//! - **Pending** ([`Status::Pending`]) — calendars accepted the digest and
//!   will commit it.
//! - **Anchored** ([`Status::Anchored`]) — the proof reaches a Bitcoin block
//!   attestation, not yet checked against anything.
//! - **Confirmed** ([`BitcoinConfirmed`]) — [`DetachedTimestamp::verify_bitcoin`]
//!   recomputed the path to the Merkle root of a header whose proof of work
//!   meets both its own target and a floor, *and* [`BitcoinHeader::confirm`]
//!   matched that header's hash against a source the verifier trusts to know
//!   the main chain: its own node, or several independent explorers that
//!   agree.
//!
//! The second step is not optional. A header is 80 bytes anyone can write:
//! one with an easy target and the right Merkle root passes every check a
//! header can have on its own. The work floor
//! ([`MIN_TARGET_ZERO_BITS`]) makes such a header cost about 2^64 hashes
//! instead of nothing; only the chain check makes it worthless.
//!
//! The file format is the one the reference Python client writes (`.ots`,
//! magic `\0OpenTimestamps\0\0Proof\0…`), serialized in the same canonical
//! order, so its tools read these files and this module reads theirs. Only
//! SHA-256, RIPEMD-160, append, prepend, reverse and hexlify are evaluated;
//! a branch through SHA-1 or Keccak is kept intact but not trusted.
//!
//! Transport is the caller's: [`calendar_submit_path`] and
//! [`calendar_upgrade_path`] name the HTTP requests, [`DetachedTimestamp::merge_calendar_response`]
//! folds in what comes back.
//!
//! The height in a Bitcoin attestation is not covered by anything: it is a
//! hint where to look, and editing it does not break the hash path. A header
//! does not carry its own height either. So [`DetachedTimestamp::verify_bitcoin`]
//! takes the height the *verifier* fetched the header at, from a node or
//! explorers it trusts, and accepts only an attestation naming that height
//! whose message is that header's Merkle root.

use ripemd::Ripemd160;

use crate::digest::bytes_to_hex;
use sha2::{Digest, Sha256};

/// File magic of a detached timestamp.
pub const MAGIC: &[u8; 31] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const MAJOR_VERSION: u8 = 1;
const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK: u8 = 0xff;
const TAG_SHA1: u8 = 0x02;
const TAG_RIPEMD160: u8 = 0x03;
const TAG_SHA256: u8 = 0x08;
const TAG_KECCAK256: u8 = 0x67;
const TAG_APPEND: u8 = 0xf0;
const TAG_PREPEND: u8 = 0xf1;
const TAG_REVERSE: u8 = 0xf2;
const TAG_HEXLIFY: u8 = 0xf3;
const PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const MAX_MSG: usize = 4096;
const MAX_PAYLOAD: usize = 8192;
const MAX_URI: usize = 1000;
const MAX_DEPTH: usize = 256;
/// Largest file or calendar response read.
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

/// The calendars the reference client submits to by default.
pub const DEFAULT_CALENDARS: [&str; 4] = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

/// Why a proof was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum OtsError {
    #[error("malformed proof: {0}")]
    Malformed(&'static str),
    #[error("the proof is for a different digest")]
    WrongDigest,
    #[error("no Bitcoin attestation in the proof commits to this block header at this height")]
    NotInBlock,
    #[error("the block header's proof of work does not meet its own target")]
    BadProofOfWork,
    #[error("the block header's target is easier than any main-chain block this proof could name")]
    InsufficientWork,
    #[error("the block header is not the one the trusted source names for this height")]
    NotOnChain,
    #[error("calendar URL {0:?} is not on the allowed list")]
    CalendarNotAllowed(String),
}

/// One operation on the message.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Self::Sha1 => TAG_SHA1,
            Self::Ripemd160 => TAG_RIPEMD160,
            Self::Sha256 => TAG_SHA256,
            Self::Keccak256 => TAG_KECCAK256,
            Self::Append(_) => TAG_APPEND,
            Self::Prepend(_) => TAG_PREPEND,
            Self::Reverse => TAG_REVERSE,
            Self::Hexlify => TAG_HEXLIFY,
        }
    }

    fn sort_key(&self) -> (u8, &[u8]) {
        match self {
            Self::Append(a) | Self::Prepend(a) => (self.tag(), a),
            _ => (self.tag(), &[]),
        }
    }

    /// Applies the operation. `None` for an operation this module does not
    /// evaluate (SHA-1, Keccak), or a result over the length limit.
    fn apply(&self, msg: &[u8]) -> Option<Vec<u8>> {
        let out = match self {
            Self::Sha256 => Sha256::digest(msg).to_vec(),
            Self::Ripemd160 => Ripemd160::digest(msg).to_vec(),
            Self::Append(a) => [msg, a].concat(),
            Self::Prepend(a) => [a.as_slice(), msg].concat(),
            Self::Reverse => msg.iter().rev().copied().collect(),
            Self::Hexlify => msg
                .iter()
                .flat_map(|b| format!("{b:02x}").into_bytes())
                .collect(),
            Self::Sha1 | Self::Keccak256 => return None,
        };
        (out.len() <= MAX_MSG).then_some(out)
    }
}

/// What a branch of the proof ends in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attestation {
    /// A calendar's promise to commit this message later.
    Pending { uri: String },
    /// The message is the Merkle root of the Bitcoin block at `height`.
    Bitcoin { height: u64 },
    /// Any other notary (Litecoin, Ethereum, future ones), kept verbatim.
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

impl Attestation {
    fn sort_key(&self) -> ([u8; 8], Vec<u8>) {
        match self {
            // Within a notary the reference client orders by the payload's
            // meaning: URI text for pending, height for Bitcoin.
            Self::Pending { uri } => (PENDING, uri.as_bytes().to_vec()),
            Self::Bitcoin { height } => (BITCOIN, height.to_be_bytes().to_vec()),
            Self::Unknown { tag, payload } => (*tag, payload.clone()),
        }
    }
}

/// A node of the proof: the message at this point, what attests to it, and
/// the operations leading on from it.
///
/// Attestations and operations are kept in the reference client's canonical
/// order whichever order they arrived in, so two proofs with the same
/// content compare equal and a parsed proof equals the one its serialization
/// parses back to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    msg: Vec<u8>,
    attestations: Vec<Attestation>,
    ops: Vec<(Op, Timestamp)>,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<u8, OtsError> {
        let b = *self
            .bytes
            .get(self.at)
            .ok_or(OtsError::Malformed("unexpected end of proof"))?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&[u8], OtsError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or(OtsError::Malformed("unexpected end of proof"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn varuint(&mut self) -> Result<u64, OtsError> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            let part = u64::from(b & 0x7f);
            if shift == 63 && part > 1 {
                return Err(OtsError::Malformed("varuint overflows u64"));
            }
            value |= part << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(OtsError::Malformed("varuint overflows u64"))
    }

    fn varbytes(&mut self, max: usize) -> Result<Vec<u8>, OtsError> {
        let len = usize::try_from(self.varuint()?)
            .ok()
            .filter(|&l| l <= max)
            .ok_or(OtsError::Malformed("length over the limit"))?;
        Ok(self.take(len)?.to_vec())
    }
}

fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varuint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn valid_uri(uri: &str) -> bool {
    uri.len() <= MAX_URI
        && uri
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-._/:".contains(&c))
}

impl Timestamp {
    /// An empty proof for `msg`, to which operations and attestations are
    /// added.
    #[must_use]
    pub fn new(msg: Vec<u8>) -> Self {
        Self {
            msg,
            attestations: Vec::new(),
            ops: Vec::new(),
        }
    }

    #[must_use]
    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    /// Reads a proof for `msg` (the format carries operations, not messages).
    pub fn deserialize(bytes: &[u8], msg: &[u8]) -> Result<Self, OtsError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(OtsError::Malformed("proof is too large"));
        }
        let mut r = Reader { bytes, at: 0 };
        let t = Self::read(&mut r, msg.to_vec(), MAX_DEPTH)?;
        if r.at != bytes.len() {
            return Err(OtsError::Malformed("trailing bytes after the proof"));
        }
        Ok(t)
    }

    fn read(r: &mut Reader<'_>, msg: Vec<u8>, depth: usize) -> Result<Self, OtsError> {
        if depth == 0 {
            return Err(OtsError::Malformed("proof nests too deeply"));
        }
        let mut node = Self::new(msg);
        loop {
            let mut tag = r.byte()?;
            let fork = tag == TAG_FORK;
            if fork {
                tag = r.byte()?;
            }
            if tag == TAG_ATTESTATION {
                node.add_attestation(read_attestation(r)?);
            } else {
                let op = match tag {
                    TAG_SHA1 => Op::Sha1,
                    TAG_RIPEMD160 => Op::Ripemd160,
                    TAG_SHA256 => Op::Sha256,
                    TAG_KECCAK256 => Op::Keccak256,
                    TAG_REVERSE => Op::Reverse,
                    TAG_HEXLIFY => Op::Hexlify,
                    TAG_APPEND | TAG_PREPEND => {
                        let arg = r.varbytes(MAX_MSG)?;
                        if arg.is_empty() {
                            return Err(OtsError::Malformed("empty append or prepend"));
                        }
                        if tag == TAG_APPEND {
                            Op::Append(arg)
                        } else {
                            Op::Prepend(arg)
                        }
                    }
                    _ => return Err(OtsError::Malformed("unknown operation tag")),
                };
                // An operation not evaluated here still has to be read past;
                // its branch is carried with an empty message and ignored.
                let next = match op {
                    Op::Sha1 | Op::Keccak256 => Vec::new(),
                    _ => op
                        .apply(&node.msg)
                        .ok_or(OtsError::Malformed("operation result exceeds the limit"))?,
                };
                let child = Self::read(r, next, depth - 1)?;
                node.add_op(op, child);
            }
            if !fork {
                return Ok(node);
            }
        }
    }

    // Sort keys identify their item: two attestations, or two operations,
    // with the same key are equal. So a binary search both finds a duplicate
    // and gives the canonical position for a new one.
    fn add_attestation(&mut self, att: Attestation) {
        let key = att.sort_key();
        if let Err(at) = self
            .attestations
            .binary_search_by(|a| a.sort_key().cmp(&key))
        {
            self.attestations.insert(at, att);
        }
    }

    fn op_position(&self, op: &Op) -> Result<usize, usize> {
        self.ops
            .binary_search_by(|(o, _)| o.sort_key().cmp(&op.sort_key()))
    }

    fn add_op(&mut self, op: Op, child: Self) {
        match self.op_position(&op) {
            Ok(at) => self.ops[at].1.merge(child),
            Err(at) => self.ops.insert(at, (op, child)),
        }
    }

    /// Adds `op` after this node, or finds it if already present, and returns
    /// the node it leads to.
    pub fn op(&mut self, op: Op) -> &mut Self {
        let pos = match self.op_position(&op) {
            Ok(at) => at,
            Err(at) => {
                let next = op.apply(&self.msg).unwrap_or_default();
                self.ops.insert(at, (op, Self::new(next)));
                at
            }
        };
        &mut self.ops[pos].1
    }

    /// Folds another proof for the same message into this one.
    pub fn merge(&mut self, other: Self) {
        for att in other.attestations {
            self.add_attestation(att);
        }
        for (op, child) in other.ops {
            self.add_op(op, child);
        }
    }

    /// The proof in the reference client's canonical order.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        // Both lists are already in canonical order (see `add_attestation`).
        let total = self.attestations.len() + self.ops.len();
        let mut i = 0;
        for att in &self.attestations {
            i += 1;
            if i < total {
                out.push(TAG_FORK);
            }
            out.push(TAG_ATTESTATION);
            write_attestation(out, att);
        }
        for (op, child) in &self.ops {
            i += 1;
            if i < total {
                out.push(TAG_FORK);
            }
            out.push(op.tag());
            if let Op::Append(a) | Op::Prepend(a) = op {
                write_varbytes(out, a);
            }
            child.write(out);
        }
    }

    /// Every attestation with the message it attests to, in tree order.
    /// Branches through an operation this module does not evaluate are left
    /// out: their messages are unknown.
    #[must_use]
    pub fn attestations(&self) -> Vec<(Vec<u8>, Attestation)> {
        let mut out = Vec::new();
        self.collect(&mut out);
        out
    }

    fn collect(&self, out: &mut Vec<(Vec<u8>, Attestation)>) {
        for a in &self.attestations {
            out.push((self.msg.clone(), a.clone()));
        }
        for (op, child) in &self.ops {
            if !matches!(op, Op::Sha1 | Op::Keccak256) {
                child.collect(out);
            }
        }
    }

    fn find_mut(&mut self, msg: &[u8]) -> Option<&mut Self> {
        if self.msg == msg {
            return Some(self);
        }
        self.ops.iter_mut().find_map(|(_, c)| c.find_mut(msg))
    }
}

fn read_attestation(r: &mut Reader<'_>) -> Result<Attestation, OtsError> {
    let tag: [u8; 8] = r.take(8)?.try_into().expect("eight bytes");
    let payload = r.varbytes(MAX_PAYLOAD)?;
    let mut inner = Reader {
        bytes: &payload,
        at: 0,
    };
    let att = match tag {
        PENDING => {
            let uri = String::from_utf8(inner.varbytes(MAX_URI)?)
                .map_err(|_| OtsError::Malformed("calendar URI is not UTF-8"))?;
            if !valid_uri(&uri) {
                return Err(OtsError::Malformed(
                    "calendar URI has a disallowed character",
                ));
            }
            Attestation::Pending { uri }
        }
        BITCOIN => Attestation::Bitcoin {
            height: inner.varuint()?,
        },
        _ => {
            inner.at = payload.len();
            Attestation::Unknown {
                tag,
                payload: payload.clone(),
            }
        }
    };
    if inner.at != payload.len() {
        return Err(OtsError::Malformed(
            "attestation payload has trailing bytes",
        ));
    }
    Ok(att)
}

fn write_attestation(out: &mut Vec<u8>, att: &Attestation) {
    let mut payload = Vec::new();
    let tag = match att {
        Attestation::Pending { uri } => {
            write_varbytes(&mut payload, uri.as_bytes());
            PENDING
        }
        Attestation::Bitcoin { height } => {
            write_varuint(&mut payload, *height);
            BITCOIN
        }
        Attestation::Unknown { tag, payload: p } => {
            payload.extend_from_slice(p);
            *tag
        }
    };
    out.extend_from_slice(&tag);
    write_varbytes(out, &payload);
}

/// Where a proof stands, from the proof alone. Neither state dates anything;
/// see [`BitcoinConfirmed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Calendars promised to commit; the URIs to ask for the upgrade.
    Pending { calendars: Vec<String> },
    /// Reaches Bitcoin attestations at these heights, not yet checked
    /// against a header.
    Anchored { heights: Vec<u64> },
}

/// A proof checked against a block header: the path reaches the header's
/// Merkle root and the header's work is real. Not yet evidence: nothing here
/// shows the header is on the main chain. Call [`BitcoinHeader::confirm`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinHeader {
    /// The height the verifier fetched the header at.
    pub height: u64,
    /// The header's hash, in the usual reversed hex display order.
    pub block_hash: String,
    /// The header's timestamp, Unix seconds.
    pub block_time: u64,
}

impl BitcoinHeader {
    /// Confirms the header against the block hash a trusted source gives for
    /// this height (`bitcoin-cli getblockhash <height>` on your own node, or
    /// the agreed answer of independent explorers), as hex in display order.
    pub fn confirm(&self, trusted_block_hash: &str) -> Result<BitcoinConfirmed, OtsError> {
        if trusted_block_hash
            .trim()
            .eq_ignore_ascii_case(&self.block_hash)
        {
            Ok(BitcoinConfirmed {
                height: self.height,
                block_hash: self.block_hash.clone(),
                block_time: self.block_time,
            })
        } else {
            Err(OtsError::NotOnChain)
        }
    }
}

/// A proof committed in a block that a trusted source puts on the main
/// chain. `block_time` is the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinConfirmed {
    pub height: u64,
    pub block_hash: String,
    /// The block's timestamp, Unix seconds.
    pub block_time: u64,
}

/// The fewest leading zero bits a header's target may have. Every block an
/// OpenTimestamps proof can name (the service started in 2016; its 2015
/// example, block 358391, is checked in tests/opentimestamps.rs) is far harder; a header
/// under this floor is refused before anything else is looked at.
pub const MIN_TARGET_ZERO_BITS: u32 = 64;

/// A detached `.ots` file: the SHA-256 digest of a file and its proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedTimestamp {
    timestamp: Timestamp,
}

impl DetachedTimestamp {
    /// A new, empty proof for `digest` (SHA-256 of the stamped file).
    #[must_use]
    pub fn new(digest: [u8; 32]) -> Self {
        Self {
            timestamp: Timestamp::new(digest.to_vec()),
        }
    }

    /// Reads a `.ots` file. Only SHA-256 file digests are accepted.
    pub fn parse(bytes: &[u8]) -> Result<Self, OtsError> {
        if bytes.len() > MAX_PROOF_BYTES {
            return Err(OtsError::Malformed("proof is too large"));
        }
        let rest = bytes
            .strip_prefix(MAGIC.as_slice())
            .ok_or(OtsError::Malformed("not an OpenTimestamps proof"))?;
        let mut r = Reader { bytes: rest, at: 0 };
        if r.varuint()? != u64::from(MAJOR_VERSION) {
            return Err(OtsError::Malformed("unsupported major version"));
        }
        if r.byte()? != TAG_SHA256 {
            return Err(OtsError::Malformed(
                "only SHA-256 file digests are supported",
            ));
        }
        let digest = r.take(32)?.to_vec();
        let timestamp = Timestamp::read(&mut r, digest, MAX_DEPTH)?;
        if r.at != rest.len() {
            return Err(OtsError::Malformed("trailing bytes after the proof"));
        }
        Ok(Self { timestamp })
    }

    /// The file as the reference client writes it.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.push(MAJOR_VERSION);
        out.push(TAG_SHA256);
        out.extend_from_slice(&self.timestamp.msg);
        self.timestamp.write(&mut out);
        out
    }

    /// The digest this proof is for.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.timestamp.msg.as_slice().try_into().expect("32 bytes")
    }

    #[must_use]
    pub fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Prepares a submission: appends `nonce` to the digest and hashes, as
    /// the reference client does, and returns the 32-byte commitment to POST
    /// to each calendar. The nonce keeps a calendar from learning which digest
    /// it was sent; pass fresh random bytes.
    pub fn prepare_submission(&mut self, nonce: [u8; 16]) -> [u8; 32] {
        let node = self.timestamp.op(Op::Append(nonce.to_vec())).op(Op::Sha256);
        node.msg.as_slice().try_into().expect("32 bytes")
    }

    /// Folds a calendar's response for `commitment` into the proof: the body
    /// of a `/digest` submission or of a `/timestamp/<hex>` upgrade.
    pub fn merge_calendar_response(
        &mut self,
        commitment: &[u8],
        body: &[u8],
    ) -> Result<(), OtsError> {
        let upgrade = Timestamp::deserialize(body, commitment)?;
        let node = self
            .timestamp
            .find_mut(commitment)
            .ok_or(OtsError::Malformed(
                "the commitment is not part of this proof",
            ))?;
        node.merge(upgrade);
        Ok(())
    }

    /// Every pending attestation: the commitment and the calendar to ask.
    #[must_use]
    pub fn pending(&self) -> Vec<(Vec<u8>, String)> {
        self.timestamp
            .attestations()
            .into_iter()
            .filter_map(|(msg, a)| match a {
                Attestation::Pending { uri } => Some((msg, uri)),
                _ => None,
            })
            .collect()
    }

    /// Pending or anchored, from the proof alone.
    #[must_use]
    pub fn status(&self) -> Status {
        let mut heights: Vec<u64> = self
            .timestamp
            .attestations()
            .into_iter()
            .filter_map(|(_, a)| match a {
                Attestation::Bitcoin { height } => Some(height),
                _ => None,
            })
            .collect();
        if heights.is_empty() {
            let mut calendars: Vec<String> = self.pending().into_iter().map(|(_, u)| u).collect();
            calendars.sort();
            calendars.dedup();
            Status::Pending { calendars }
        } else {
            heights.sort_unstable();
            heights.dedup();
            Status::Anchored { heights }
        }
    }

    /// Checks the proof against the 80-byte header of the Bitcoin block at
    /// `height`, as the verifier fetched it: there must be an attestation for
    /// that height whose message is the header's Merkle root, the header's
    /// target must have at least [`MIN_TARGET_ZERO_BITS`] leading zero bits,
    /// and its hash must meet that target. The result still has to be
    /// confirmed against the main chain ([`BitcoinHeader::confirm`]).
    pub fn verify_bitcoin(
        &self,
        height: u64,
        header: &[u8; 80],
    ) -> Result<BitcoinHeader, OtsError> {
        let merkle_root = &header[36..68];
        let committed = self
            .timestamp
            .attestations()
            .into_iter()
            .any(|(msg, a)| a == Attestation::Bitcoin { height } && msg == merkle_root);
        if !committed {
            return Err(OtsError::NotInBlock);
        }
        let bits = u32::from_le_bytes(header[72..76].try_into().expect("4 bytes"));
        let target = target_of(bits).ok_or(OtsError::BadProofOfWork)?;
        if leading_zero_bits(&target) < MIN_TARGET_ZERO_BITS {
            return Err(OtsError::InsufficientWork);
        }
        let hash: [u8; 32] = Sha256::digest(Sha256::digest(header)).into();
        let mut be = hash;
        be.reverse();
        if be > target {
            return Err(OtsError::BadProofOfWork);
        }
        let block_time = u64::from(u32::from_le_bytes(
            header[68..72].try_into().expect("4 bytes"),
        ));
        let mut display = hash;
        display.reverse();
        let block_hash = bytes_to_hex(&display);
        Ok(BitcoinHeader {
            height,
            block_hash,
            block_time,
        })
    }
}

/// The big-endian 256-bit target a compact `nBits` encodes. A negative or
/// zero target, or one that overflows 256 bits, is `None` rather than wrapped.
fn target_of(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x00ff_ffff;
    if mantissa & 0x0080_0000 != 0 || mantissa == 0 || !(3..=32).contains(&exponent) {
        return None;
    }
    let mut target = [0_u8; 32];
    let m = mantissa.to_be_bytes();
    let start = 32 - exponent;
    target[start..start + 3].copy_from_slice(&m[1..]);
    Some(target)
}

fn leading_zero_bits(be: &[u8; 32]) -> u32 {
    let mut n = 0;
    for &b in be {
        if b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// Whether a block hash (internal byte order) is at or below the target a
/// compact `nBits` encodes.
#[cfg(test)]
fn meets_target(hash: &[u8; 32], bits: u32) -> bool {
    let Some(target) = target_of(bits) else {
        return false;
    };
    let mut be = *hash;
    be.reverse();
    be <= target
}

/// The path to POST a 32-byte commitment to, under a calendar's base URL.
#[must_use]
pub fn calendar_submit_path(calendar: &str) -> String {
    format!("{}/digest", calendar.trim_end_matches('/'))
}

/// The URL to GET an upgrade of `commitment` from the calendar a pending
/// attestation names, if that calendar is on `allowed` (patterns like
/// `https://*.calendar.opentimestamps.org`, as in the reference client).
pub fn calendar_upgrade_path(
    uri: &str,
    commitment: &[u8],
    allowed: &[&str],
) -> Result<String, OtsError> {
    if !valid_uri(uri) || !allowed.iter().any(|p| url_matches(p, uri)) {
        return Err(OtsError::CalendarNotAllowed(uri.to_owned()));
    }
    Ok(format!(
        "{}/timestamp/{}",
        uri.trim_end_matches('/'),
        bytes_to_hex(commitment)
    ))
}

/// The calendars the reference client trusts for upgrades.
pub const DEFAULT_UPGRADE_ALLOWLIST: [&str; 3] = [
    "https://*.calendar.opentimestamps.org",
    "https://*.calendar.eternitywall.com",
    "https://*.calendar.catallaxy.com",
];

/// A calendar URL against an allowlist pattern, as the reference client
/// matches them: same scheme, no path, and the host matching the pattern with
/// `*` standing for one or more characters. Stricter in one way: a host with
/// a port is never allowed.
fn url_matches(pattern: &str, uri: &str) -> bool {
    let (Some(p), Some(u)) = (
        pattern.strip_prefix("https://"),
        uri.strip_prefix("https://"),
    ) else {
        return false;
    };
    let host = u.strip_suffix('/').unwrap_or(u);
    if host.is_empty() || host.contains(['/', ':']) {
        return false;
    }
    match p.strip_prefix('*') {
        Some(suffix) => host.len() > suffix.len() && host.ends_with(suffix),
        None => host == p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varuints_round_trip_and_overflow_is_refused() {
        for v in [0, 1, 127, 128, 300, 358_391, u64::MAX] {
            let mut out = Vec::new();
            write_varuint(&mut out, v);
            let mut r = Reader { bytes: &out, at: 0 };
            assert_eq!(r.varuint().unwrap(), v);
        }
        let too_big = [0xff; 11];
        assert!(Reader {
            bytes: &too_big,
            at: 0
        }
        .varuint()
        .is_err());
    }

    #[test]
    fn a_target_is_met_exactly_at_its_bound() {
        // nBits 0x1d00ffff: the genesis target 0x00000000ffff0000…
        let bits = 0x1d00_ffff;
        let mut at = [0_u8; 32];
        at[26] = 0xff;
        at[27] = 0xff; // internal order is little-endian
        assert!(meets_target(&at, bits));
        let mut over = at;
        over[0] = 1;
        assert!(!meets_target(&over, bits));
        assert!(meets_target(&[0; 32], bits));
        assert!(!meets_target(&[0; 32], 0x1d80_0000)); // negative
        assert!(!meets_target(&[0; 32], 0x2200_ffff)); // overflow
    }

    #[test]
    fn the_work_floor_counts_leading_zero_bits_of_the_target() {
        // Genesis difficulty: 32 zero bits, far under the floor.
        assert_eq!(leading_zero_bits(&target_of(0x1d00_ffff).unwrap()), 32);
        // Exponent 0x17 leaves 32 - 23 = 9 zero bytes, and 0x03 adds 6 bits.
        assert_eq!(leading_zero_bits(&target_of(0x1703_4219).unwrap()), 78);
        assert_eq!(leading_zero_bits(&[0; 32]), 256);
    }

    #[test]
    fn calendar_urls_are_matched_like_the_reference_client() {
        let a = &DEFAULT_UPGRADE_ALLOWLIST;
        // What the public calendars actually call themselves.
        assert_eq!(
            calendar_upgrade_path("https://alice.btc.calendar.opentimestamps.org", &[1, 2], a)
                .unwrap(),
            "https://alice.btc.calendar.opentimestamps.org/timestamp/0102"
        );
        assert!(
            calendar_upgrade_path("https://finney.calendar.eternitywall.com/", &[1], a).is_ok()
        );
        assert!(calendar_upgrade_path("https://evilcalendar.opentimestamps.org", &[1], a).is_err());
        assert!(
            calendar_upgrade_path("https://x.calendar.opentimestamps.org/path", &[1], a).is_err()
        );
        assert!(
            calendar_upgrade_path("https://evil.com:1.calendar.opentimestamps.org", &[1], a)
                .is_err()
        );
        assert!(calendar_upgrade_path(
            "https://evil.example/x.calendar.opentimestamps.org",
            &[1],
            a
        )
        .is_err());
        assert!(
            calendar_upgrade_path("http://alice.calendar.opentimestamps.org", &[1], a).is_err()
        );
        assert!(calendar_upgrade_path("https://calendar.opentimestamps.org", &[1], a).is_err());
        assert!(calendar_upgrade_path("https://a.calendar.opentimestamps.org?x", &[1], a).is_err());
        let exact = ["https://alice.btc.calendar.opentimestamps.org"];
        assert!(calendar_upgrade_path(
            "https://alice.btc.calendar.opentimestamps.org",
            &[1],
            &exact
        )
        .is_ok());
    }

    #[test]
    fn a_fresh_submission_is_pending_nowhere_until_a_calendar_answers() {
        let mut d = DetachedTimestamp::new([7; 32]);
        let c = d.prepare_submission([9; 16]);
        let mut expect = [7_u8; 32].to_vec();
        expect.extend_from_slice(&[9; 16]);
        assert_eq!(c.to_vec(), Sha256::digest(&expect).to_vec());
        assert_eq!(d.status(), Status::Pending { calendars: vec![] });

        // A calendar's answer: prepend, sha256, pending attestation.
        let mut body = vec![TAG_PREPEND];
        write_varbytes(&mut body, b"abcd");
        body.push(TAG_SHA256);
        body.push(TAG_ATTESTATION);
        write_attestation(
            &mut body,
            &Attestation::Pending {
                uri: "https://alice.calendar.opentimestamps.org".into(),
            },
        );
        d.merge_calendar_response(&c, &body).unwrap();
        assert_eq!(
            d.status(),
            Status::Pending {
                calendars: vec!["https://alice.calendar.opentimestamps.org".into()]
            }
        );
        let again = DetachedTimestamp::parse(&d.serialize()).unwrap();
        assert_eq!(again, d);
        assert!(d.merge_calendar_response(&[0; 32], &body).is_err());
    }

    /// Every operation the format has, in one proof: each is read, applied
    /// where this module evaluates it, carried where it does not, and written
    /// back byte for byte; branches that share an operation are merged.
    #[test]
    fn every_operation_round_trips_and_shared_branches_merge() {
        let att = |out: &mut Vec<u8>, height: u8| {
            out.push(TAG_ATTESTATION);
            write_attestation(
                out,
                &Attestation::Bitcoin {
                    height: height.into(),
                },
            );
        };
        let mut body = Vec::new();
        for (tag, arg) in [
            (TAG_SHA1, None),
            (TAG_RIPEMD160, None),
            (TAG_KECCAK256, None),
            (TAG_REVERSE, None),
            (TAG_HEXLIFY, None),
            (TAG_PREPEND, Some(b"pre".as_slice())),
        ] {
            body.push(TAG_FORK);
            body.push(tag);
            if let Some(a) = arg {
                write_varbytes(&mut body, a);
            }
            att(&mut body, tag);
        }
        body.push(TAG_SHA256);
        att(&mut body, 1);
        let msg = b"message".to_vec();
        let t = Timestamp::deserialize(&body, &msg).unwrap();
        assert_eq!(t.msg(), msg.as_slice());
        let again = Timestamp::deserialize(&t.serialize(), &msg).unwrap();
        assert_eq!(again, t);
        let messages: Vec<Vec<u8>> = t.attestations().into_iter().map(|(m, _)| m).collect();
        assert!(messages.contains(&b"egassem".to_vec()));
        assert!(messages.contains(&b"6d657373616765".to_vec()));
        assert!(messages.contains(&b"premessage".to_vec()));
        assert!(messages.contains(&Ripemd160::digest(&msg).to_vec()));
        // SHA-1 and Keccak branches are carried, but their messages unknown.
        assert_eq!(messages.len(), 5);

        // Two answers that share their first operation become one branch.
        let mut merged = Timestamp::new(msg.clone());
        for height in [7, 8] {
            let mut b = vec![TAG_SHA256];
            att(&mut b, height);
            merged.merge(Timestamp::deserialize(&b, &msg).unwrap());
        }
        assert_eq!(merged.ops.len(), 1);
        assert_eq!(merged.attestations().len(), 2);
        assert!(Op::Append(vec![0; MAX_MSG]).apply(&msg).is_none());
    }

    #[test]
    fn malformed_parts_are_refused_with_a_reason() {
        let msg = [0_u8; 32];
        let too_long_varuint = [0xff_u8; 11];
        let mut r = Reader {
            bytes: &too_long_varuint,
            at: 0,
        };
        assert!(r.varuint().is_err());
        for bad in [
            vec![TAG_APPEND, 0],
            vec![0x42],
            vec![TAG_SHA256, TAG_ATTESTATION],
        ] {
            assert!(Timestamp::deserialize(&bad, &msg).is_err(), "{bad:?}");
        }
        let pending = |uri: &[u8]| {
            let mut payload = Vec::new();
            write_varbytes(&mut payload, uri);
            let mut b = vec![TAG_ATTESTATION];
            b.extend_from_slice(&PENDING);
            write_varbytes(&mut b, &payload);
            b
        };
        assert!(Timestamp::deserialize(&pending(b"https://ok.example"), &msg).is_ok());
        assert!(Timestamp::deserialize(&pending(b"https://bad example"), &msg).is_err());
        assert!(Timestamp::deserialize(&pending(b"\xff\xfe"), &msg).is_err());
        let mut trailing = vec![TAG_ATTESTATION];
        trailing.extend_from_slice(&BITCOIN);
        write_varbytes(&mut trailing, &[5, 0]);
        assert!(Timestamp::deserialize(&trailing, &msg).is_err());
        let mut extra = pending(b"https://ok.example");
        extra.push(0);
        assert!(Timestamp::deserialize(&extra, &msg).is_err());

        let huge = vec![0_u8; MAX_PROOF_BYTES + 1];
        assert!(Timestamp::deserialize(&huge, &msg).is_err());
        assert!(DetachedTimestamp::parse(&huge).is_err());

        // `pending` lists calendars only, not blocks.
        let mut d = DetachedTimestamp::new([1; 32]);
        let c = d.prepare_submission([2; 16]);
        let mut b = pending(b"https://ok.example");
        b[0] = TAG_FORK;
        b.insert(1, TAG_ATTESTATION);
        b.push(TAG_ATTESTATION);
        write_attestation(&mut b, &Attestation::Bitcoin { height: 9 });
        d.merge_calendar_response(&c, &b).unwrap();
        assert_eq!(d.pending().len(), 1);
    }

    #[test]
    fn malformed_proofs_are_refused_not_panicked_on() {
        let good = {
            let mut d = DetachedTimestamp::new([1; 32]);
            let c = d.prepare_submission([2; 16]);
            let mut body = vec![TAG_ATTESTATION];
            write_attestation(&mut body, &Attestation::Bitcoin { height: 5 });
            d.merge_calendar_response(&c, &body).unwrap();
            d.serialize()
        };
        assert!(DetachedTimestamp::parse(&good).is_ok());
        for cut in 0..good.len() {
            assert!(
                DetachedTimestamp::parse(&good[..cut]).is_err(),
                "cut at {cut}"
            );
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(DetachedTimestamp::parse(&trailing).is_err());
        // Nesting past the depth limit.
        let mut deep = MAGIC.to_vec();
        deep.extend_from_slice(&[1, TAG_SHA256]);
        deep.extend_from_slice(&[0; 32]);
        deep.extend(std::iter::repeat_n(TAG_SHA256, 300));
        assert!(DetachedTimestamp::parse(&deep).is_err());
    }
}
