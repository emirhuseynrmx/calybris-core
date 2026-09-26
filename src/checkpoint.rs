//! Signed checkpoints in the formats independent witnesses already speak.
//!
//! A [`TreeHead`] says what a log contains. A checkpoint is the same size and
//! root written as text, signed by the log, and co-signed by witnesses the log
//! operator does not control. Three C2SP specifications define it, and this
//! module follows them byte for byte so that existing witnesses and verifiers
//! (the Go `sumdb/note` package, the transparency-dev witness network, Sigsum)
//! accept a Calybris checkpoint without knowing what Calybris is:
//!
//! - **tlog-checkpoint** (<https://c2sp.org/tlog-checkpoint>): the body is
//!   the origin line, the tree size in decimal, the root in standard base64,
//!   then optional extension lines, each ending in a newline.
//! - **signed-note** (<https://c2sp.org/signed-note>): the body, a blank line,
//!   then one line per signature: `— <name> <base64(key hash ‖ signature)>`.
//!   The key hash is the first four bytes of
//!   `SHA-256(name ‖ "\n" ‖ algorithm ‖ public key)`.
//! - **tlog-cosignature** (<https://c2sp.org/tlog-cosignature>): a witness
//!   signs `"cosignature/v1\ntime <unix seconds>\n" ‖ body` and publishes
//!   `timestamp ‖ signature`, so every cosignature says when the witness saw
//!   the checkpoint.
//!
//! The text is the canonical form. There is exactly one way to write a given
//! checkpoint: [`Checkpoint::parse`] refuses a size with a leading zero, a root
//! whose base64 is not the canonical encoding of 32 bytes, an empty line or a
//! control character, so the same tree head cannot hash two ways.
//!
//! Keys are Ed25519. A log key uses algorithm byte `0x01`, a witness key
//! `0x04`, and both are written in the `name+hash+base64` verifier-key format
//! the Go `note` package reads. Nothing here reads a clock or a random number
//! generator: signing is deterministic, and a witness's timestamp is passed in.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::merkle::{Hash, TreeHead};

/// Algorithm byte of a log's Ed25519 note-signing key.
pub const ALG_ED25519: u8 = 0x01;
/// Algorithm byte of a witness's Ed25519 `cosignature/v1` key.
pub const ALG_COSIGNATURE_V1: u8 = 0x04;
/// Largest note [`SignedNote::parse`] reads. A checkpoint with a hundred
/// cosignatures is under 20 KiB.
pub const MAX_NOTE_BYTES: usize = 64 * 1024;
/// Most signature lines a note may carry, as in the Go `note` package.
pub const MAX_SIGNATURES: usize = 100;

const SIGNATURE_PREFIX: &str = "\u{2014} ";
const COSIGNATURE_HEADER: &str = "cosignature/v1\ntime ";

/// Why a checkpoint, note or key was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CheckpointError {
    #[error("key name is empty or contains a space, a plus sign or a control character")]
    BadName,
    #[error("key is malformed: {0}")]
    BadKey(&'static str),
    #[error("key algorithm {0:#04x} is not the one this operation needs")]
    WrongAlgorithm(u8),
    #[error("note is larger than {MAX_NOTE_BYTES} bytes")]
    NoteTooLarge,
    #[error("note is malformed: {0}")]
    MalformedNote(&'static str),
    #[error("checkpoint is malformed: {0}")]
    MalformedCheckpoint(&'static str),
    #[error("note carries more than {MAX_SIGNATURES} signatures")]
    TooManySignatures,
    #[error("note carries two signatures from the same key")]
    DuplicateSignature,
    #[error("note carries no signature from {0}")]
    NotSigned(String),
    #[error("signature from {0} does not verify")]
    BadSignature(String),
}

/// A log's state as C2SP tlog-checkpoint text: origin, size, root, extensions.
///
/// Fields are private so that every value is one [`Checkpoint::body`] can
/// write and [`Checkpoint::parse`] reads back unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    origin: String,
    size: u64,
    root: Hash,
    extensions: Vec<String>,
}

fn is_valid_line(line: &str) -> bool {
    !line.is_empty() && !line.chars().any(char::is_control)
}

impl Checkpoint {
    /// A checkpoint of `head` for the log named `origin`.
    ///
    /// The origin identifies the log to witnesses and must be unique to it;
    /// C2SP recommends a schema-less URL such as `decisions.example.com/log`.
    pub fn new(origin: &str, head: TreeHead) -> Result<Self, CheckpointError> {
        if !is_valid_line(origin) {
            return Err(CheckpointError::MalformedCheckpoint(
                "origin must be one non-empty line without control characters",
            ));
        }
        Ok(Self {
            origin: origin.to_owned(),
            size: head.size,
            root: head.root,
            extensions: Vec::new(),
        })
    }

    /// Adds an extension line after the root. Witnesses cosign extension
    /// lines but make no statement about them.
    pub fn with_extension(mut self, line: &str) -> Result<Self, CheckpointError> {
        if !is_valid_line(line) {
            return Err(CheckpointError::MalformedCheckpoint(
                "extension must be one non-empty line without control characters",
            ));
        }
        self.extensions.push(line.to_owned());
        Ok(self)
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn root(&self) -> &Hash {
        &self.root
    }

    #[must_use]
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }

    #[must_use]
    pub fn head(&self) -> TreeHead {
        TreeHead {
            size: self.size,
            root: self.root,
        }
    }

    /// The canonical body text, ending in a newline.
    #[must_use]
    pub fn body(&self) -> String {
        let mut out = format!(
            "{}\n{}\n{}\n",
            self.origin,
            self.size,
            BASE64.encode(self.root)
        );
        for line in &self.extensions {
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    /// `SHA-256(body)`. A timestamp over this dates the checkpoint's
    /// *content* only; to date the log's signature as well, stamp
    /// [`SignedNote::signed_by`] instead.
    #[must_use]
    pub fn digest(&self) -> Hash {
        Sha256::digest(self.body().as_bytes()).into()
    }

    /// Reads a body, accepting only its canonical form.
    pub fn parse(body: &str) -> Result<Self, CheckpointError> {
        let err = CheckpointError::MalformedCheckpoint;
        let text = body
            .strip_suffix('\n')
            .ok_or(err("body must end in a newline"))?;
        // Not `lines()`: it would also strip a trailing `\r`, so a CRLF copy
        // would parse as the same value. The format is LF only.
        // skipcq: RS-W1217
        let mut lines = text.split('\n');
        let origin = lines.next().ok_or(err("missing origin"))?;
        let size = lines.next().ok_or(err("missing tree size"))?;
        let root = lines.next().ok_or(err("missing root hash"))?;
        let extensions: Vec<&str> = lines.collect();

        if !is_valid_line(origin) {
            return Err(err("origin must be non-empty, without control characters"));
        }
        let size_ok = !size.is_empty()
            && size.bytes().all(|b| b.is_ascii_digit())
            && (size == "0" || !size.starts_with('0'));
        if !size_ok {
            return Err(err("tree size must be decimal without leading zeros"));
        }
        let size: u64 = size.parse().map_err(|_| err("tree size exceeds u64"))?;
        let decoded = BASE64
            .decode(root)
            .map_err(|_| err("root hash is not standard base64"))?;
        let root_bytes: Hash = decoded
            .as_slice()
            .try_into()
            .map_err(|_| err("root hash is not 32 bytes"))?;
        if BASE64.encode(root_bytes) != root {
            return Err(err("root hash is not canonically encoded"));
        }
        if !extensions.iter().all(|l| is_valid_line(l)) {
            return Err(err(
                "extension lines must be non-empty, without control characters",
            ));
        }
        Ok(Self {
            origin: origin.to_owned(),
            size,
            root: root_bytes,
            extensions: extensions.into_iter().map(str::to_owned).collect(),
        })
    }
}

/// One signature line of a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteSignature {
    pub name: String,
    pub key_hash: u32,
    /// The signature bytes after the key hash. For a `cosignature/v1` line
    /// that is the 8-byte big-endian timestamp followed by the signature.
    pub signature: Vec<u8>,
}

impl NoteSignature {
    /// The line as it appears in a note, ending in a newline.
    #[must_use]
    pub fn line(&self) -> String {
        let mut raw = Vec::with_capacity(4 + self.signature.len());
        raw.extend_from_slice(&self.key_hash.to_be_bytes());
        raw.extend_from_slice(&self.signature);
        format!("{SIGNATURE_PREFIX}{} {}\n", self.name, BASE64.encode(raw))
    }

    /// Reads one line, without its trailing newline.
    pub fn parse_line(line: &str) -> Result<Self, CheckpointError> {
        let err = CheckpointError::MalformedNote;
        let rest = line
            .strip_prefix(SIGNATURE_PREFIX)
            .ok_or(err("signature line must start with an em dash and a space"))?;
        let (name, encoded) = rest
            .split_once(' ')
            .ok_or(err("signature line must be `— name signature`"))?;
        if !is_valid_name(name) {
            return Err(CheckpointError::BadName);
        }
        let raw = BASE64
            .decode(encoded)
            .map_err(|_| err("signature is not standard base64"))?;
        if raw.len() < 5 {
            return Err(err("signature is shorter than a key hash and one byte"));
        }
        Ok(Self {
            name: name.to_owned(),
            key_hash: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
            signature: raw[4..].to_vec(),
        })
    }
}

/// A C2SP signed note: text plus signature lines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedNote {
    text: String,
    signatures: Vec<NoteSignature>,
}

impl SignedNote {
    /// Reads a note. Signatures are parsed, not verified: verify the ones
    /// from keys you trust with [`SignedNote::verify`] and
    /// [`SignedNote::cosignature_time`], and ignore the rest.
    pub fn parse(note: &str) -> Result<Self, CheckpointError> {
        let err = CheckpointError::MalformedNote;
        if note.len() > MAX_NOTE_BYTES {
            return Err(CheckpointError::NoteTooLarge);
        }
        if note.chars().any(|c| c.is_control() && c != '\n') {
            return Err(err("note contains a control character other than newline"));
        }
        let split = note
            .rfind("\n\n")
            .ok_or(err("note has no blank line before its signatures"))?;
        let text = &note[..=split];
        if text.ends_with(
            "

",
        ) {
            return Err(err("note text ends in a blank line"));
        }
        let block = &note[split + 2..];
        let block = block
            .strip_suffix('\n')
            .ok_or(err("note must end in a newline"))?;
        if block.is_empty() {
            return Err(err("note has no signatures"));
        }
        let mut signatures = Vec::new();
        // Not `lines()`: it would also strip a trailing `\r`, so a CRLF copy
        // would parse as the same value. The format is LF only.
        // skipcq: RS-W1217
        for line in block.split('\n') {
            if signatures.len() == MAX_SIGNATURES {
                return Err(CheckpointError::TooManySignatures);
            }
            let sig = NoteSignature::parse_line(line)?;
            if signatures
                .iter()
                .any(|s: &NoteSignature| s.name == sig.name && s.key_hash == sig.key_hash)
            {
                return Err(CheckpointError::DuplicateSignature);
            }
            signatures.push(sig);
        }
        Ok(Self {
            text: text.to_owned(),
            signatures,
        })
    }

    /// The signed text, ending in a newline.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn signatures(&self) -> &[NoteSignature] {
        &self.signatures
    }

    /// The checkpoint the text encodes.
    pub fn checkpoint(&self) -> Result<Checkpoint, CheckpointError> {
        Checkpoint::parse(&self.text)
    }

    /// Adds a signature line. A second line from the same key is refused
    /// rather than replacing the first.
    pub fn add_signature(&mut self, sig: NoteSignature) -> Result<(), CheckpointError> {
        if self
            .signatures
            .iter()
            .any(|s| s.name == sig.name && s.key_hash == sig.key_hash)
        {
            return Err(CheckpointError::DuplicateSignature);
        }
        if self.signatures.len() == MAX_SIGNATURES {
            return Err(CheckpointError::TooManySignatures);
        }
        self.signatures.push(sig);
        Ok(())
    }

    /// The note as text: body, blank line, signature lines.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = self.text.clone();
        out.push('\n');
        for sig in &self.signatures {
            out.push_str(&sig.line());
        }
        out
    }

    /// The note with `key`'s signature only, as text, after checking that
    /// signature: the bytes to timestamp.
    ///
    /// A timestamp over the body alone proves the body existed, not that the
    /// log had signed it. Someone who later steals the log key can sign an
    /// old, already-timestamped body, so body evidence cannot show that a
    /// signature predates a key's revocation. A timestamp over these bytes
    /// covers the signature too.
    pub fn signed_by(&self, key: &NoteVerifier) -> Result<String, CheckpointError> {
        self.verify(key)?;
        let sig = self.signature_from(key)?;
        Ok(format!("{}\n{}", self.text, sig.line()))
    }

    fn signature_from(&self, key: &NoteVerifier) -> Result<&NoteSignature, CheckpointError> {
        self.signatures
            .iter()
            .find(|s| s.name == key.name && s.key_hash == key.key_hash)
            .ok_or_else(|| CheckpointError::NotSigned(key.name.clone()))
    }

    /// Checks the note signature of an Ed25519 note key (a log's key).
    pub fn verify(&self, key: &NoteVerifier) -> Result<(), CheckpointError> {
        if key.algorithm != ALG_ED25519 {
            return Err(CheckpointError::WrongAlgorithm(key.algorithm));
        }
        let sig = self.signature_from(key)?;
        let bytes: [u8; 64] = sig
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CheckpointError::BadSignature(key.name.clone()))?;
        key.key
            .verify_strict(self.text.as_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| CheckpointError::BadSignature(key.name.clone()))
    }

    /// Checks a witness's `cosignature/v1` and returns the time, in Unix
    /// seconds, at which the witness says it signed.
    pub fn cosignature_time(&self, key: &NoteVerifier) -> Result<u64, CheckpointError> {
        if key.algorithm != ALG_COSIGNATURE_V1 {
            return Err(CheckpointError::WrongAlgorithm(key.algorithm));
        }
        let sig = self.signature_from(key)?;
        let bad = || CheckpointError::BadSignature(key.name.clone());
        if sig.signature.len() != 72 {
            return Err(bad());
        }
        let mut time = [0_u8; 8];
        time.copy_from_slice(&sig.signature[..8]);
        let timestamp = u64::from_be_bytes(time);
        let bytes: [u8; 64] = sig.signature[8..].try_into().map_err(|_| bad())?;
        let message = cosignature_message(timestamp, &self.text)?;
        key.key
            .verify_strict(message.as_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| bad())?;
        Ok(timestamp)
    }
}

fn cosignature_message(timestamp: u64, text: &str) -> Result<String, CheckpointError> {
    // Not `lines()`: it would also strip a trailing `\r`, so a CRLF copy
    // would parse as the same value. The format is LF only.
    // skipcq: RS-W1217
    if text.split('\n').count() < 4 {
        return Err(CheckpointError::MalformedNote(
            "a cosigned note has at least three lines",
        ));
    }
    Ok(format!("{COSIGNATURE_HEADER}{timestamp}\n{text}"))
}

/// A key name as signed-note allows it: non-empty, no space, no plus sign,
/// no control character.
#[must_use]
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c == '+' || c.is_whitespace() || c.is_control())
}

fn key_hash(name: &str, algorithm: u8, public: &[u8; 32]) -> u32 {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([algorithm]);
    h.update(public);
    let d = h.finalize();
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// A public key a note is verified against, in the Go `note` verifier-key
/// format `name+hhhhhhhh+base64(algorithm ‖ public key)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteVerifier {
    name: String,
    algorithm: u8,
    key_hash: u32,
    key: VerifyingKey,
}

impl NoteVerifier {
    fn new(name: &str, algorithm: u8, key: VerifyingKey) -> Result<Self, CheckpointError> {
        if !is_valid_name(name) {
            return Err(CheckpointError::BadName);
        }
        Ok(Self {
            name: name.to_owned(),
            algorithm,
            key_hash: key_hash(name, algorithm, key.as_bytes()),
            key,
        })
    }

    /// Reads a verifier key. The key hash in it must match the key.
    pub fn parse(vkey: &str) -> Result<Self, CheckpointError> {
        let mut parts = vkey.splitn(3, '+');
        let (Some(name), Some(hash), Some(encoded)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(CheckpointError::BadKey("expected name+hash+key"));
        };
        if hash.len() != 8 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CheckpointError::BadKey("key hash must be 8 hex digits"));
        }
        let raw = BASE64
            .decode(encoded)
            .map_err(|_| CheckpointError::BadKey("key is not standard base64"))?;
        let (&algorithm, public) = raw
            .split_first()
            .ok_or(CheckpointError::BadKey("key is empty"))?;
        if algorithm != ALG_ED25519 && algorithm != ALG_COSIGNATURE_V1 {
            return Err(CheckpointError::WrongAlgorithm(algorithm));
        }
        let public: [u8; 32] = public
            .try_into()
            .map_err(|_| CheckpointError::BadKey("Ed25519 public key must be 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&public)
            .map_err(|_| CheckpointError::BadKey("not an Ed25519 public key"))?;
        let parsed = Self::new(name, algorithm, key)?;
        let stated = u32::from_str_radix(hash, 16)
            .map_err(|_| CheckpointError::BadKey("key hash must be 8 hex digits"))?;
        if stated != parsed.key_hash {
            return Err(CheckpointError::BadKey("key hash does not match the key"));
        }
        Ok(parsed)
    }

    /// The verifier key as text.
    #[must_use]
    pub fn to_vkey(&self) -> String {
        let mut raw = Vec::with_capacity(33);
        raw.push(self.algorithm);
        raw.extend_from_slice(self.key.as_bytes());
        format!("{}+{:08x}+{}", self.name, self.key_hash, BASE64.encode(raw))
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn key_hash(&self) -> u32 {
        self.key_hash
    }

    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// The raw Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

fn parse_skey(skey: &str, algorithms: &[u8]) -> Result<(String, [u8; 32]), CheckpointError> {
    let rest = skey
        .strip_prefix("PRIVATE+KEY+")
        .ok_or(CheckpointError::BadKey(
            "signer key must start with PRIVATE+KEY+",
        ))?;
    let mut parts = rest.splitn(3, '+');
    let (Some(name), Some(hash), Some(encoded)) = (parts.next(), parts.next(), parts.next()) else {
        return Err(CheckpointError::BadKey(
            "expected PRIVATE+KEY+name+hash+key",
        ));
    };
    if !is_valid_name(name) {
        return Err(CheckpointError::BadName);
    }
    if hash.len() != 8 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CheckpointError::BadKey("key hash must be 8 hex digits"));
    }
    let raw = BASE64
        .decode(encoded)
        .map_err(|_| CheckpointError::BadKey("key is not standard base64"))?;
    let (&algorithm, seed) = raw
        .split_first()
        .ok_or(CheckpointError::BadKey("key is empty"))?;
    if !algorithms.contains(&algorithm) {
        return Err(CheckpointError::WrongAlgorithm(algorithm));
    }
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| CheckpointError::BadKey("Ed25519 seed must be 32 bytes"))?;
    Ok((name.to_owned(), seed))
}

fn render_skey(name: &str, algorithm: u8, hash: u32, seed: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(33);
    raw.push(algorithm);
    raw.extend_from_slice(seed);
    format!("PRIVATE+KEY+{name}+{hash:08x}+{}", BASE64.encode(raw))
}

/// A log's checkpoint-signing key.
pub struct LogSigner {
    verifier: NoteVerifier,
    key: SigningKey,
}

impl std::fmt::Debug for LogSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogSigner")
            .field("name", &self.verifier.name)
            .finish_non_exhaustive()
    }
}

impl LogSigner {
    /// The key for `name` from a caller-held 32-byte seed.
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, CheckpointError> {
        let key = SigningKey::from_bytes(seed);
        Ok(Self {
            verifier: NoteVerifier::new(name, ALG_ED25519, key.verifying_key())?,
            key,
        })
    }

    /// Reads a Go `note` signer key (`PRIVATE+KEY+name+hash+base64(0x01 ‖ seed)`).
    pub fn from_skey(skey: &str) -> Result<Self, CheckpointError> {
        let (name, seed) = parse_skey(skey, &[ALG_ED25519])?;
        Self::from_seed(&name, &seed)
    }

    /// The signer key as text. It is the secret: store it like one.
    #[must_use]
    pub fn to_skey(&self) -> String {
        render_skey(
            &self.verifier.name,
            ALG_ED25519,
            self.verifier.key_hash,
            &self.key.to_bytes(),
        )
    }

    #[must_use]
    pub fn verifier(&self) -> &NoteVerifier {
        &self.verifier
    }

    /// Signs the checkpoint, giving a note with one signature: the log's.
    #[must_use]
    pub fn sign(&self, checkpoint: &Checkpoint) -> SignedNote {
        let text = checkpoint.body();
        let signature = self.key.sign(text.as_bytes()).to_bytes().to_vec();
        SignedNote {
            text,
            signatures: vec![NoteSignature {
                name: self.verifier.name.clone(),
                key_hash: self.verifier.key_hash,
                signature,
            }],
        }
    }
}

/// A witness's `cosignature/v1` key.
pub struct WitnessSigner {
    verifier: NoteVerifier,
    key: SigningKey,
}

impl std::fmt::Debug for WitnessSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessSigner")
            .field("name", &self.verifier.name)
            .finish_non_exhaustive()
    }
}

impl WitnessSigner {
    /// The key for `name` from a caller-held 32-byte seed.
    pub fn from_seed(name: &str, seed: &[u8; 32]) -> Result<Self, CheckpointError> {
        let key = SigningKey::from_bytes(seed);
        Ok(Self {
            verifier: NoteVerifier::new(name, ALG_COSIGNATURE_V1, key.verifying_key())?,
            key,
        })
    }

    /// Reads a signer key with algorithm `0x04`, or `0x01` as the Go
    /// cosigner also accepts; either way the key signs as `cosignature/v1`.
    pub fn from_skey(skey: &str) -> Result<Self, CheckpointError> {
        let (name, seed) = parse_skey(skey, &[ALG_COSIGNATURE_V1, ALG_ED25519])?;
        Self::from_seed(&name, &seed)
    }

    /// The signer key as text, with algorithm `0x04`. It is the secret.
    #[must_use]
    pub fn to_skey(&self) -> String {
        render_skey(
            &self.verifier.name,
            ALG_COSIGNATURE_V1,
            self.verifier.key_hash,
            &self.key.to_bytes(),
        )
    }

    #[must_use]
    pub fn verifier(&self) -> &NoteVerifier {
        &self.verifier
    }

    /// The cosignature line over `text` (a checkpoint body) at `timestamp`,
    /// in Unix seconds. This only signs; a witness decides first whether it
    /// should (see `witness`).
    pub fn cosign(&self, text: &str, timestamp: u64) -> Result<NoteSignature, CheckpointError> {
        let message = cosignature_message(timestamp, text)?;
        let mut signature = Vec::with_capacity(72);
        signature.extend_from_slice(&timestamp.to_be_bytes());
        signature.extend_from_slice(&self.key.sign(message.as_bytes()).to_bytes());
        Ok(NoteSignature {
            name: self.verifier.name.clone(),
            key_hash: self.verifier.key_hash,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(size: u64) -> Checkpoint {
        Checkpoint::new(
            "decisions.example/log",
            TreeHead {
                size,
                root: [7; 32],
            },
        )
        .unwrap()
    }

    #[test]
    fn a_body_is_the_c2sp_layout_and_parses_back() {
        let c = cp(1000).with_extension("prev abc").unwrap();
        let body = c.body();
        assert_eq!(
            body,
            format!(
                "decisions.example/log\n1000\n{}\nprev abc\n",
                BASE64.encode([7_u8; 32])
            )
        );
        assert_eq!(Checkpoint::parse(&body).unwrap(), c);
        assert_eq!(
            c.digest(),
            <[u8; 32]>::from(Sha256::digest(body.as_bytes()))
        );
    }

    #[test]
    fn only_the_canonical_body_parses() {
        let root = BASE64.encode([7_u8; 32]);
        let good = format!("o\n5\n{root}\n");
        assert!(Checkpoint::parse(&good).is_ok());
        for bad in [
            format!("o\n05\n{root}\n"),
            format!("o\n+5\n{root}\n"),
            format!("o\n5\n{root}"),
            format!("\n5\n{root}\n"),
            format!("o\n5\n{}\n", root.trim_end_matches('=')),
            format!("o\n5\n{root}\n\n"),
            format!("o\n5\n{root}\next\t\n"),
            format!("o\n18446744073709551616\n{root}\n"),
            format!("o\n5\n{}\n", BASE64.encode([7_u8; 31])),
            "o\n5\n".to_owned(),
            // A root whose last base64 character carries non-zero spare bits.
            format!("o\n5\n{}\n", {
                let mut r = root.clone();
                r.replace_range(42..43, "9");
                r
            }),
        ] {
            assert!(Checkpoint::parse(&bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_log_signature_verifies_and_breaks_on_any_change() {
        let log = LogSigner::from_seed("decisions.example/log", &[1; 32]).unwrap();
        let note = log.sign(&cp(9));
        let rendered = note.render();
        let parsed = SignedNote::parse(&rendered).unwrap();
        parsed.verify(log.verifier()).unwrap();
        assert_eq!(parsed.checkpoint().unwrap(), cp(9));

        let tampered = rendered.replacen("\n9\n", "\n8\n", 1);
        assert!(matches!(
            SignedNote::parse(&tampered).unwrap().verify(log.verifier()),
            Err(CheckpointError::BadSignature(_))
        ));
        let stranger = LogSigner::from_seed("decisions.example/log", &[2; 32]).unwrap();
        assert!(matches!(
            parsed.verify(stranger.verifier()),
            Err(CheckpointError::NotSigned(_))
        ));
    }

    #[test]
    fn a_cosignature_carries_its_time_and_binds_it() {
        let log = LogSigner::from_seed("log", &[1; 32]).unwrap();
        let witness = WitnessSigner::from_seed("witness.example", &[3; 32]).unwrap();
        let mut note = log.sign(&cp(4));
        note.add_signature(witness.cosign(note.text(), 1_790_000_000).unwrap())
            .unwrap();
        let parsed = SignedNote::parse(&note.render()).unwrap();
        assert_eq!(
            parsed.cosignature_time(witness.verifier()).unwrap(),
            1_790_000_000
        );
        parsed.verify(log.verifier()).unwrap();

        // Changing the timestamp breaks the signature it is bound into.
        let mut forged = parsed.clone();
        forged.signatures[1].signature[7] ^= 1;
        assert!(forged.cosignature_time(witness.verifier()).is_err());

        // A cosignature key cannot verify as a log key, nor the reverse.
        assert_eq!(
            parsed.verify(witness.verifier()),
            Err(CheckpointError::WrongAlgorithm(ALG_COSIGNATURE_V1))
        );
        assert_eq!(
            parsed.cosignature_time(log.verifier()),
            Err(CheckpointError::WrongAlgorithm(ALG_ED25519))
        );
    }

    #[test]
    fn keys_round_trip_and_a_wrong_hash_is_refused() {
        let log = LogSigner::from_seed("log.example", &[5; 32]).unwrap();
        let vkey = log.verifier().to_vkey();
        assert_eq!(NoteVerifier::parse(&vkey).unwrap(), *log.verifier());
        let again = LogSigner::from_skey(&log.to_skey()).unwrap();
        assert_eq!(again.verifier(), log.verifier());

        let (name, rest) = vkey.split_once('+').unwrap();
        let (_, key) = rest.split_once('+').unwrap();
        assert!(NoteVerifier::parse(&format!("{name}+00000000+{key}")).is_err());
        assert!(NoteVerifier::parse(&format!("other+{rest}")).is_err());
        assert!(LogSigner::from_seed("has space", &[5; 32]).is_err());
        assert!(LogSigner::from_seed("a+b", &[5; 32]).is_err());

        let w = WitnessSigner::from_seed("w", &[6; 32]).unwrap();
        assert_eq!(
            WitnessSigner::from_skey(&w.to_skey()).unwrap().verifier(),
            w.verifier()
        );
        assert!(LogSigner::from_skey(&w.to_skey()).is_err());
        assert_eq!(format!("{w:?}"), "WitnessSigner { name: \"w\", .. }");
    }

    #[test]
    fn malformed_notes_are_refused_not_panicked_on() {
        let log = LogSigner::from_seed("log", &[1; 32]).unwrap();
        let good = log.sign(&cp(3)).render();
        let dup = {
            let sig = log.sign(&cp(3)).signatures()[0].line();
            format!("{good}{sig}")
        };
        for bad in [
            String::default(),
            "no blank line\n".to_owned(),
            good.trim_end().to_owned(),
            good.replace('\u{2014}', "-"),
            format!("{}\n", good.trim_end()) + "\u{2014} x !!!\n",
            good.replace("\n\n", "\n\n\n"),
            "o\n1\nAA==\n\n\u{2014} n AAAA\n".to_owned(),
            good.replacen("log", "lo\rg", 1),
            dup,
        ] {
            assert!(SignedNote::parse(&bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            SignedNote::parse(&"a".repeat(MAX_NOTE_BYTES + 1)),
            Err(CheckpointError::NoteTooLarge)
        );
    }

    #[test]
    fn the_stamped_bytes_carry_the_log_signature_and_nothing_else() {
        let log = LogSigner::from_seed("log", &[1; 32]).unwrap();
        let w = WitnessSigner::from_seed("w", &[2; 32]).unwrap();
        let mut note = log.sign(&cp(3));
        let before = note.signed_by(log.verifier()).unwrap();
        note.add_signature(w.cosign(note.text(), 9).unwrap())
            .unwrap();
        // Cosignatures arriving later do not change what was stamped.
        assert_eq!(note.signed_by(log.verifier()).unwrap(), before);
        assert_eq!(before, log.sign(&cp(3)).render());
        assert_ne!(
            before,
            cp(3).body(),
            "the body alone would not date the signature"
        );
        // Only a verifying log signature can be stamped.
        let stranger = LogSigner::from_seed("log", &[5; 32]).unwrap();
        assert!(note.signed_by(stranger.verifier()).is_err());
        assert!(note.signed_by(w.verifier()).is_err());
    }

    #[test]
    fn a_second_signature_from_the_same_key_is_refused() {
        let log = LogSigner::from_seed("log", &[1; 32]).unwrap();
        let w = WitnessSigner::from_seed("w", &[2; 32]).unwrap();
        let mut note = log.sign(&cp(3));
        note.add_signature(w.cosign(note.text(), 1).unwrap())
            .unwrap();
        assert_eq!(
            note.add_signature(w.cosign(note.text(), 2).unwrap()),
            Err(CheckpointError::DuplicateSignature)
        );
    }
}
