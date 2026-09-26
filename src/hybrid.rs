//! Ed25519 + ML-DSA-65 hybrid signatures over an artifact digest.
//!
//! Decision records are kept for years, and a signature made today has to stay
//! convincing for as long as the record does. Ed25519 would not survive a
//! large quantum computer; ML-DSA (FIPS 204) is designed to. Neither is asked
//! to stand alone here: a hybrid signature is valid only when **both** halves
//! verify, so it is at least as strong as the stronger of the two — a flaw in
//! the new lattice scheme does not weaken what Ed25519 already gives, and a
//! quantum break of Ed25519 does not forge the lattice half.
//!
//! What is signed is always 32 bytes: a policy digest, a tree head digest, a
//! receipt's claims digest. Both halves sign `"calyhyb1" ‖ digest`, and ML-DSA
//! additionally binds the context string `calybris`, so a signature cannot be
//! lifted onto another protocol that happens to sign the same bytes.
//!
//! Signing is deterministic: the same keys and digest give the same signature,
//! which keeps a signed artifact reproducible byte for byte. Keys come from
//! 32-byte seeds the caller generates and stores; this module never reads a
//! random number generator.
//!
//! Batches: an ML-DSA-65 signature is 3,309 bytes and costs far more to make
//! than an Ed25519 one, so signing every decision on its own does not scale.
//! [`HybridSigner::sign_batch`] puts the digests of a batch in an RFC 9162
//! Merkle tree and signs the tree's head once, under its own tag `calyhbt1`;
//! each item gets an inclusion proof of `log₂ n` hashes. An item verifies only
//! when its proof leads to the signed root *and* both halves of the one
//! signature verify, so a forger has to break the hybrid signature or find a
//! SHA-256 collision, as for an item signed alone.
//!
//! **The ML-DSA implementation used here (RustCrypto `ml-dsa`) has not been
//! independently audited.** That is why this sits behind its own feature,
//! `preview-pq`, rather than inside `preview`.
//!
//! Post-quantum security models for long-lived audit evidence: Kao,
//! arXiv:2512.00110.

use ed25519_dalek::Signer as _;
use sha2::{Digest, Sha256};

use crate::merkle::{all_inclusion_proofs, leaf_hash, root_of, verify_inclusion, Hash, TreeHead};
use ml_dsa::signature::Keypair as _;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature as PqSignature, VerifyingKey,
};

/// Domain tag for both halves of the message.
pub const HYBRID_TAG: &[u8; 8] = b"calyhyb1";

/// FIPS 204 context string bound into the ML-DSA half.
pub const ML_DSA_CONTEXT: &[u8] = b"calybris";

/// Domain tag for the head of a signed batch.
pub const BATCH_TAG: &[u8; 8] = b"calyhbt1";

/// Why a hybrid signature did not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HybridError {
    #[error("Ed25519 half is malformed")]
    MalformedEd25519,
    #[error("ML-DSA-65 half is malformed")]
    MalformedMlDsa,
    #[error("Ed25519 half does not verify")]
    Ed25519Invalid,
    #[error("ML-DSA-65 half does not verify")]
    MlDsaInvalid,
    #[error("ML-DSA signing failed")]
    SigningFailed,
    #[error("a batch needs at least one digest")]
    EmptyBatch,
    #[error("the item's proof does not lead to the signed batch root")]
    NotInBatch,
}

/// The two public keys a verifier has to trust, together.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridPublicKey {
    pub ed25519: [u8; 32],
    /// FIPS 204 encoded ML-DSA-65 verifying key, 1,952 bytes.
    pub ml_dsa_65: Vec<u8>,
}

/// Both signatures over the same tagged digest.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HybridSignature {
    /// 64 bytes.
    pub ed25519: Vec<u8>,
    /// FIPS 204 encoded ML-DSA-65 signature, 3,309 bytes.
    pub ml_dsa_65: Vec<u8>,
}

/// A signer holding both private keys.
pub struct HybridSigner {
    ed25519: ed25519_dalek::SigningKey,
    ml_dsa: ml_dsa::SigningKey<MlDsa65>,
}

impl std::fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigner").finish_non_exhaustive()
    }
}

fn message(digest: &[u8; 32]) -> [u8; 40] {
    let mut m = [0_u8; 40];
    m[..8].copy_from_slice(HYBRID_TAG);
    m[8..].copy_from_slice(digest);
    m
}

impl HybridSigner {
    /// Both keys from caller-held 32-byte seeds. Use two independent seeds.
    #[must_use]
    pub fn from_seeds(ed25519_seed: &[u8; 32], ml_dsa_seed: &[u8; 32]) -> Self {
        Self {
            ed25519: ed25519_dalek::SigningKey::from_bytes(ed25519_seed),
            ml_dsa: ml_dsa::SigningKey::<MlDsa65>::from_seed(&(*ml_dsa_seed).into()),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519.verifying_key().to_bytes(),
            ml_dsa_65: self.ml_dsa.verifying_key().encode().as_slice().to_vec(),
        }
    }

    /// Signs `"calyhyb1" ‖ digest` with both keys.
    pub fn sign(&self, digest: &[u8; 32]) -> Result<HybridSignature, HybridError> {
        let m = message(digest);
        let ed = self.ed25519.sign(&m).to_bytes().to_vec();
        let pq = self
            .ml_dsa
            .expanded_key()
            .sign_deterministic(&m, ML_DSA_CONTEXT)
            .map_err(|_| HybridError::SigningFailed)?;
        Ok(HybridSignature {
            ed25519: ed,
            ml_dsa_65: pq.encode().as_slice().to_vec(),
        })
    }
}

/// One hybrid signature over a whole batch of digests.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchSignature {
    /// How many digests the batch holds.
    pub size: u64,
    /// RFC 9162 root of the tree whose leaves are the digests.
    pub root: Hash,
    /// Hybrid signature over [`batch_digest`] of `size` and `root`.
    pub signature: HybridSignature,
}

/// Where one digest sits in a signed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchItem {
    pub index: u64,
    /// Inclusion proof from the item to the batch root, leaf upwards.
    pub proof: Vec<Hash>,
}

/// `SHA-256("calyhbt1" ‖ size as u64 big-endian ‖ root)`: what a batch's
/// hybrid signature signs.
#[must_use]
pub fn batch_digest(size: u64, root: &Hash) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BATCH_TAG);
    h.update(size.to_be_bytes());
    h.update(root);
    h.finalize().into()
}

impl HybridSigner {
    /// Signs every digest in `digests` with a single hybrid signature, and
    /// returns it with one [`BatchItem`] per digest, in order.
    pub fn sign_batch(
        &self,
        digests: &[[u8; 32]],
    ) -> Result<(BatchSignature, Vec<BatchItem>), HybridError> {
        if digests.is_empty() {
            return Err(HybridError::EmptyBatch);
        }
        let leaves: Vec<Hash> = digests.iter().map(|d| leaf_hash(d)).collect();
        let size = leaves.len() as u64;
        let root = root_of(&leaves);
        let signature = self.sign(&batch_digest(size, &root))?;
        let items = all_inclusion_proofs(&leaves)
            .into_iter()
            .enumerate()
            .map(|(i, proof)| BatchItem {
                index: i as u64,
                proof,
            })
            .collect();
        Ok((
            BatchSignature {
                size,
                root,
                signature,
            },
            items,
        ))
    }
}

/// A batch whose hybrid signature has been checked once; its items can then
/// be checked with a few hashes each.
#[derive(Debug)]
pub struct VerifiedBatch<'a> {
    batch: &'a BatchSignature,
}

impl VerifiedBatch<'_> {
    /// Checks that `digest` is item `item.index` of this batch.
    pub fn verify_item(&self, digest: &[u8; 32], item: &BatchItem) -> Result<(), HybridError> {
        let head = TreeHead {
            size: self.batch.size,
            root: self.batch.root,
        };
        verify_inclusion(&head, item.index, &leaf_hash(digest), &item.proof)
            .map_err(|_| HybridError::NotInBatch)
    }
}

/// Checks a batch's hybrid signature, both halves.
pub fn verify_batch<'a>(
    public: &HybridPublicKey,
    batch: &'a BatchSignature,
) -> Result<VerifiedBatch<'a>, HybridError> {
    if batch.size == 0 {
        return Err(HybridError::EmptyBatch);
    }
    verify(
        public,
        &batch_digest(batch.size, &batch.root),
        &batch.signature,
    )?;
    Ok(VerifiedBatch { batch })
}

/// Checks one item of a batch: the batch signature and the item's proof.
pub fn verify_batch_item(
    public: &HybridPublicKey,
    digest: &[u8; 32],
    item: &BatchItem,
    batch: &BatchSignature,
) -> Result<(), HybridError> {
    verify_batch(public, batch)?.verify_item(digest, item)
}

/// Valid only when both halves verify against `public` for `digest`.
pub fn verify(
    public: &HybridPublicKey,
    digest: &[u8; 32],
    sig: &HybridSignature,
) -> Result<(), HybridError> {
    let m = message(digest);

    let ed_key = ed25519_dalek::VerifyingKey::from_bytes(&public.ed25519)
        .map_err(|_| HybridError::MalformedEd25519)?;
    let ed_sig_bytes: [u8; 64] = sig
        .ed25519
        .as_slice()
        .try_into()
        .map_err(|_| HybridError::MalformedEd25519)?;
    let ed_sig = ed25519_dalek::Signature::from_bytes(&ed_sig_bytes);
    ed_key
        .verify_strict(&m, &ed_sig)
        .map_err(|_| HybridError::Ed25519Invalid)?;
    // `verify_strict`, not `verify`: it also refuses small-order keys and
    // non-canonical signatures.

    let vk_enc = EncodedVerifyingKey::<MlDsa65>::try_from(public.ml_dsa_65.as_slice())
        .map_err(|_| HybridError::MalformedMlDsa)?;
    let vk = VerifyingKey::<MlDsa65>::decode(&vk_enc);
    let sig_enc = EncodedSignature::<MlDsa65>::try_from(sig.ml_dsa_65.as_slice())
        .map_err(|_| HybridError::MalformedMlDsa)?;
    let pq_sig = PqSignature::<MlDsa65>::decode(&sig_enc).ok_or(HybridError::MalformedMlDsa)?;
    if vk.verify_with_context(&m, ML_DSA_CONTEXT, &pq_sig) {
        Ok(())
    } else {
        Err(HybridError::MlDsaInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> HybridSigner {
        HybridSigner::from_seeds(&[1; 32], &[2; 32])
    }

    #[test]
    fn a_hybrid_signature_verifies_and_is_deterministic() {
        let s = signer();
        let d = [9_u8; 32];
        let a = s.sign(&d).unwrap();
        let b = s.sign(&d).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.ed25519.len(), 64);
        assert_eq!(a.ml_dsa_65.len(), 3_309);
        assert_eq!(s.public_key().ml_dsa_65.len(), 1_952);
        verify(&s.public_key(), &d, &a).unwrap();
    }

    #[test]
    fn either_half_failing_fails_the_whole() {
        let s = signer();
        let d = [9_u8; 32];
        let good = s.sign(&d).unwrap();

        let mut bad = good.clone();
        bad.ed25519[0] ^= 1;
        assert_eq!(
            verify(&s.public_key(), &d, &bad),
            Err(HybridError::Ed25519Invalid)
        );

        let mut bad = good.clone();
        bad.ml_dsa_65[100] ^= 1;
        assert!(verify(&s.public_key(), &d, &bad).is_err());

        // A valid Ed25519 half next to another key's ML-DSA half.
        let other = HybridSigner::from_seeds(&[1; 32], &[3; 32])
            .sign(&d)
            .unwrap();
        let mixed = HybridSignature {
            ed25519: good.ed25519.clone(),
            ml_dsa_65: other.ml_dsa_65,
        };
        assert_eq!(
            verify(&s.public_key(), &d, &mixed),
            Err(HybridError::MlDsaInvalid)
        );
    }

    #[test]
    fn another_digest_or_key_does_not_verify() {
        let s = signer();
        let sig = s.sign(&[9; 32]).unwrap();
        assert!(verify(&s.public_key(), &[8; 32], &sig).is_err());
        let stranger = HybridSigner::from_seeds(&[5; 32], &[6; 32]).public_key();
        assert!(verify(&stranger, &[9; 32], &sig).is_err());
    }

    #[test]
    fn malformed_halves_are_refused_not_panicked_on() {
        let s = signer();
        let d = [9_u8; 32];
        let mut sig = s.sign(&d).unwrap();
        sig.ed25519.truncate(10);
        assert_eq!(
            verify(&s.public_key(), &d, &sig),
            Err(HybridError::MalformedEd25519)
        );
        let mut sig = s.sign(&d).unwrap();
        sig.ml_dsa_65.truncate(10);
        assert_eq!(
            verify(&s.public_key(), &d, &sig),
            Err(HybridError::MalformedMlDsa)
        );
        let mut pk = s.public_key();
        pk.ml_dsa_65.push(0);
        assert_eq!(
            verify(&pk, &d, &s.sign(&d).unwrap()),
            Err(HybridError::MalformedMlDsa)
        );
    }

    #[test]
    fn an_invalid_ed25519_public_key_is_malformed() {
        let s = signer();
        let d = [9_u8; 32];
        let sig = s.sign(&d).unwrap();
        let bad = (0_u8..=255)
            .map(|b| [b; 32])
            .find(|k| ed25519_dalek::VerifyingKey::from_bytes(k).is_err())
            .expect("some 32-byte string is not a curve point");
        let mut pk = s.public_key();
        pk.ed25519 = bad;
        assert_eq!(verify(&pk, &d, &sig), Err(HybridError::MalformedEd25519));
    }

    #[test]
    fn every_item_of_a_batch_verifies_under_one_signature() {
        let s = signer();
        let digests: Vec<[u8; 32]> = (0..37_u8).map(|i| [i; 32]).collect();
        let (batch, items) = s.sign_batch(&digests).unwrap();
        assert_eq!(batch.size, 37);
        assert_eq!(items.len(), 37);
        let verified = verify_batch(&s.public_key(), &batch).unwrap();
        for (d, item) in digests.iter().zip(&items) {
            verified.verify_item(d, item).unwrap();
        }
        verify_batch_item(&s.public_key(), &digests[5], &items[5], &batch).unwrap();
    }

    #[test]
    fn a_batch_refuses_outsiders_moved_items_and_forged_roots() {
        let s = signer();
        let digests: Vec<[u8; 32]> = (0..8_u8).map(|i| [i; 32]).collect();
        let (batch, items) = s.sign_batch(&digests).unwrap();
        let v = verify_batch(&s.public_key(), &batch).unwrap();
        assert_eq!(
            v.verify_item(&[99; 32], &items[0]),
            Err(HybridError::NotInBatch)
        );
        assert_eq!(
            v.verify_item(&digests[1], &items[0]),
            Err(HybridError::NotInBatch)
        );

        // A root the signer never signed.
        let mut forged = batch.clone();
        forged.root = leaf_hash(&[99; 32]);
        assert!(verify_batch(&s.public_key(), &forged).is_err());
        let mut resized = batch.clone();
        resized.size = 9;
        assert!(verify_batch(&s.public_key(), &resized).is_err());
        let mut empty = batch;
        empty.size = 0;
        assert_eq!(
            verify_batch(&s.public_key(), &empty).unwrap_err(),
            HybridError::EmptyBatch
        );
        assert_eq!(s.sign_batch(&[]).unwrap_err(), HybridError::EmptyBatch);
    }

    #[test]
    fn a_batch_signature_is_not_a_plain_signature_over_its_root() {
        let s = signer();
        let (batch, items) = s.sign_batch(&[[4; 32]]).unwrap();
        assert!(items[0].proof.is_empty());
        assert_eq!(batch.root, leaf_hash(&[4; 32]));
        assert!(verify(&s.public_key(), &batch.root, &batch.signature).is_err());
    }

    #[test]
    fn the_signer_debug_output_shows_no_key_material() {
        let shown = format!("{:?}", signer());
        assert_eq!(shown, "HybridSigner { .. }");
    }
}
