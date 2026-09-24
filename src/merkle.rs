//! Merkle inclusion and consistency proofs over a decision log.
//!
//! The WAL is a hash chain. A chain proves that the records still present are
//! the ones that were written, but it has two gaps an auditor feels:
//!
//! - To check **one** decision, the auditor needs every record before it.
//! - To show that yesterday's log is a prefix of today's, the auditor needs
//!   yesterday's trusted head *and* every record since.
//!
//! A Merkle tree over the same records closes both with proofs of `log₂ n`
//! hashes. An inclusion proof shows one record is in a tree of a given size and
//! root; a consistency proof shows the tree of size `m` is a prefix of the tree
//! of size `n`, so a log that was rewritten after its head was published cannot
//! produce one. Bring in independent witnesses who co-sign each published head
//! and the operator no longer has to be trusted to keep a single history.
//!
//! The tree is exactly the one in RFC 9162 (Certificate Transparency 2.0), §2.1:
//! a leaf hashes as `SHA-256(0x00 ‖ data)`, an interior node as
//! `SHA-256(0x01 ‖ left ‖ right)`, and a tree of `n` leaves splits at the
//! largest power of two below `n`. Proofs are built and checked with the
//! algorithms of §2.1.3 and §2.1.4. Keeping to the standard means any RFC 9162
//! verifier can check these proofs without this crate.
//!
//! What a leaf is, is the caller's choice. [`leaf_from_entry_hash`] turns a WAL
//! `entry_hash` into leaf data, so the tree commits to the records the chain
//! already commits to. A signed [`TreeHead`] is bound under the digest tag
//! `calymth1`, which no earlier artifact uses.
//!
//! Witness co-signing of published heads: Syta et al., "Keeping Authorities
//! 'Honest or Bust' with Decentralized Witness Cosigning", arXiv:1503.08768.

use sha2::{Digest, Sha256};

/// A SHA-256 output.
pub type Hash = [u8; 32];

/// Domain tag for [`TreeHead::digest`].
pub const TREE_HEAD_TAG: &[u8; 8] = b"calymth1";

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

/// Why a proof could not be built or did not verify.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MerkleError {
    #[error("leaf index {index} is outside a tree of size {size}")]
    IndexOutOfRange { index: u64, size: u64 },
    #[error("tree size {old} is not a prefix size of a tree of size {new}")]
    BadSizes { old: u64, new: u64 },
    #[error("proof has the wrong length for this position")]
    BadProofLength,
    #[error("proof does not lead to the expected root")]
    RootMismatch,
    #[error("entry hash is not 64 lowercase hex characters")]
    BadEntryHash,
}

/// The size and root of a tree: what gets published, signed and witnessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TreeHead {
    pub size: u64,
    pub root: Hash,
}

impl TreeHead {
    /// The head of the tree over `leaves` (leaf data, not leaf hashes).
    #[must_use]
    pub fn of<L: AsRef<[u8]>>(leaves: &[L]) -> Self {
        let hashed: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l.as_ref())).collect();
        Self {
            size: hashed.len() as u64,
            root: root_of(&hashed),
        }
    }

    /// `SHA-256("calymth1" ‖ size as u64 big-endian ‖ root)`: the 32 bytes a
    /// signer or witness signs for this head.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(TREE_HEAD_TAG);
        h.update(self.size.to_be_bytes());
        h.update(self.root);
        h.finalize().into()
    }
}

/// `SHA-256(0x00 ‖ data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 ‖ left ‖ right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The 32 bytes a WAL `entry_hash` encodes, as leaf data.
pub fn leaf_from_entry_hash(entry_hash: &str) -> Result<Hash, MerkleError> {
    let bytes = entry_hash.as_bytes();
    if bytes.len() != 64 {
        return Err(MerkleError::BadEntryHash);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(MerkleError::BadEntryHash),
    };
    let mut out = [0_u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// The root of the tree over already-hashed leaves. The empty tree's root is
/// `SHA-256("")`, as RFC 9162 defines it.
#[must_use]
pub fn root_of(leaf_hashes: &[Hash]) -> Hash {
    match leaf_hashes.len() {
        0 => Sha256::digest([]).into(),
        1 => leaf_hashes[0],
        n => {
            let k = split(n as u64) as usize;
            node_hash(&root_of(&leaf_hashes[..k]), &root_of(&leaf_hashes[k..]))
        }
    }
}

/// The inclusion proof for leaf `index` in the tree over `leaf_hashes`
/// (RFC 9162 §2.1.3.1), ordered from the leaf upwards.
pub fn inclusion_proof(leaf_hashes: &[Hash], index: u64) -> Result<Vec<Hash>, MerkleError> {
    let size = leaf_hashes.len() as u64;
    if index >= size {
        return Err(MerkleError::IndexOutOfRange { index, size });
    }
    Ok(path(index as usize, leaf_hashes))
}

fn path(m: usize, d: &[Hash]) -> Vec<Hash> {
    if d.len() <= 1 {
        return Vec::new();
    }
    let k = split(d.len() as u64) as usize;
    if m < k {
        let mut p = path(m, &d[..k]);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = path(m - k, &d[k..]);
        p.push(root_of(&d[..k]));
        p
    }
}

/// Checks that `leaf_hash` is leaf `index` of the tree `head` (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    head: &TreeHead,
    index: u64,
    leaf_hash: &Hash,
    proof: &[Hash],
) -> Result<(), MerkleError> {
    if index >= head.size {
        return Err(MerkleError::IndexOutOfRange {
            index,
            size: head.size,
        });
    }
    let (mut f_n, mut s_n) = (index, head.size - 1);
    let mut r = *leaf_hash;
    for p in proof {
        if s_n == 0 {
            return Err(MerkleError::BadProofLength);
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n != 0 {
        return Err(MerkleError::BadProofLength);
    }
    if r == head.root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// The consistency proof between the tree of the first `old_size` leaves and
/// the tree over all of `leaf_hashes` (RFC 9162 §2.1.4.1).
pub fn consistency_proof(leaf_hashes: &[Hash], old_size: u64) -> Result<Vec<Hash>, MerkleError> {
    let new_size = leaf_hashes.len() as u64;
    if old_size == 0 || old_size > new_size {
        return Err(MerkleError::BadSizes {
            old: old_size,
            new: new_size,
        });
    }
    Ok(subproof(old_size as usize, leaf_hashes, true))
}

fn subproof(m: usize, d: &[Hash], b: bool) -> Vec<Hash> {
    let n = d.len();
    if m == n {
        return if b { Vec::new() } else { vec![root_of(d)] };
    }
    let k = split(n as u64) as usize;
    if m <= k {
        let mut p = subproof(m, &d[..k], b);
        p.push(root_of(&d[k..]));
        p
    } else {
        let mut p = subproof(m - k, &d[k..], false);
        p.push(root_of(&d[..k]));
        p
    }
}

/// Checks that `old` is a prefix of `new` (RFC 9162 §2.1.4.2).
pub fn verify_consistency(
    old: &TreeHead,
    new: &TreeHead,
    proof: &[Hash],
) -> Result<(), MerkleError> {
    if old.size == 0 || old.size > new.size {
        return Err(MerkleError::BadSizes {
            old: old.size,
            new: new.size,
        });
    }
    if old.size == new.size {
        return if proof.is_empty() && old.root == new.root {
            Ok(())
        } else if !proof.is_empty() {
            Err(MerkleError::BadProofLength)
        } else {
            Err(MerkleError::RootMismatch)
        };
    }
    let mut proof = proof.to_vec();
    if old.size.is_power_of_two() {
        proof.insert(0, old.root);
    }
    let (mut f_n, mut s_n) = (old.size - 1, new.size - 1);
    while f_n & 1 == 1 {
        f_n >>= 1;
        s_n >>= 1;
    }
    let Some((first, rest)) = proof.split_first() else {
        return Err(MerkleError::BadProofLength);
    };
    let (mut f_r, mut s_r) = (*first, *first);
    for c in rest {
        if s_n == 0 {
            return Err(MerkleError::BadProofLength);
        }
        if f_n & 1 == 1 || f_n == s_n {
            f_r = node_hash(c, &f_r);
            s_r = node_hash(c, &s_r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            s_r = node_hash(&s_r, c);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n != 0 {
        return Err(MerkleError::BadProofLength);
    }
    if f_r == old.root && s_r == new.root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

/// The largest power of two strictly less than `n`, for `n > 1`.
pub(crate) fn split(n: u64) -> u64 {
    debug_assert!(n > 1);
    1_u64 << (63 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&(i as u64).to_be_bytes()))
            .collect()
    }

    /// The definition of RFC 9162 §2.1.1 written out naively, to hold the
    /// iterative verifiers against something that shares no code with them.
    fn mth(d: &[Hash]) -> Hash {
        match d.len() {
            0 => Sha256::digest([]).into(),
            1 => d[0],
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                node_hash(&mth(&d[..k]), &mth(&d[k..]))
            }
        }
    }

    fn head(d: &[Hash]) -> TreeHead {
        TreeHead {
            size: d.len() as u64,
            root: root_of(d),
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The eight-leaf vectors used by the Certificate Transparency reference
    /// implementations: the root after each of the first eight leaves. A tree
    /// that agrees with these is the RFC 6962/9162 tree, not merely a tree that
    /// agrees with itself.
    #[test]
    fn roots_match_the_certificate_transparency_reference_vectors() {
        let data = [
            "",
            "00",
            "10",
            "2021",
            "3031",
            "40414243",
            "5051525354555657",
            "606162636465666768696a6b6c6d6e6f",
        ];
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        let leaves: Vec<Vec<u8>> = data.iter().map(|d| unhex(d)).collect();
        for n in 1..=8 {
            let h = TreeHead::of(&leaves[..n]);
            assert_eq!(
                h.root.to_vec(),
                unhex(roots[n - 1]),
                "root after {n} leaves"
            );
        }
    }

    #[test]
    fn split_is_the_largest_power_of_two_below_n() {
        for (n, k) in [
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 4),
            (8, 4),
            (9, 8),
            (1024, 512),
            (1025, 1024),
        ] {
            assert_eq!(split(n), k, "n={n}");
        }
    }

    #[test]
    fn root_matches_the_naive_definition() {
        for n in 0..70 {
            let d = leaves(n);
            assert_eq!(root_of(&d), mth(&d), "n={n}");
        }
    }

    #[test]
    fn every_inclusion_proof_verifies_and_every_tampered_one_fails() {
        for n in 1..=40 {
            let d = leaves(n);
            let h = head(&d);
            for i in 0..n as u64 {
                let p = inclusion_proof(&d, i).unwrap();
                verify_inclusion(&h, i, &d[i as usize], &p).unwrap();
                // wrong leaf
                let other = leaf_hash(b"not a leaf");
                assert!(verify_inclusion(&h, i, &other, &p).is_err());
                // wrong index
                if n > 1 {
                    let j = (i + 1) % n as u64;
                    if d[j as usize] != d[i as usize] {
                        assert!(
                            verify_inclusion(&h, j, &d[i as usize], &p).is_err(),
                            "n={n} i={i}"
                        );
                    }
                }
                // every single flipped proof element
                for k in 0..p.len() {
                    let mut bad = p.clone();
                    bad[k][0] ^= 1;
                    assert!(verify_inclusion(&h, i, &d[i as usize], &bad).is_err());
                }
                // truncated and extended
                if !p.is_empty() {
                    assert!(verify_inclusion(&h, i, &d[i as usize], &p[..p.len() - 1]).is_err());
                }
                let mut long = p.clone();
                long.push([7; 32]);
                assert!(verify_inclusion(&h, i, &d[i as usize], &long).is_err());
            }
        }
    }

    #[test]
    fn every_consistency_proof_verifies_and_every_tampered_one_fails() {
        for n in 1..=40 {
            let d = leaves(n);
            let new = head(&d);
            for m in 1..=n {
                let old = head(&d[..m]);
                let p = consistency_proof(&d, m as u64).unwrap();
                verify_consistency(&old, &new, &p).unwrap_or_else(|e| panic!("m={m} n={n}: {e}"));
                for k in 0..p.len() {
                    let mut bad = p.clone();
                    bad[k][31] ^= 0x80;
                    assert!(
                        verify_consistency(&old, &new, &bad).is_err(),
                        "m={m} n={n} k={k}"
                    );
                }
                // a rewritten history: same size, different old root
                let mut forged = old;
                forged.root[0] ^= 1;
                assert!(verify_consistency(&forged, &new, &p).is_err());
            }
        }
    }

    #[test]
    fn a_rewritten_prefix_cannot_prove_consistency_with_the_published_head() {
        let d = leaves(20);
        let published = head(&d[..12]);
        let mut rewritten = d.clone();
        rewritten[5] = leaf_hash(b"edited after publication");
        let new = head(&rewritten);
        let p = consistency_proof(&rewritten, 12).unwrap();
        assert_eq!(
            verify_consistency(&published, &new, &p),
            Err(MerkleError::RootMismatch)
        );
    }

    #[test]
    fn bad_sizes_are_refused() {
        let d = leaves(5);
        assert!(inclusion_proof(&d, 5).is_err());
        assert!(consistency_proof(&d, 0).is_err());
        assert!(consistency_proof(&d, 6).is_err());
        let h = head(&d);
        assert!(verify_inclusion(&h, 9, &d[0], &[]).is_err());
    }

    #[test]
    fn entry_hashes_decode_and_malformed_ones_are_refused() {
        let hex = "00ff".repeat(16);
        let b = leaf_from_entry_hash(&hex).unwrap();
        assert_eq!(b[0], 0x00);
        assert_eq!(b[1], 0xff);
        assert!(leaf_from_entry_hash("00FF").is_err());
        assert!(leaf_from_entry_hash(&"g".repeat(64)).is_err());
        assert!(leaf_from_entry_hash(&"A".repeat(64)).is_err());
    }

    #[test]
    fn the_tree_head_digest_is_tagged_and_binds_size_and_root() {
        let d = leaves(3);
        let h = head(&d);
        let mut other = h;
        other.size = 4;
        assert_ne!(h.digest(), other.digest());
        let mut manual = Sha256::new();
        manual.update(b"calymth1");
        manual.update(3_u64.to_be_bytes());
        manual.update(h.root);
        assert_eq!(h.digest(), <[u8; 32]>::from(manual.finalize()));
    }

    #[test]
    fn consistency_between_equal_sizes_and_impossible_sizes() {
        let d = leaves(6);
        let h = head(&d);
        verify_consistency(&h, &h, &[]).unwrap();
        let mut other = h;
        other.root[0] ^= 1;
        assert_eq!(
            verify_consistency(&other, &h, &[]),
            Err(MerkleError::RootMismatch)
        );
        assert_eq!(
            verify_consistency(&h, &h, &[[0; 32]]),
            Err(MerkleError::BadProofLength)
        );
        let empty = TreeHead {
            size: 0,
            root: h.root,
        };
        assert!(matches!(
            verify_consistency(&empty, &h, &[]),
            Err(MerkleError::BadSizes { .. })
        ));
        let bigger = TreeHead {
            size: 7,
            root: h.root,
        };
        assert!(matches!(
            verify_consistency(&bigger, &h, &[]),
            Err(MerkleError::BadSizes { .. })
        ));
        // A non-power-of-two old tree with no proof at all.
        let old = head(&d[..3]);
        assert_eq!(
            verify_consistency(&old, &h, &[]),
            Err(MerkleError::BadProofLength)
        );
        // Too long a proof runs past the root.
        let mut p = consistency_proof(&d, 3).unwrap();
        p.extend([[1; 32]; 4]);
        assert!(verify_consistency(&old, &h, &p).is_err());
    }

    #[test]
    fn a_truncated_consistency_proof_is_too_short() {
        let d = leaves(11);
        let (old, new) = (head(&d[..5]), head(&d));
        let p = consistency_proof(&d, 5).unwrap();
        assert!(p.len() > 1);
        assert_eq!(
            verify_consistency(&old, &new, &p[..p.len() - 1]),
            Err(MerkleError::BadProofLength)
        );
    }
}
