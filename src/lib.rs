//! # Calybris Core
//!
//! Deterministic proof-carrying decision kernel, HMAC-SHA256 hash-chained
//! write-ahead log, CAS atomic budget engine, and fixed-point financial proofs.
//!
//! - **`kernel`**: Allocation-free integer decision kernel (~8.6M prescribe/sec on CodSpeed CI)
//! - **`verify`**: Canonical digests, replay verification, correctness certificates
//! - **`receipt`**: Replay-verified receipts binding policy, state, WAL, and signatures
//! - **`finance`**: Ledger snapshots and fixed-point conservation proofs for pre-trade guard primitives
//! - **`wal`**: Single-writer hash-chained WAL with HMAC keying and trusted head anchors
//! - **`budget`**: Per-tenant atomic budget management with conservation invariant
//! - **`config`**: Runtime configuration with builder ergonomics
//! - **`builder`**: Builder patterns for `KernelInput`, `KernelModel`, `PolicySnapshot`
//! - **`persistence`**: Snapshot save/load and crash recovery
//! - **`async_wal`**: Non-blocking WAL via Tokio (feature `async`)
//! - **`instrument`**: Structured tracing instrumentation (feature `observability`)
//!
//! Behind the `preview` feature, released but not yet under the 1.x stability
//! promise (`docs/PREVIEW.md`):
//!
//! - **`counterfactual`**: what a losing candidate would need to win, and the winner's margin
//! - **`merkle`**: RFC 9162 inclusion and consistency proofs over a decision log
//! - **`exploration`**: keyed, replayable exploration with exact recorded propensities
//! - **`ope`**: off-policy estimates of what a different policy would have achieved
//! - **`hybrid`**: Ed25519 + ML-DSA-65 hybrid signatures and batches (feature `preview-pq`)
//! - **`checkpoint`**: C2SP signed checkpoints, log signatures and witness cosignatures
//! - **`witness`**: an independent witness speaking C2SP tlog-witness
//! - **`audit`**: witness quorums, split-view evidence, record proofs, revoked keys
//! - **`ots`**: OpenTimestamps proofs verified against Bitcoin block headers
//! - **`tsa`**: RFC 3161 timestamp tokens against pinned TSA certificates (feature `preview-tsa`)
//!
//! ```no_run
//! use calybris_core::kernel::*;
//! use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
//! use calybris_core::finance::certify_ledger;
//! use calybris_core::budget::BudgetEngine;
//! use calybris_core::builder::{InputBuilder, ModelBuilder, PolicyBuilder};
//! use calybris_core::config::EngineConfig;
//! #[cfg(feature = "wal")]
//! use calybris_core::wal::WalWriter;
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "serde")]
mod bounded_io;
mod sync;

/// Async hash-chained WAL using Tokio.
#[cfg(feature = "async")]
pub mod async_wal;
// Witness quorums, split-view evidence and record proofs for outside auditors (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod audit;
/// Per-tenant atomic budget engine with CAS reservation.
pub mod budget;
/// Builder ergonomics for inputs, models, and policies.
pub mod builder;
// C2SP signed checkpoints, log signatures and witness cosignatures (feature `preview`). Documented in the module itself.
/// Single proof envelope binding decision to full evidence chain.
#[cfg(feature = "serde")]
pub mod certificate;
#[cfg(feature = "preview")]
pub mod checkpoint;
/// Runtime configuration and validation.
pub mod config;
// What would have to change for a decision to come out differently (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod counterfactual;
/// Canonical SHA-256 digests for audit binding.
pub mod digest;
// Keyed, replayable exploration among near-best candidates (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod exploration;
/// Fixed-point financial layer: ledger digest and conservation proofs.
pub mod finance;
// Ed25519 + ML-DSA-65 hybrid signatures over an artifact digest (feature `preview-pq`). Documented in the module itself.
#[cfg(feature = "preview-pq")]
pub mod hybrid;
/// Structured tracing instrumentation.
#[cfg(feature = "observability")]
pub mod instrument;
#[cfg(kani)]
mod kani_proofs;
/// Allocation-free prescriptive decision kernel.
pub mod kernel;
// RFC 9162 Merkle inclusion and consistency proofs over a decision log (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod merkle;
// OpenTimestamps proofs anchored in Bitcoin (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod ots;
// Off-policy estimates of what a different policy would have achieved (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod ope;
// Decision outcomes: what happened after a decision, and how it was chosen. Documented in the module itself.
pub mod outcome;
/// Snapshot persistence and crash recovery.
#[cfg(feature = "serde")]
pub mod persistence;

pub mod proof;

#[cfg(feature = "provenance")]
pub mod provenance;

/// Signed receipt binding a decision to policy, state, and WAL evidence.
#[cfg(feature = "serde")]
pub mod receipt;

pub mod state;
// RFC 3161 timestamp requests and token verification (feature `preview-tsa`). Documented in the module itself.
#[cfg(feature = "preview-tsa")]
pub mod tsa;
/// Decision verification, replay, and correctness certificates.
pub mod verify;
/// HMAC-SHA256 hash-chained write-ahead log.
#[cfg(feature = "wal")]
pub mod wal;
// An independent witness speaking C2SP tlog-witness (feature `preview`). Documented in the module itself.
#[cfg(feature = "preview")]
pub mod witness;
