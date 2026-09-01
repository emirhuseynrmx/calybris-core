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
/// Per-tenant atomic budget engine with CAS reservation.
pub mod budget;
/// Builder ergonomics for inputs, models, and policies.
pub mod builder;
/// Single proof envelope binding decision to full evidence chain.
#[cfg(feature = "serde")]
pub mod certificate;
/// Runtime configuration and validation.
pub mod config;
/// Canonical SHA-256 digests for audit binding.
pub mod digest;
/// Fixed-point financial layer: ledger digest and conservation proofs.
pub mod finance;
/// Structured tracing instrumentation.
#[cfg(feature = "observability")]
pub mod instrument;
/// Allocation-free prescriptive decision kernel.
pub mod kernel;
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
/// Decision verification, replay, and correctness certificates.
pub mod verify;
/// HMAC-SHA256 hash-chained write-ahead log.
#[cfg(feature = "wal")]
pub mod wal;
