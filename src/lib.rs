//! # Calybris Core
//!
//! Deterministic proof-carrying decision kernel, HMAC-SHA256 hash-chained
//! write-ahead log, CAS atomic budget engine, and fixed-point financial proofs.
//!
//! - **`kernel`**: Allocation-free integer decision kernel (8.6M decisions/sec)
//! - **`verify`**: Canonical digests, replay verification, correctness certificates
//! - **`finance`**: Ledger snapshots, conservation proofs (HFT-grade integer accounting)
//! - **`wal`**: Generic tamper-evident hash-chained WAL with optional HMAC keying
//! - **`budget`**: Per-tenant atomic budget management with conservation invariant
//!
//! ```no_run
//! use calybris_core::kernel::*;
//! use calybris_core::verify::{audit_bundle, verify_decision, VerifyResult};
//! use calybris_core::finance::certify_ledger;
//! use calybris_core::budget::BudgetEngine;
//! #[cfg(feature = "serde")]
//! use calybris_core::wal::WalWriter;
//! ```

#![forbid(unsafe_code)]

/// Canonical SHA-256 digests for audit binding.
pub mod digest;
/// Per-tenant atomic budget engine with CAS reservation.
pub mod budget;
/// Fixed-point financial layer: ledger digest and conservation proofs.
pub mod finance;
/// Allocation-free prescriptive decision kernel.
pub mod kernel;
/// Decision verification, replay, and correctness certificates.
pub mod verify;
/// HMAC-SHA256 hash-chained write-ahead log.
#[cfg(feature = "serde")]
pub mod wal;