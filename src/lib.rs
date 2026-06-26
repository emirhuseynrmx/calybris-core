//! # Calybris Core
//!
//! Deterministic proof-carrying decision kernel, HMAC-SHA256 hash-chained
//! write-ahead log, and CAS atomic budget engine.
//!
//! - **`kernel`**: Allocation-free integer decision kernel (8.6M decisions/sec)
//! - **`wal`**: Generic tamper-evident hash-chained WAL with optional HMAC keying
//! - **`budget`**: Per-tenant atomic budget management with conservation invariant
//!
//! ```no_run
//! use calybris_core::kernel::*;
//! use calybris_core::wal::WalWriter;
//! use calybris_core::budget::BudgetEngine;
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

/// Per-tenant atomic budget engine with CAS reservation.
pub mod budget;
/// Allocation-free prescriptive decision kernel.
pub mod kernel;
/// HMAC-SHA256 hash-chained write-ahead log.
pub mod wal;
