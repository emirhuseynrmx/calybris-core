//! Sync primitives for budget concurrency.
//!
//! When the build script enables `cfg(loom)` through `CALYBRIS_LOOM`, mutexes
//! and atomics use `loom::sync` for model checking. `Arc` stays
//! `std::sync::Arc` (loom's `Arc` does not support `HashMap` keys).

#[cfg(loom)]
pub use loom::sync::atomic::{AtomicI64, AtomicU64, Ordering};
#[cfg(loom)]
pub use loom::sync::{Mutex, RwLock};

#[cfg(not(loom))]
pub use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
#[cfg(not(loom))]
pub use std::sync::{Mutex, RwLock};

pub use std::sync::Arc;
