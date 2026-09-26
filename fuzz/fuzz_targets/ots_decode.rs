//! OpenTimestamps proofs come from files and from calendar servers.
//!
//! The property: parsing never panics, what parses serializes to a form that
//! parses back to the same proof, and a proof on its own is never reported
//! as verified — only a block header can do that.

#![no_main]

use calybris_core::ots::{DetachedTimestamp, Status};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(proof) = DetachedTimestamp::parse(data) else {
        return;
    };
    let canonical = proof.serialize();
    let again = DetachedTimestamp::parse(&canonical).expect("a serialized proof parses");
    assert_eq!(again, proof);
    assert_eq!(again.serialize(), canonical);
    assert!(!matches!(proof.status(), Status::Verified(_)));
    let _ = proof.pending();
});
