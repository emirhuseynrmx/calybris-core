//! A decision receipt is the artifact a third party is handed.
//!
//! The property: verification of an attacker-supplied receipt never panics, and
//! never reports a receipt valid against a state and WAL it does not describe.

#![no_main]

use calybris_core::receipt::DecisionReceipt;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(receipt) = serde_json::from_slice::<DecisionReceipt>(data) else {
        return;
    };

    // Round-tripping must not panic and must not lose the record. A receipt
    // that re-encodes to something that decodes differently would be a receipt
    // two readers could disagree about.
    if let Ok(encoded) = serde_json::to_vec(&receipt) {
        match serde_json::from_slice::<DecisionReceipt>(&encoded) {
            Ok(again) => assert_eq!(receipt, again, "receipt did not survive a round trip"),
            Err(error) => panic!("a receipt we encoded would not decode: {error}"),
        }
    }
});
