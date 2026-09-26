//! Checkpoint notes and witness requests arrive from the network.
//!
//! The property: parsing never panics, and whatever parses is canonical —
//! rendering it gives text that parses back to the same value, and a
//! checkpoint body that parses renders to exactly the bytes it came from.

#![no_main]

use calybris_core::checkpoint::{Checkpoint, SignedNote};
use calybris_core::witness::AddCheckpoint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(note) = SignedNote::parse(text) {
        let again = SignedNote::parse(&note.render()).expect("a rendered note parses");
        assert_eq!(again, note);
        if let Ok(cp) = note.checkpoint() {
            assert_eq!(cp.body(), note.text(), "a checkpoint body has one form");
        }
    }
    if let Ok(cp) = Checkpoint::parse(text) {
        assert_eq!(cp.body(), text);
    }
    if let Ok(req) = AddCheckpoint::parse(text) {
        assert_eq!(
            AddCheckpoint::parse(&req.render()).expect("a rendered request parses"),
            req
        );
    }
});
