//! RFC 3161 responses are DER from a remote authority.
//!
//! The property: verification of arbitrary bytes never panics, whatever the
//! ASN.1 inside claims about lengths, algorithms or certificates.

#![no_main]

use calybris_core::tsa::{verify_response, verify_token_der, PinnedTsa};
use libfuzzer_sys::fuzz_target;

const RSA: &str = include_str!("../../tests/fixtures/rfc3161/rsa.crt");
const P256: &str = include_str!("../../tests/fixtures/rfc3161/p256.crt");

fuzz_target!(|data: &[u8]| {
    let pins = [
        PinnedTsa::from_pem(RSA).expect("fixture"),
        PinnedTsa::from_pem(P256).expect("fixture"),
    ];
    let digest = [0x5a; 32];
    let _ = verify_response(data, &digest, None, &pins);
    let _ = verify_response(data, &digest, Some(7), &pins);
    let _ = verify_token_der(data, &digest, None, &pins);
});
