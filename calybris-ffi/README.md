# calybris-ffi

A stable C ABI over the Calybris decision kernel, for callers that are neither
Rust nor Python.

It adds no behaviour. Every function converts C structs into the kernel's own
types, calls `calybris-core`, and converts back — so a C caller makes the same
decision and recomputes the same digest as everyone else.

```c
#include "calybris.h"

calybris_policy *policy = NULL;
if (calybris_policy_new(&config, models, 2, &policy) != CALYBRIS_OK) {
  /* handle it; *policy is NULL */
}

calybris_decision decision;
calybris_decide(policy, &input, &decision);

char hex[CALYBRIS_DIGEST_HEX_LEN + 1];
calybris_decision_digest_hex(&decision, hex, sizeof(hex));

calybris_policy_free(policy);
```

## Build

```sh
cargo build -p calybris-ffi --release
```

Produces a `cdylib` and a `staticlib`. The header is
[`include/calybris.h`](include/calybris.h), hand-written rather than generated,
so that it can carry the comments a caller needs and so that it is reviewable as
part of the contract.

## What is stable

`CALYBRIS_ABI_VERSION`, the layout of every struct in the header, the status
codes, and the function signatures. Check the ABI version before anything else:

```c
if (calybris_abi_version() != CALYBRIS_ABI_VERSION) {
  /* refuse to continue rather than guess at the layouts */
}
```

**The struct layouts are not the digest layouts.** Digests are defined
byte-for-byte in [docs/SPECIFICATION.md](../docs/SPECIFICATION.md) and are a
separate, also-frozen thing. Never hash these structs — ask for a digest.

## How it behaves at the edges

| | |
|---|---|
| Panics | Unwinding across `extern "C"` is undefined behaviour, so every entry point catches it and returns `CALYBRIS_ERR_PANIC`. The kernel is not expected to panic; this is the boundary refusing to make a bug worse. |
| Null pointers | Refused with `CALYBRIS_ERR_NULL`, never dereferenced. `calybris_policy_free(NULL)` is defined as doing nothing. |
| Short buffers | `CALYBRIS_ERR_BUFFER_TOO_SMALL`, and **nothing is written** — so a caller that ignores the status cannot read a truncated digest as a whole one. |
| Unknown discriminants | An `action` or `reason` that is not a real variant is refused with `CALYBRIS_ERR_UNKNOWN_VARIANT` rather than reinterpreted. |
| Failed verification | `calybris_verify` sets `*valid` to 0 before doing anything, so a caller that ignores the status does not read a stale 1. |
| Ownership | The only thing this crate allocates for the caller is the policy handle. Free it once with `calybris_policy_free`. |

## Tests

`cargo test -p calybris-ffi` exercises the entry points from Rust. That is
necessary and not sufficient: those tests use Rust's idea of the struct layouts,
so a header declaring a field in the wrong order or the wrong width would pass
every one of them.

[`tests/smoke.c`](tests/smoke.c) is the check that matters. A C compiler reads
the header, the program links the static library, and it asserts the three
digests pinned in `tests/fixtures/calybris_outcome_v1.json` — the same bytes the
Rust and Python golden tests assert. One set of bytes, three callers.

```sh
python scripts/check_c_abi.py
```

It compiles with `-Wall -Wextra -Werror` (or `/W4 /WX`) and skips cleanly on a
machine with no C compiler. CI runs it on Linux and Windows.

## Versioning

This crate tracks `calybris-core`, and
[docs/COMPATIBILITY.md](../docs/COMPATIBILITY.md) applies to it: the ABI is
stable across 1.x. New functions can be added; a change to any existing layout
would need `CALYBRIS_ABI_VERSION` 2 and a major release.
