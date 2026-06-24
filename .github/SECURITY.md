# Security Policy

## Reporting a Vulnerability

Email: emirhuseyininci@gmail.com
Subject: `[SECURITY] Calybris Core — <brief description>`

I will acknowledge receipt within 48 hours.

## Open-Source Core Security

- `#![forbid(unsafe_code)]` — no unsafe Rust in project code
- SHA-256 hash-chained WAL — tamper-evident decision log
- CAS-based budget reservation — no overspend under concurrency
- Integer-only kernel API — no floating-point in hot path
- Corrupt WAL and concurrent budget tests included

## Full Engine Security

The proprietary engine adds API-plane separation, constant-time key comparison, deployment hardening (read-only Docker, no-new-privileges), provider credential isolation, and additional adversarial tests.

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |
