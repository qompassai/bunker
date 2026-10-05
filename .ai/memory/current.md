# Current Work

Post-quantum secure Nix binary cache server (fork of zhaofengli/attic).

## Status

Active development: PQ hardening program in progress (2026-10-04).
See ~/workspace/bunker/plan-2026-10-04.md for the phased plan.

Decisions (2026-10-04, Matt):
- Hybrid signatures (Ed25519 + ML-DSA-65) for NAR signing
- Proxy is a workspace member (moved from .forge/proxy/)
- NixOS deployment target; also local/dev cache and remote ops
- Finish PQ before considering upstream attic sync; stay forked

## Standing rules

- License: AGPL-3.0 + Q-CDA (see LICENSE-AGPL, LICENSE-QCDA).
- Tiger Style Rust for all new/changed code.
- Gates per phase: cargo build, clippy -D warnings, tests 50/50 validation/adversarial.
