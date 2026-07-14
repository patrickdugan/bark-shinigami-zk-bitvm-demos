# RISC Zero outer verifier scaffold

This crate is the fail-closed boundary between a STWO proof of the pinned Cairo
relation and a Boundless receipt. It does not authorize the current showcase:
`BarkShinigamiOutputV3` deliberately returns `chain_state_verified = 0` and
`operator_take_authorized = 0`, so no 32-byte authorization journal can be
emitted.

## What is implemented

- Exact parsing of the 19 public `u32` words returned by
  `BarkShinigamiOutputV3`.
- Mandatory, domain-separated commitments to the public Cairo program and the
  complete STWO verifier policy.
- A private `VerifiedExecution` constructor reachable only from the upstream
  cryptographic verifier adapter.
- Native deserialization of the pinned compressed proof format, followed by
  the real `cairo_air::verifier::verify_cairo` call.
- Strict rejection of bytes after the bzip2 stream and bytes after the one
  canonical bincode object.
- Exact enforcement of channel salt, PCS/FRI parameters, preprocessing mode,
  interaction PoW and the authenticated STWO program hash.
- Allocation-free parsing of the complete versioned guest-input frame and
  canonical Bark envelope, including a typed RISC Zero image-ID handshake.
- A fixed-width artifact-complete journal encoder cross-checked against the
  outer adapter with a shared golden digest.
- A 32-byte Boundless journal that can be constructed only when the proof,
  program pin, policy pin, transaction relation, chain state and operator
  authorization all succeed.

There is no mock verifier, development receipt, or caller-provided acceptance
boolean.

## Pins

| Component | Pin |
| --- | --- |
| `stwo-cairo` | `b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1` |
| STWO | `93dd93e0` |
| STWO Rust toolchain | `nightly-2025-06-23` |
| RISC Zero | `3.0.4` |
| Proof format | bzip2-compressed bincode `CairoProofForRustVerifier<Blake2sMerkleHasher>` |

The checked-in target configuration selects RISC Zero's required custom
`getrandom` backend for `riscv32im-risc0-zkvm-elf`; it has no effect on native
builds.

## Commands

The claim and journal layer is portable and testable now:

```text
cargo test
cargo test --no-default-features
```

The native upstream adapter requires the pinned nightly:

```text
rustup toolchain install nightly-2025-06-23
cargo +nightly-2025-06-23 check --features upstream-stwo
cargo +nightly-2025-06-23 test --features upstream-stwo
```

The native suite reloads both checked-in compressed artifacts through the
adapter, calls upstream `verify_cairo`, checks the authenticated program hash
and Bark statement digests, confirms that their `1,0,0` outputs cannot emit an
authorization journal, and rejects compressed-stream and bincode trailers.

The checked-in guest still stops at a deliberate compile guard. The repository
now includes `../stwo-cairo-risc0-verifier-only.patch`, which gates host file
utilities, JSON diagnostics, Rayon and Pedersen table materialization while
leaving the real verifier and its relation bounds intact. The dedicated GitHub
RV32 workflow applies that patch to the exact upstream commit and compiles the
full guest with RISC Zero Rust 1.88.0.

The guard and zero policy pins remain until that cross-compile passes and both
checked-in STWO proofs execute inside the guest. A compile success alone is not
an operator authorization and does not create a receipt.
