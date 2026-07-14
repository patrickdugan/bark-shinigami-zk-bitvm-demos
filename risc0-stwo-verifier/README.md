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
cargo +nightly-2025-06-23 test --features upstream-stwo --test real_proofs
```

The real-proof test reloads both checked-in compressed artifacts through the
native adapter, calls upstream `verify_cairo`, checks the authenticated Bark
statement digests, and confirms that their `1,0,0` outputs cannot emit an
authorization journal.

Building `--features risc0-guest` for `riscv32im-risc0-zkvm-elf` intentionally
stops at a compile error. At the pinned commit, `cairo-air` unconditionally
includes `std::fs`, Rayon and portable-SIMD/prover modules. The STWO core
verifier supports `no_std`, but the Cairo-specific verifier has not yet been
split into an RV32-compatible crate. Removing this error without completing and
reviewing that port would turn a visible missing verifier into an unsafe gap.

The minimum upstream work is to feature-gate file utilities, Rayon and
`prover_types::simd`; move the scalar claim types needed by the verifier into a
verifier-only module; use `stwo` and `stwo-constraint-framework` without default
features; and cross-compile the resulting real verifier before replacing the
zero policy pins in the guest.
