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
- A distinct 184-byte `BARKZKVE` journal that proves the STWO verification and
  pinned relation output on denial. Its type and length cannot alias the
  32-byte authorization journal.

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
`getrandom` backend and exact 3.0.4 linker layout for
`riscv32im-risc0-zkvm-elf`; it has no effect on native builds.

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

The checked-in guest still stops an unpatched direct Cargo build at a deliberate
compile guard. The repository includes
`../stwo-cairo-risc0-verifier-only.patch`, which gates host file utilities,
JSON diagnostics, Rayon and Pedersen table materialization while leaving the
real verifier and its relation bounds intact. The dedicated GitHub RV32
workflow applies that patch to the exact upstream commit; its full compile and
local execution with RISC Zero Rust 1.88.0 are green.

Both proof artifacts independently reproduce the nonzero program commitment
`4c75023e...714ef067` and policy commitment `626cd38f...71955314` now pinned in
the guest. GitHub run
[`29364870460`](https://github.com/patrickdugan/bark-shinigami-zk-bitvm-demos/actions/runs/29364870460)
executed both in the exact pinned local zkVM executor. The measured image ID is
`62516f3521371587578fa93e3f9d8952bdf396d733c54079ac27f91864720484`;
the owner-exit and virtual-CET sessions used 2,551,810,043 and 2,580,013,351
cycles respectively and each emitted the expected 184-byte denial journal.

This is measured execution, not a cryptographic RISC Zero receipt. A compile
success or 184-byte denial journal is not operator authorization; the current
`1,0,0` relation still cannot emit the 32-byte authorization journal.
