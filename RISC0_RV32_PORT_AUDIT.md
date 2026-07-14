# RISC Zero RV32 verifier-port audit

Status: **both real proofs execute in the RISC Zero RV32 local executor; fail
closed**. GitHub run
[`29364870460`](https://github.com/patrickdugan/bark-shinigami-zk-bitvm-demos/actions/runs/29364870460)
built the complete guest and exact pinned local executor, executed both saved
STWO proofs, and emitted type-distinct 184-byte denial-evidence journals. It
did not generate a RISC Zero receipt or contact a remote prover network. This
audit removes no verification check and introduces no host-supplied acceptance
value.

## Reproduced boundary

The audit used isolated copies of the exact proof dependencies:

- `stwo-cairo` `b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1`
- STWO `93dd93e04f42edba48d8984858c8c39ce9f30c8c`
- `risc0-zkvm` `3.0.4`

The only source change before cross-compilation was removal of the deliberate
`target_os = "zkvm"` `compile_error!` guard. The verifier still deserializes
`CairoProofForRustVerifier<Blake2sMerkleHasher>` and calls the real
`verify_cairo::<Blake2sMerkleChannel>` function.

RISC Zero does not publish its custom Rust target for native Windows. The real
cross-check therefore runs on a GitHub Ubuntu runner with official RISC Zero
Rust and:

```text
cargo +risc0 check \
  --features risc0-guest \
  --target riscv32im-risc0-zkvm-elf
```

The target needs the standard RISC Zero custom-randomness selection, even when
the verifier never asks for randomness, and the checked-in RISC Zero 3.0.4
linker layout places executable text at `0x00200800`:

```toml
[target.riscv32im-risc0-zkvm-elf]
rustflags = [
  '--cfg', 'getrandom_backend="custom"',
  '-C', 'link-arg=-Triscv32im-risc0-zkvm-elf.ld',
]
```

Cargo must be launched from the guest crate (or receive equivalent explicit
flags), because configuration discovery starts at the process working
directory rather than at an arbitrary `--manifest-path`.

Without it, `getrandom 0.3.4`, reached through
`risc0-zkvm-platform 2.2.2`, stops at its unsupported-target
`compile_error!`.

## Exact failures reached

With that target configuration, RISC Zero Rust `1.94.1` reaches two independent
failures:

1. `risc0-zkvm 3.0.4` defines `panic_impl`, but the 1.94.1 target sysroot also
   loads `std` and defines the same lang item. This SDK/toolchain mismatch
   produces `E0152: found duplicate lang item panic_impl` before the guest can
   link. The historically matching RISC Zero Rust release is `r0.1.88.0`,
   published June 27, 2025. Its diagnostic rerun was started but deliberately
   capped rather than waiting indefinitely for the 490,849,318-byte toolchain
   download.
2. `sonic-rs 0.3.17`, pulled unconditionally by `cairo-air`, fails on RV32 with
   `E0512`: its `MetaNode` is 64 bits while `Value` is 128 bits, so its internal
   transmute is invalid. `sonic-rs` is used only by host JSON/file utilities;
   it is not part of the cryptographic verification relation.

The second failure is a genuine `stwo-cairo` verifier packaging blocker and is
not fixed by adding RAM or using a remote prover.

## Exact dependency audit

At the pinned commit, `cairo-air` unconditionally includes dependencies that
the verifier call does not need: Clap, bzip2, serde JSON, `sonic-rs`, and Rayon.
Its public `utils` module mixes the verifier-required
`pack_into_secure_felts` helper with host proof-file and JSON utilities.

`stwo-cairo-common` also unconditionally depends on Rayon, primarily for
Pedersen table construction. This remains a portability risk to test after
removing `sonic-rs`; it was not the first compiler failure and is therefore not
claimed here as a confirmed blocker.

The previous portable-SIMD diagnosis was too broad. In the pinned graph,
`prover_types::simd` and STWO's SIMD backend are already gated by the `prover`
feature, and the verifier build does not enable that feature.

`verify_cairo` itself uses `std::collections::HashMap` and `serde_json` only to
format relation-use diagnostics. The relation-use bounds and all calls to
STWO's PCS/FRI verifier must remain unchanged.

## Minimal verifier-only port

The smallest defensible upstream patch is:

1. Add a `verifier` feature to `cairo-air`; put file I/O, Clap, bzip2,
   `serde_json`, and `sonic-rs` behind a separate host-utils feature.
2. Move `pack_into_secure_felts` into an allocation-only verifier utility
   module so `air.rs` and `flat_claims.rs` do not import the file utility module.
3. Remove pretty-JSON diagnostic formatting from the verifier-only build while
   preserving the exact `uses >= PRIME` rejection and every assertion in
   `verify_claim`.
4. Make Rayon optional in `stwo-cairo-common`. Provide sequential Pedersen
   table construction for the verifier build, or omit table materialization
   when only preprocessed IDs and log sizes are requested.
5. Set `default-features = false` for `stwo` and
   `stwo-constraint-framework`, enabling only their verifier-compatible `std`
   surface if the matching RISC Zero target requires it.
6. Cross-compile with the SDK-matched RISC Zero Rust 1.88.0 toolchain, then run
   the two checked-in proofs through the resulting guest before measuring and
   pinning its image ID.

The direct-build compile guard remains because Cargo cannot apply the checked-in
upstream patch by itself. The GitHub workflow removes it only in an isolated
copy after the exact patch applies and its file scope is checked. Do not replace
`verify_cairo` with a Boolean, a host attestation, or a development receipt.
The CI job pins all four versions (RISC Zero Rust, SDK, STWO, and `stwo-cairo`)
so an incompatible latest toolchain cannot mask a real regression.

## Checked-in verifier-only patch

`stwo-cairo-risc0-verifier-only.patch` is an application-ready diff against
`b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1`. It feature-gates `cairo-air`
host utilities and `stwo-cairo-common`'s prover-only Pedersen table
materialization. In `verifier.rs`, it replaces pretty-JSON diagnostics in the
verifier-only build but leaves the exact `uses >= PRIME` rejection intact. It
does not modify AIR components, the Fiat-Shamir channel, PCS or FRI logic. Its
SHA-256 is
`106255ba721391977be95efe9bafdd257db81f0fe550f1a35c88d07632d5b6e1`.

Apply and validate it from a clean pinned `stwo-cairo` checkout:

```text
git checkout --detach b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1
git apply --check /path/to/stwo-cairo-risc0-verifier-only.patch
git apply /path/to/stwo-cairo-risc0-verifier-only.patch
cargo +nightly-2025-06-23 fmt \
  --manifest-path stwo_cairo_prover/Cargo.toml \
  --package cairo-air -- --check
cargo +nightly-2025-06-23 check \
  --manifest-path stwo_cairo_prover/Cargo.toml \
  --package cairo-air
cargo +nightly-2025-06-23 check \
  --manifest-path stwo_cairo_prover/Cargo.toml \
  --package cairo-air --no-default-features --features verifier
cargo +nightly-2025-06-23 check \
  --manifest-path stwo_cairo_prover/Cargo.toml \
  --package stwo-cairo-common --features prover
```

All four native validation commands passed against the pinned checkout. The
default build still includes the existing proof-file and CLI surface. The
verifier-only build excludes bincode, bzip2, Clap, `serde_json`, `sonic-rs`
and Rayon, eliminating the confirmed RV32 pointer-width failure and
prover-threading surface while retaining the real verifier. The existing
`prover` feature still compiles the Pedersen tables and Rayon path.

The GitHub RV32 probe, on an Ubuntu runner with official RISC Zero Rust, is:

```text
rzup install rust 1.88.0  # installs backing release r0.1.88.0
cargo +risc0 check \
  --manifest-path stwo_cairo_prover/Cargo.toml \
  --package cairo-air --no-default-features --features verifier \
  --target riscv32im-risc0-zkvm-elf
```

For a full `risc0-zkvm 3.0.4` guest rather than the isolated `cairo-air`
probe, also configure the target's getrandom backend and exact linker layout:

```toml
[target.riscv32im-risc0-zkvm-elf]
rustflags = [
  '--cfg', 'getrandom_backend="custom"',
  '-C', 'link-arg=-Triscv32im-risc0-zkvm-elf.ld',
]
```

The dedicated `RISC Zero RV32 verifier port` GitHub workflow applies the patch
to a clean pinned checkout, asserts its exact file scope and unchanged
relation-use predicate, rejects host-only dependencies from the RV32 graph,
pins `enum-ordinalize` 4.3.2 (the latest checked version compatible with the
SDK's Rust 1.88 toolchain), enables RISC Zero's partial `std` runtime without
also selecting its no-std entry macro, and compiles the full guest around the
real `verify_cairo` call. The release guest supplies only the five compiler
atomic ABI functions actually referenced by this single-hart RV32IM graph;
they use compiler fences and volatile accesses and do not weaken STWO checks.
The host executor lock pins the complete mutually compatible RISC Zero 3.0.4
dependency family, avoiding the `impl Read` object-safety failure caused by a
mixed `risc0-circuit-rv32im 4.0.4` graph.

## Measured local execution

Run `29364870460` validated that the ELF's executable `PT_LOAD` begins at RISC
Zero `TEXT_START` `0x00200800` and that entry `0x005836b4` lies inside it. The
measured artifacts are:

| Artifact | Value |
| --- | --- |
| user ELF | 4,556,392 bytes; SHA-256 `d7782be6ed709b0489a6f7c4cf7ba41ef540cd70c8dc0ea95685d9086258f1b3` |
| encoded program | 4,588,816 bytes; SHA-256 `5440480726db70569ab3a644322617c4d9c6e70bee26b5dd1f9a152299c4fa97` |
| image ID | `62516f3521371587578fa93e3f9d8952bdf396d733c54079ac27f91864720484` |
| owner exit | 2,551,810,043 cycles; 2,857 segments; max `po2` 20 |
| virtual CET | 2,580,013,351 cycles; 2,889 segments; max `po2` 20 |

Both sessions halted cleanly after the real `verify_cairo` call. Each journal
proved `transaction_relation_valid = 1` while retaining
`chain_state_verified = 0` and `operator_take_authorized = 0`. The executor
required exactly 184 denial-evidence bytes and rejected any 32-byte
authorization alias. `RISC0_EXECUTOR=local` was set explicitly; no Boundless,
Bonsai, PrimeLab, or other proving-network request occurred. A local execution
session is not a cryptographic RISC Zero receipt, so receipt generation and
independent receipt verification remain mandatory before any enforcement
claim.
