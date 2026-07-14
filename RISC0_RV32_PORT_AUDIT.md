# RISC Zero RV32 verifier-port audit

Status: **real verifier cross-compiles for RV32; zkVM execution pending; fail
closed**. GitHub run
[`29351949727`](https://github.com/patrickdugan/bark-shinigami-zk-bitvm-demos/actions/runs/29351949727)
compiled the complete guest successfully. This audit removes no verification
check and introduces no host-supplied acceptance value.

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
the verifier never asks for randomness:

```toml
[target.riscv32im-risc0-zkvm-elf]
rustflags = ['--cfg', 'getrandom_backend="custom"']
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
`3624ce654927a66082b36caf47f5a0ac62a51179d92897b89c62d587a615c719`.

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
probe, also configure the target's getrandom backend:

```toml
[target.riscv32im-risc0-zkvm-elf]
rustflags = ['--cfg', 'getrandom_backend="custom"']
```

The dedicated `RISC Zero RV32 verifier port` GitHub workflow applies the patch
to a clean pinned checkout, asserts its exact file scope and unchanged
relation-use predicate, rejects host-only dependencies from the RV32 graph,
pins `enum-ordinalize` 4.3.2 (the latest checked version compatible with the
SDK's Rust 1.88 toolchain), enables RISC Zero's partial `std` runtime without
also selecting its no-std entry macro, and compiles the full guest around the
real `verify_cairo` call. Run `29351949727` passed this complete cross-compile
in 1 minute 23 seconds. The next gate builds a release ELF and executes both
checked-in proofs with the real local zkVM executor; failure must not be
bypassed with a mock verifier.
