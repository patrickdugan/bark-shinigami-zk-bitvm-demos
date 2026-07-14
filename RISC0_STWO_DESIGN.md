# RISC Zero recursion contract for the Shinigami STWO relation

Status: design specification, not an enforcement claim. A fail-closed RISC Zero
guest scaffold and reviewable upstream verifier-only patch now exist; the
checked-in guest remains guarded pending the dedicated RV32 cross-compile and
does not yet satisfy this contract. No receipt, Boundless request, or BitVM
transaction graph satisfying this document exists yet.

This document defines one public statement from the compressed STWO proof all
the way to the claim-specialized BitVM Groth16 key. It deliberately binds exact
artifact bytes. A receipt produced for a semantically similar rebuild is not a
receipt for this statement.

## Security statement

For `Risc0StwoJournalV1` digest `J`, a valid RISC Zero receipt proves that the
pinned guest consumed exact bytes `(executable, envelope, stwo_proof)` and:

1. `SHA256(executable)`, `SHA256(envelope)`, and `SHA256(stwo_proof)` equal the
   hashes committed by `J`;
2. the executable decodes canonically and its proof program is exactly the
   program exposed in the STWO proof's public memory;
3. the compressed proof decodes under the pinned STWO binary schema and passes
   the pinned STWO verifier under the exact policy below;
4. the proof exposes exactly the 19 public output felts of
   `BarkShinigamiOutputV3`;
5. the first three output felts are exactly `(1, 0, 0)`;
6. the next eight output felts are the exact tagged SHA-256 digest of the
   supplied `BarkSpendEnvelopeV1`;
7. the envelope is canonical, contains the committed nonzero contract nonce,
   and contains the required STWO policy pin; and
8. the remaining eight output felts are canonical `u32` Taproot-sighash words.

The `(1, 0, 0)` prefix means only `transaction_relation_valid = 1`,
`chain_state_verified = 0`, and `operator_take_authorized = 0`. Recursively
proving this output does not authenticate Bitcoin headers, UTXO inclusion, or
CSV maturity and cannot authorize an operator take. A later relation that
proves chain state must use a new output schema and a new RISC Zero image.

## Immutable verifier profile

The guest must pin these implementation identities:

- STWO Cairo commit:
  `b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1`;
- public-segment patch SHA-256:
  `ed5027b67ee3798ef2f1467604816cc5efb8e44cedf6083d329ae8f8e4227a71`;
- Cairo executable schema/compiler: Scarb and Cairo `2.18.0`;
- proof Rust type:
  `CairoProofForRustVerifier<Blake2sMerkleHasher>` at the pinned commit;
- compressed encoding: that commit's `bincode` binary encoding, not JSON,
  Cairo-serde, or extended binary; and
- output schema: `BarkShinigamiOutputV3`, exactly 19 felts.

The binary proof is not self-describing. A schema or dependency change requires
a new guest image and journal version even if a new decoder happens to accept
the old bytes.

The exact `StwoPolicyV1` accepted by the guest is:

| Parameter | Required value |
| --- | ---: |
| Merkle/channel hash | Blake2s |
| channel salt | 0 |
| PCS PoW bits | 26 |
| interaction PoW bits | 24 |
| FRI log blowup factor | 1 |
| FRI queries | 70 |
| FRI last-layer degree log | 0 |
| FRI fold step | 1 |
| lifting log size | none |
| preprocessed trace | canonical |

Its repository policy digest is
`cc48a057589ddbcf51c8458db65640609f21dac3afa485f717089806567dbece`.
The guest must compare the proof's serialized PCS/FRI configuration, channel
salt, and preprocessed-trace variant before verification. Blake2s is selected by
the verifier type. Interaction PoW 24 is a constant in the pinned verifier and
must be covered by the guest image ID. Merely checking the policy digest supplied
by the host is insufficient.

## Guest input

The host writes one bounded `Risc0StwoInputV1` frame:

```text
u32_le version = 1
u32_le executable_len
u8[executable_len] executable_bytes
u32_le envelope_len
u8[envelope_len] envelope_bytes
u64_le proof_len
u8[proof_len] compressed_stwo_proof_bytes
u8[32] expected_risc0_image_id
```

Required limits are `executable_len <= 4 MiB`,
`envelope_len <= 16 MiB`, and `proof_len <= 8 MiB`. Lengths must be minimally
encoded, additions must be checked, and trailing input bytes are forbidden.

`expected_risc0_image_id` solves the build-order problem without creating a
hash cycle: the generic verifier guest is built first, its image ID is placed in
the envelope, and the Cairo executable/proof are then generated. The guest
checks the envelope pin against this input. The receipt verifier must separately
require this value to equal the actual image ID used to verify the RISC Zero
receipt. The Boundless claim also binds that actual image ID.

The guest must hash the byte slices before parsing. It must not accept a path,
URL, host-side parsed object, or decompressed object in place of these bytes.

## Executable-to-proof binding

`SHA256(executable_bytes)` binds the complete Cairo executable artifact,
including metadata and hints, but that hash alone does not show that the STWO
proof ran its bytecode. The guest must also:

1. strictly decode the executable JSON with the pinned Cairo 2.18 schema;
2. reject duplicate keys, unknown representation variants, noncanonical field
   encodings, and trailing data;
3. reproduce the pinned `get_program_and_hints_from_executable` proof-program
   construction for the executable entrypoint;
4. compare every resulting public program-memory word with
   `proof.claim.public_data.public_memory.program`; and
5. compute the STWO program hash with the pinned
   `encode_and_hash_memory_section` algorithm and compare it to the program hash
   committed by the journal.

Hints are witness-generation aids rather than STWO public program memory. The
full executable SHA-256 binds them for reproducibility; the word-for-word public
program comparison is the cryptographic execution binding.

## Public output binding

After successful STWO verification, the guest extracts public output from
`proof.claim.public_data.public_memory.output`. It rejects any output length
other than 19 and rejects any felt that is not canonically representable as a
`u32`.

The canonical word order is:

```text
0  transaction_relation_valid = 1
1  chain_state_verified = 0
2  operator_take_authorized = 0
3..10  statement_digest_0 .. statement_digest_7
11..18 taproot_sighash_0 .. taproot_sighash_7
```

The canonical byte encoding of an output word is `u32_be`. Thus:

```text
statement_digest = concat(output[3].be, ..., output[10].be)
taproot_sighash   = concat(output[11].be, ..., output[18].be)
full_output_bytes = concat(output[0].be, ..., output[18].be)
```

The guest strictly decodes `envelope_bytes`, requires no trailing bytes,
requires a nonzero 32-byte nonce, and recomputes:

```text
statement_digest_expected =
  SHA256(SHA256(tag) || SHA256(tag) || envelope_bytes)
tag = UTF8("BarkZkBitvm/StatementV1")
```

It requires `statement_digest == statement_digest_expected`, the decoded nonce
to equal the nonce committed below, the envelope STWO-policy pin to equal
`StwoPolicyV1`, and the envelope RISC Zero pin to equal
`expected_risc0_image_id`.

## RISC Zero journal

Boundless Blake3-Groth16 requires a 32-byte journal. To bind every requested
field, the journal is not the bare Bark statement digest. It is the tagged
SHA-256 of this fixed-width record:

```text
Risc0StwoBindingV1 =
  u8[8]   magic = "BARKSTO1"
  u16_le  version = 1
  u8[20]  stwo_cairo_git_commit (raw decoded hex)
  u8[32]  public_segment_patch_sha256
  u8[32]  executable_sha256
  u8[32]  stwo_program_hash_be
  u8[32]  stwo_policy_digest
  u64_le  compressed_proof_len
  u8[32]  compressed_proof_sha256
  u32_le  envelope_len
  u8[32]  envelope_sha256
  u8[32]  contract_nonce
  u8[32]  bark_statement_digest
  u16_le  output_schema = 3
  u16_le  output_word_count = 19
  u32_be[3] output_prefix = [1, 0, 0]
  u8[32]  full_output_sha256
  u8[32]  expected_risc0_image_id
```

`stwo_program_hash_be` is the canonical 32-byte big-endian encoding of the
STWO verification output's Stark-field element; left padding is required and
modular aliases are forbidden. `full_output_sha256` is
`SHA256(full_output_bytes)` as defined above.

The sole journal bytes are:

```text
J = SHA256(SHA256(tag) || SHA256(tag) || Risc0StwoBindingV1)
tag = UTF8("BarkZkBitvm/Risc0StwoJournalV1")
```

The guest commits exactly `J` and no ABI prefix, vector length, newline, JSON,
or trailing byte. Host tooling must retain the decoded binding record beside
the receipt so an auditor can recompute `J`.

Binding the exact compressed-proof hash is an evidence/provenance choice, not a
STARK soundness requirement; multiple valid STWO proofs can establish the same
semantic statement. This profile intentionally makes each accepted outer
receipt proof-artifact-specific because exact proof bytes were requested. A
future proof-interchangeable profile must use a new journal version and omit
that field explicitly.

## Boundless claim

Let `IMAGE_ID` be the independently verified RISC Zero image ID and `J` the
exact 32-byte journal above. The only accepted Boundless claim is:

```text
claim = Blake3Groth16ReceiptClaim::ok(IMAGE_ID, J)
C     = claim.digest()
s     = BN254_Fr::from_be_bytes_mod_order(C)
```

The implementation must use the Boundless algorithm and constants pinned at
commit `1c334eb77717089c835652b9483bb79c82fbdafe`. The accepted selectable seal
is exactly `0x62f049f6 || 256-byte-proof`. `RISC0_DEV_MODE`, fake receipts,
pruned claims without the reconstructed value, another selector, another
control root/control ID, a noncanonical scalar, or a journal other than `J` are
hard failures.

The host must verify the original Boundless key with public input `[s]` before
constructing BitVM artifacts. Market request IDs and GitHub provenance are
audit metadata; neither substitutes for local Groth16 verification.

## Claim-specialized BitVM key

For the pinned Boundless key with `gamma_abc_g1 = [IC0, IC1]`, construct:

```text
IC0_fixed = IC0 + s * IC1
VK_C.gamma_abc_g1 = [IC0_fixed, G1_identity]
BitVM runtime public input = [Fr::ZERO]
```

The same proof must verify under both `(VK, [s])` and `(VK_C, [0])`. The
canonical serialized `VK_C` bytes and SHA-256 must be recorded. Official BitVM
commit `7d1ca3660cac08aab62e76f3aa4daec0d7403ecc` must receive `VK_C`, the proof,
and only the zero runtime scalar. Passing the generic key or the actual claim
scalar as a runtime input reopens valid-proof/false-claim substitution.

The graph commitment must hash actual serialized Taproot leaves and
transactions generated from `VK_C`; a manifest field claiming a graph hash is
not sufficient. Recompute the Taproot root after mutating `C`, `J`, `IMAGE_ID`,
or any key coordinate and require it to change.

## Mandatory rejection cases

The guest or the next verifier layer must reject all of the following:

- truncated, oversized, trailing, noncanonical, or wrong-version guest input;
- any executable byte change, executable parse ambiguity, or proof program
  memory differing from the executable-derived program;
- a compressed-proof byte change, wrong binary schema, decompression/resource
  limit breach, malformed field/curve element, or trailing proof bytes;
- any STWO verification failure;
- Blake2sM31, Poseidon252, nonzero channel salt, weaker PoW/FRI parameters,
  another preprocessed trace, or another interaction-PoW verifier build;
- public output not exactly 19 canonical `u32` felts;
- output prefix other than exactly `(1, 0, 0)`;
- statement words not equal to the tagged digest of the exact envelope;
- a zero/different nonce, a different STWO policy pin, or a different RISC Zero
  image pin in the envelope;
- a changed Taproot-sighash word or full-output hash;
- a RISC Zero receipt verified under an image ID different from the binding and
  envelope image ID;
- a journal differing by one byte, an ABI-encoded journal, or a bare statement
  digest used in place of `J`;
- a Boundless selector, claim digest, control identity, journal, or public
  scalar mismatch;
- a Groth16 proof that is merely well-formed but does not verify;
- a generic or differently specialized BitVM key, a nonzero runtime scalar, or
  an identity base placed in the wrong key slot; and
- a graph whose actual serialized bytes do not hash to the recorded graph
  commitment or whose transactions fail Bitcoin Core policy/consensus checks.

## Current artifact audit

The repository currently contains two real, internally verified compressed
STWO proofs. The reload adapter now enforces the exact checked-in
`StwoPolicyV1`, rejects compressed and decompressed trailers, and exposes the
authenticated program hash:

| Fixture | Bytes | SHA-256 |
| --- | ---: | --- |
| `owner_exit_allow.stwo.bin` | 1,117,271 | `3917b6d9fc6b53aef98221a37962034af5109c16036ede06dd16275d94696072` |
| `virtual_cet_guard.stwo.bin` | 1,149,083 | `27918852ae2590972f7401873b9f888a459de6a030c2e1c2bc082512e8cdc87e` |

The dishonest owner fixture produced no proof, as required. GitHub Actions run
`29304103188` reports successful in-process verification for the two positive
proofs. A pinned native verifier also reloads the compressed artifacts, invokes
`verify_cairo`, and records the authenticated outputs in
`proof-evidence/*.verified-output.json`. Both proofs expose STWO program hash
`0xbcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0`
and the required relation-only prefix `(1, 0, 0)`.

They are not yet inputs to this recursion contract. Missing or incompatible
data is:

1. **Exact proved executable bytes are absent from the repository.** The run
   records executable SHA-256
   `5b1e4c7c4a545b5ee34c06d672cfa1d4e3e38b732951c60a65a5dcdaba4b5c22`,
   but the locally present rebuilt executable hashes to
   `c778fef8a5d34c0fad7b3f77b52a1ce94a6bfcb5e0b6939a6de723ee23f0b4e2`.
   Equivalence must not be assumed. Publish the exact run artifact in an
   immutable GitHub release.
2. **The checked-in checksum file omits the executable and argument files.** The
   workflow pinned them, but `proof-evidence/SHA256SUMS.txt` contains only
   proofs, measurements, verified outputs, and the canonical policy receipt.
3. **Windows working-tree bytes are not a canonical artifact encoding.** The
   challenge and CET argument files currently contain CRLF locally while the
   workflow hashes canonical LF bytes. Release hashes must name exact bytes and
   must not depend on checkout conversion.
4. **The proved envelopes pin an unavailable RISC Zero image ID of all zeroes.**
   Final recursive proofs require a nonzero guest image ID and regeneration of
   the Cairo executable, arguments, and STWO proofs under the non-circular build
   order above.
5. **The RISC Zero crate is a fail-closed scaffold, not a guest artifact.**
   `risc0-stwo-verifier/` now strictly parses the complete framed input and Bark
   envelope, performs a typed image-ID handshake, implements the fixed-width
   journal record, and has a native adapter to the real upstream verifier. The
   guest binary does not yet call those complete bindings: `cairo-air` is not
   RV32-compatible, the zkVM build intentionally stops at `compile_error!`, and
   its policy pins remain zero. There is no ELF, image ID, execution receipt, or
   measured cycle/memory bound. `RISC0_RV32_PORT_AUDIT.md` records the real
   target failures: an SDK/toolchain mismatch and host-only `sonic-rs` in the
   unconditional Cairo-AIR graph.
6. **No Boundless receipt exists for this guest/journal.** There is no request,
   real 260-byte selectable seal, reconstructed claim, or locally verified
   claim digest.
7. **No canonical claim-specialized key artifact or actual BitVM graph exists.**
   The versioned outer adapter and manifest now consume the artifact-complete
   journal, algebraically specialize the key, double-verify it with zero BitVM
   runtime input, and hash-check a caller-provided key artifact. Canonical key
   serialization, official chunker output, Taproot root, transactions, Core
   relay results, and watcher-disprove run are still absent.

Until every missing item is produced and independently checked, receipts remain
`not_enforced` and `operator_take_authorized` remains false.
