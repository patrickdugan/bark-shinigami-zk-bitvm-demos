# Bark / Shinigami / ZK-BitVM showcase

This is the showcase companion to the generic Bark adapter in
[ark-bitcoin/bark#36](https://github.com/ark-bitcoin/bark/pull/36). The Bark PR
remains a generic Rust-to-Cairo claim encoder; proof-market and BitVM code lives
here. All publication and provenance rules in this showcase are GitHub-only.

The implementation is fail-closed. It does **not** claim mainnet readiness or
on-chain ZK enforcement. A real Boundless receipt and a relay-tested BitVM
transaction graph do not yet exist, so every demo reports `not_enforced` and
never authorizes the operator-take path.

## What is implemented

- `BarkSpendEnvelopeV1`, a strict canonical binary statement binding network
  genesis, fresh nonce, Bark `VtxoId`, exact `ProtocolEncoding(VTXO)`, anchor and
  spend transactions, ordered prevouts, input/height/CSV context, script flags,
  role evidence, and proof-program pins. Its identity is the BIP340-style
  tagged SHA-256 `BarkZkBitvm/StatementV1`.
- Real signed Bark fixture spends. Host preflight validates the Bark VTXO,
  Taproot owner script/control block, BIP341 signature, CSV sequence, prevout,
  amount, and transaction shape. Height/confirmation context remains a
  synthetic fixture until Core headers/inclusion are independently verified;
  host preflight is not a replacement for the mandatory Core/Shinigami gate.
- A virtual-CET test policy with a fixed test oracle/event, BIP340
  announcement/attestation, outcome, payout table, and exact output matching.
  The fixture oracle secret is intentionally public and is not a production
  trust root.
- A Shinigami-invoking Cairo relation scaffold. It executes Shinigami and
  computes the same tagged statement digest, but deliberately emits
  `accepted = 0` until a strict envelope parser links every engine input inside
  Cairo. Scarb currently also rejects Shinigami's
  `sha256_process_block_syscall`, because syscalls are unsupported in Cairo
  executables. `verify-cairo-tapout.ps1` asserts that exact reviewed blocker.
- Exact `StwoPolicyV1` pinning: Blake2s, PoW 26, interaction PoW 24, blowup 1,
  70 queries, last-layer degree 0, fold step 1, no lifting log size, and the
  canonical preprocessed trace variant.
- Strict Boundless `Blake3Groth16V0_1` parsing: selector `62f049f6`, 32-byte
  journal, 256-byte raw proof, one canonical BN254 public scalar, and
  claim-specific BitVM2 GitHub provenance checks.
- Fail-closed BitVMX gates for the 256-byte outer proof, including resource,
  standardness, and fresh permissionless-watcher observations.
- A bond/dispute state-machine model with regtest/signet deadlines, whole-graph
  fee reserve, watcher reward, and an all-watchers-offline failure control.

## Three use cases

`owner_exit_allow` constructs and verifies a valid Bark pubkey-VTXO owner exit.
It can enter the proof pipeline, but cannot authorize a bond take without the
real outer proof and BitVM graph.

`owner_exit_challenge` changes the signed output amount without resigning. The
statement digest changes and the Taproot signature check rejects the dishonest
operator assertion.

`virtual_cet_guard` constructs a valid Bark owner spend whose outputs are bound
to the test oracle event, outcome, signatures, and payout table. Mutating any
of those inputs rejects it.

Run from this directory:

```powershell
$env:CARGO_TARGET_DIR = 'D:\cargo-target\bark-zk-bitvm-showcase'
cargo run --bin owner_exit_allow
cargo run --bin owner_exit_challenge
cargo run --bin virtual_cet_guard
```

## Tests and red/blue gates

```powershell
$env:CARGO_TARGET_DIR = 'D:\cargo-target\bark-zk-bitvm-showcase'
$env:TEMP = 'D:\cargo-target\tmp'
$env:TMP = $env:TEMP
cargo test --all-targets
```

The suite includes 10,000 seeded statement mutations per demo, strict codec
tests, the known legacy linear collisions, Boundless selector/length/scalar and
replay attacks, GitHub provenance attacks, BitVMX resource/watcher gates, and
bond/timing/offline-watcher controls. The older UTXORef trusted-cosigner
exercise remains under `run-red-blue.ps1` as historical attack evidence only;
it is not the ZK-BitVM security boundary.

Before any positive signet label, the remaining gates are:

1. port Shinigami's SHA-256 path to STWO-compatible software, implement the
   strict Cairo envelope parser, and remove forced `accepted = 0` only after
   native/Cairo differential agreement;
2. generate the new STWO proof under exactly `StwoPolicyV1`;
3. build the RISC Zero STWO-verifier guest with dev receipts disabled;
4. obtain and verify a real Boundless Blake3Groth16 receipt on Sepolia;
5. build BitVM2 and BitVMX candidates and require every transaction to pass
   Bitcoin Core 31.1 consensus and `testmempoolaccept`;
6. exercise a fresh permissionless watcher slash on regtest and public signet.

If an enforcement backend misses its relay/resource/watcher gates, it is a
tap-out for that backend. If both miss, the showcase publishes no enforcement
claim. There is no automatic fallback to fake receipts, Prime Intellect, or
mainnet.

## Security assumptions

BitVM protects an operator bond/reimbursement output, not arbitrary VTXO
validity. Bark's owner exit stays independent. A completed deployment would
still require one honest setup participant, an honest online watcher, data
availability, Bitcoin liveness, and RISC Zero/Groth16 trust assumptions. The
official BitVM and BitVMX implementations are experimental.
