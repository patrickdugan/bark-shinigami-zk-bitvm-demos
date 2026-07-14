# Bark / Shinigami / ZK-BitVM showcase

This is the showcase companion to the generic Bark adapter in
[ark-bitcoin/bark#36](https://github.com/ark-bitcoin/bark/pull/36). The Bark PR
remains a generic Rust-to-Cairo claim encoder; proof-market and BitVM code lives
here. All publication and provenance rules in this showcase are GitHub-only.

The implementation is fail-closed. It does **not** claim mainnet readiness or
on-chain ZK enforcement. Real STWO proofs now exist for the two fixed valid
fixtures, and the dishonest fixture is rejected before proof generation. Those
inner proofs do not authenticate Bitcoin chain state and are not recursively
verified by RISC Zero, Boundless, or Bitcoin. A real Boundless receipt and a
relay-tested BitVM transaction graph do not yet exist, so every demo still
reports `not_enforced` and never authorizes the operator-take path.

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
- A STWO-executable Shinigami relation with Alexandria's pinned pure-Cairo
  SHA-256, strict envelope and canonical Bitcoin transaction parsers,
  Shinigami's BIP341 sighash, and Garaga's pure-Cairo secp256k1 verifier. It
  emits `transaction_relation_valid = 1` only after binding the owner signature
  to the exact Bark spend; the CET case additionally verifies the pinned oracle
  announcement and attestation and binds every payout to a transaction output.
  It separately emits `chain_state_verified = 0` and
  `operator_take_authorized = 0`: envelope height integers are not Bitcoin
  header/UTXO proofs.
- Fixture-specific Bark policy pins for regtest genesis, VTXO/anchor hashes,
  owner leaf/control block, Shinigami relation ID, and STWO policy. This is a
  showcase relation for the checked-in Bark vector, not a generic replacement
  for Shinigami's full Bitcoin Script engine.
- Exact `StwoPolicyV1` pinning: Blake2s, channel salt 0, PoW 26, interaction
  PoW 24, blowup 1, 70 queries, last-layer degree 0, fold step 1, no lifting
  log size, and the canonical preprocessed trace variant. Its canonical record
  is checked in under `proof-evidence/`.
- Reproducible binary STWO proof vectors for the fixed owner-exit and virtual
  CET fixtures. GitHub Actions built STWO commit `b1acf8bf...`, proved both,
  ran its internal verifier, and required the dishonest output mutation to
  fail without emitting a proof. The proofs and measurements are checked in
  under [`proof-evidence/`](proof-evidence/README.md).
- A pinned binary-proof reload verifier that deserializes the saved artifacts,
  invokes STWO's real `verify_cairo`, records the authenticated program hash
  and exact 19-felt outputs, enforces every policy parameter, and rejects a
  mutated proof, a compressed-stream trailer, and a bincode-object trailer.
- A fail-closed [`risc0-stwo-verifier/`](risc0-stwo-verifier/README.md)
  scaffold and exact [`RISC0_STWO_DESIGN.md`](RISC0_STWO_DESIGN.md) recursion
  contract. It strictly parses the complete guest frame and Bark envelope,
  binds the two image IDs in one operation, and encodes the exact 378-byte
  artifact journal. The native adapter uses the real upstream verifier; the
  checked-in RV32 guest remains guarded while a reviewable verifier-only
  `stwo-cairo` patch and dedicated GitHub cross-compile job test the real
  `verify_cairo` path. The reproduced target failures and exact port are in
  [`RISC0_RV32_PORT_AUDIT.md`](RISC0_RV32_PORT_AUDIT.md).
- Strict Boundless `Blake3Groth16V0_1` parsing: selector `62f049f6`, 32-byte
  journal, 256-byte raw proof, one canonical BN254 public scalar, and
  claim-specific BitVM2 GitHub provenance checks.
- Versioned cryptographic Boundless-to-BitVM adapters pinned to Boundless commit
  `1c334eb77717089c835652b9483bb79c82fbdafe` and official BitVM commit
  `7d1ca3660cac08aab62e76f3aa4daec0d7403ecc`. The artifact-complete profile
  recomputes the tagged journal from the exact executable, envelope, STWO proof,
  program, policy, output, nonce, and image bindings; strictly decodes every
  proof coordinate; verifies Groth16; and folds the claim scalar into a
  claim-specialized verification key before the official BitVM chunker sees it.
- Fail-closed BitVMX gates for the 256-byte outer proof, including resource,
  standardness, and fresh permissionless-watcher observations.
- A bond/dispute state-machine model with regtest/signet deadlines, whole-graph
  fee reserve, watcher reward, and an all-watchers-offline failure control.

## Three use cases

`owner_exit_allow` constructs and verifies a valid Bark pubkey-VTXO owner exit.
Its fixed reference vector has a verified STWO proof. Each live run uses a fresh
nonce and therefore needs a new proof; neither can authorize a bond take
without authenticated chain state, the outer proof, and the BitVM graph.

`owner_exit_challenge` changes the signed output amount without resigning. The
statement digest changes and the Taproot signature check rejects the dishonest
operator assertion. The remote STWO gate confirms that Cairo aborts and leaves
no proof artifact.

`virtual_cet_guard` constructs a valid Bark owner spend whose outputs are bound
to the test oracle event, outcome, signatures, and payout table. Mutating any
of those inputs rejects it. Its fixed reference vector also has a verified STWO
proof.

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
$scarb = 'D:\_tools\scarb-v2.18.0\scarb-v2.18.0-x86_64-pc-windows-msvc\bin\scarb.exe'
.\test-cairo-adversarial.ps1 -Scarb $scarb
```

The suite includes 10,000 seeded statement mutations per demo, strict codec
tests, the known legacy linear collisions, Boundless selector/length/scalar and
replay attacks, GitHub provenance attacks, BitVMX resource/watcher gates, and
bond/timing/offline-watcher controls. The older UTXORef trusted-cosigner
exercise remains under `run-red-blue.ps1` as historical attack evidence only;
it is not the ZK-BitVM security boundary.

The current executable-Cairo and outer-boundary findings are recorded in
[`ZK_RED_BLUE_REPORT.md`](ZK_RED_BLUE_REPORT.md).

Before any positive signet label, the remaining gates are:

1. add authenticated Bitcoin header-chain, confirmation, and UTXO-inclusion
   evidence to the proven relation;
2. port the Cairo/STWO verifier to a verifier-only RISC Zero RV32IM guest and
   build it with dev receipts disabled (upstream Cairo verifier dependencies are
   not guest-compatible as-is);
3. obtain and verify a real Boundless Blake3Groth16 receipt on Sepolia;
4. build BitVM2 and BitVMX candidates and require every transaction to pass
   Bitcoin Core 31.1 consensus and `testmempoolaccept`;
5. exercise a fresh permissionless watcher slash on regtest and public signet.

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
