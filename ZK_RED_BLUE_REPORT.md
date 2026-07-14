# Active ZK/BitVM red-blue report

Date: 2026-07-14

Scope: `BarkSpendEnvelopeV1`, the Shinigami Cairo executable, the
Boundless-Groth16 adapter, and the intended official BitVM chunker boundary.
The generic Bark PR remains unchanged.

## Reproduced red-team attacks

The red team executed the Cairo program, rather than relying on host models.

1. Self-asserted chain heights: changing only `chain_height` and
   `prevout_confirmed_height` from `10000/7984` to the impossible `2016/0`
   previously returned `accepted = 1` with the unchanged owner signature.
2. Recursive verifier substitution: changing the unchecked zero
   `risc0_image_id` to an attacker-selected value previously returned
   `accepted = 1`.
3. Phantom prevout amount: the Cairo relation did not bind the caller-supplied
   amount to the pinned Bark fixture.
4. Valid-proof/false-claim substitution: wire parsing and Groth16 verification
   alone could verify any genuine Boundless claim supplied by the caller.
5. Dynamic BitVM scalar substitution: official BitVM commit
   `7d1ca3660cac08aab62e76f3aa4daec0d7403ecc` fixes the Groth16 key but accepts
   its one public scalar through runtime WOTS assertions. A manifest scalar is
   metadata, not a tapscript constraint.
6. Host authorization modeling: public all-true booleans could construct an
   `OperatorTake` result without proof, Core, or watcher evidence.

The audit also confirmed that the anchor hash does not prove confirmation or
unspentness, the Cairo relation ID is not the executable hash, and no current
graph has passed Bitcoin Core relay/package testing.

## Blue-team fixes

- Cairo output is now split into `transaction_relation_valid`,
  `chain_state_verified`, and `operator_take_authorized`. The latter two are
  hard zero until authenticated chain evidence and a real graph exist.
- Envelope heights are no longer treated as facts by the signed transaction
  relation. The transaction still proves CSV sequence intent.
- The specialized fixture pins the exact 10,000-sat prevout amount, rejects a
  nonzero/unexpected RISC Zero image while the guest is unavailable, and applies
  a conservative 100,000-byte transaction cap.
- The new Boundless adapter follows official Boundless commit
  `1c334eb77717089c835652b9483bb79c82fbdafe`: it enforces canonical BN254
  coordinates, curve and subgroup membership, the pinned verification key, and
  cryptographic Groth16 verification.
- Before proof verification, it recomputes the Blake3-Groth16 claim from the
  independently supplied image ID and exact 32-byte Bark statement journal.
- The expected scalar is folded into `gamma_abc[0]`; `gamma_abc[1]` becomes the
  identity and the official BitVM chunker receives a zero runtime scalar. The
  generated verifier scripts are therefore claim-specific without trusting a
  dynamic assertion value.
- The Boolean enforcement model is test-only and cannot be called by library
  consumers.

## Executed gates

- Rust all-target suite: 73 tests passed (48 library, 3 fixture, 4 adversarial
  corpus, 11 BitVMX, 7 STWO-evidence); zero failed.
- Boundless/BitVM adapter: official reference receipt accepted; proof mutation,
  field alias, unrelated receipt, image mutation, statement mutation, and
  different fixed claim rejected.
- Cairo build: Scarb 2.18 executable built successfully.
- Honest owner and CET executions both emitted the prefix `1, 0, 0`.
- Executable Cairo red gate: false heights stayed `1, 0, 0`; attacker RISC Zero
  image and phantom prevout amount aborted.
- GitHub Actions run
  [`29304103188`](https://github.com/patrickdugan/bark-shinigami-zk-bitvm-demos/actions/runs/29304103188)
  built pinned STWO commit `b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1`.
  The fixed owner-exit and virtual-CET relations produced binary proofs and
  passed STWO's internal verifier. The dishonest output mutation exited 1 at
  Cairo `ASSERT_EQ` and left no proof.
- Owner proof: 1,117,271 bytes, SHA-256
  `3917b6d9fc6b53aef98221a37962034af5109c16036ede06dd16275d94696072`,
  39.54 seconds, 15,188,892 KiB peak RSS.
- CET proof: 1,149,083 bytes, SHA-256
  `27918852ae2590972f7401873b9f888a459de6a030c2e1c2bc082512e8cdc87e`,
  1:41.77, 15,442,736 KiB peak RSS.
- The saved binary proofs were independently decompressed, deserialized and
  reverified with the pinned native `verify_cairo` path. Both authenticate
  program hash
  `0xbcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0`
  and exact 19-felt outputs beginning `1, 0, 0`. A one-byte serialized-proof
  mutation, a compressed-stream trailer, and a bincode-object trailer were
  rejected. The adapter also rejects any policy parameter outside the pinned
  channel-salt/PoW/FRI/preprocessing profile.
- Seven new evidence-boundary tests reject proof tampering, cross-case
  substitution, stale fixed-proof replay against a fresh nonce, incomplete
  checksum coverage, and any attempt to treat checksum provenance as
  cryptographic authorization.

Reproduce the executable red gate with:

```powershell
$scarb = 'D:\_tools\scarb-v2.18.0\scarb-v2.18.0-x86_64-pc-windows-msvc\bin\scarb.exe'
.\test-cairo-adversarial.ps1 -Scarb $scarb
```

## Remaining fail-closed boundary

No operator take is enabled. The inner STWO proving barrier is now cleared for
the two fixed valid fixtures, but the relation still deliberately reports
`chain_state_verified = 0`. It has no authenticated header chain, confirmation,
or UTXO-inclusion proof. A checked-in upstream patch now separates the
Cairo/STWO verifier from host filesystem, Rayon, CLI, compression and JSON
diagnostic dependencies; its dedicated GitHub RV32 cross-compile still has to
pass. The SIMD prover module was already feature-gated and was not the primary
blocker.
After a real Boundless proof, the claim-specialized BitVM scripts still need a
complete bond assertion/disprove/take graph, Bitcoin Core regtest package
acceptance, and a fresh permissionless-watcher disprove. Until all of those
artifacts exist, every receipt remains `not_enforced` and
`operator_take_authorized=false`.

The RISC Zero verifier crate remains a scaffold: its portable/no-std boundary
has 15 passing tests, its exact-nightly native suite has 18, and its adapter
calls the real upstream verifier. The guest binary still has zero policy pins
and remains compile-guarded until the Cairo-AIR verifier-only port passes the
full RV32 guest job.
