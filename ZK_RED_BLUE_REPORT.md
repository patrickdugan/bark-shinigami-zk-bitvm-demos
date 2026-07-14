# Active ZK/BitVM red-blue report

Date: 2026-07-13

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

- Rust all-target suite: 56 tests passed (38 library, 3 fixture, 4 adversarial
  corpus, 11 BitVMX); zero failed.
- Boundless/BitVM adapter: official reference receipt accepted; proof mutation,
  field alias, unrelated receipt, image mutation, statement mutation, and
  different fixed claim rejected.
- Cairo build: Scarb 2.18 executable built successfully.
- Honest owner and CET executions both emitted the prefix `1, 0, 0`.
- Executable Cairo red gate: false heights stayed `1, 0, 0`; attacker RISC Zero
  image and phantom prevout amount aborted.

Reproduce the executable red gate with:

```powershell
$scarb = 'D:\_tools\scarb-v2.18.0\scarb-v2.18.0-x86_64-pc-windows-msvc\bin\scarb.exe'
.\test-cairo-adversarial.ps1 -Scarb $scarb
```

## Remaining fail-closed boundary

No operator take is enabled. A real remote STWO proof still needs a 64-128 GB
CPU host. The Cairo/STWO verifier must then be ported to a verifier-only RISC
Zero RV32IM guest; upstream Cairo verifier crates currently include `std`,
Rayon, portable SIMD, filesystem, and prover-only dependencies. After a real
Boundless proof, the claim-specialized BitVM scripts still need a complete
bond assertion/disprove/take graph, Bitcoin Core regtest package acceptance,
and a fresh permissionless-watcher disprove. Until all of those artifacts
exist, every receipt remains `not_enforced` and `operator_take_authorized=false`.
