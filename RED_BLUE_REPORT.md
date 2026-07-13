# Legacy dishonest-operator red/blue report

> Historical test-double evidence only. This report predates
> `BarkSpendEnvelopeV1` and does not demonstrate ZK-verified BitVM enforcement.
> The active v3 demos fail closed until a real Boundless receipt and relay-tested
> BitVM graph exist.

Date: 2026-07-13

Scope: the standalone Bark/Shinigami/STWO/UTXORef showcase. The generic Bark
encoder PR was deliberately left unchanged by this exercise.

## Method

Independent agents took red-team, blue-team, and integration-audit roles. The
final harness runs both sides against an exact-file sparse checkout of UTXORef
at `13f43d7f7bbddf10fa507770645ef05e49189441`. The runner rejects drift in its
reviewed top-level, collision, transcript-container, and per-case schemas;
duplicate cases; missing Boolean fields; unexpected stderr; known sensitive-key
field names or PEM material; and any change to the reviewed source-closure digest
`3d3c65dd4f1f206357baf0aeea6aa1c0b85a5f2a2a6656ab04c120fe28450899`.
A separate audit program independently re-hashes the public artifact bytes,
re-pins the exact UTXORef source closure, recomputes the
policy/bundle/attestation digests, verifies the Ed25519 attestation, cross-links
it to the signed state marks, and reruns graph verification from the saved
transcript.

## Red-team results

The dishonest operator successfully reproduced the primary threat:

- all three external facts in the signed checkpoint were false;
- the operator disclosed all five public trace wires as `1`;
- the public trace and full UTXORef graph verified;
- fraud count was zero and no input-disprove witness was constructible; and
- because the vulnerable demo operator controlled both keys, a co-signed
  settlement witness was ready.

The deterministic vulnerable graph hash is
`f26ff80f5405debdc19e2d765c5fc2ad1a38e1ab99c4ca9216398b59998cbdfa`.

The red team also reproduced four exact collisions in the current linear Cairo
binding:

| Claim | Original | Colliding change | Binding result |
|---|---|---|---|
| generic owner exit | amount `100000`, delay `144` | amount `100001`, delay `113` | unchanged |
| generic owner exit | settlement high/low limbs | high `+17`, low `-31` | unchanged |
| Bark-native owner exit | amount `10000`, delay `2016` | amount `10001`, delay `1985` | unchanged |
| Bark-native owner exit | settlement high/low limbs | high `+17`, low `-31` | unchanged |

Every colliding claim has a different canonical input SHA-256 while the Cairo
binding check still passes. The public `[ok, role, binding]` output is therefore
not a collision-resistant commitment to all 25 claim fields.

## Blue-team tightening

The hardened showcase freezes an independent challenger/cosigner key, state
signer, operator key, exact circuit, expected inputs, UTXORef source closure,
and CSV policy before its simulated funding decision. A separately keyed
verifier test double hashes supplied canonical claim/proof/Shinigami artifact
bytes, derives facts from those hashes, and signs the policy/network/case/nonce
context plus the complete bundle. Operator disclosures, claimed hashes, and the
operator's case label do not determine those facts. The trusted gate re-hashes
the bytes, verifies the artifact-bound attestation, and issues the challenger
BIP340 signature only when its exact result is all true.

All twelve matrix cases passed:

| Case | Result |
|---|---|
| honest independently verified facts | graph verified; cosignature and simulated admission issued |
| generic linear-binding collision | unchanged algebraic binding, but full claim digest mismatch caught |
| Bark-native linear-binding collision | unchanged algebraic binding, but full claim digest mismatch caught |
| generic settlement-limb collision | unchanged algebraic binding, but full claim digest mismatch caught |
| Bark-native settlement-limb collision | unchanged algebraic binding, but full claim digest mismatch caught |
| false facts disclosed as all ones | caught; no BitVM disprove exists; cosignature and admission withheld |
| false proof artifact relabeled as honest case | signed artifact facts remain false; cosignature and admission withheld |
| false artifact bytes with claimed honest hashes | independently derived hashes differ; cosignature and admission withheld |
| false fact disclosed as zero | caught by input-binding evidence; cosignature withheld |
| rogue challenger-key substitution | rejected against the pre-pinned policy |
| self-allowlisted state signer | self-trusted graph works only under rogue policy; fixed policy rejects it |
| internally valid policy substitution | self-hash is valid but does not match the pre-pinned funding policy |

The successful control emits a sanitized receipt and full public transcript
containing the graph hash,
assertion tree root, settlement sighash, both public BIP340 signatures, the
synthetic assertion outpoint, and a fresh UTXORef graph-verification result.
The reviewed output schemas expose no private scalars; the runner recursively
rejects known secret/private-key field names and private-key PEM material.

## What this does and does not enforce

This closes the showcased false-Boolean admission path only under a separately
trusted verifier/cosigner policy. It does not turn the current assertion graph
into trustless ZK enforcement:

- the independent verifier is a same-process test double over small synthetic
  bytes, not trusted artifact storage or a service that actually reruns the
  pinned STWO and Shinigami artifacts;
- accepted-attestation nonce consumption is kept only in memory;
- UTXORef's demo finalizer currently receives both signing secrets in one
  process instead of accepting an operator-signed prepared transaction;
- the assertion outpoint and funding decision are synthetic, and nothing is
  funded or broadcast;
- UTXORef's JavaScript verifies the Taproot path and BIP340 signatures; this is
  not Bitcoin consensus validation and verifies neither STWO, Shinigami, nor
  the external facts;
- the operator emergency-recovery path still becomes available after 144
  blocks; and
- the collision-prone Cairo binding itself is documented, not fixed by this
  showcase-only gate.

A production design needs a collision-resistant public commitment, actual
pinned STWO/Shinigami recomputation inside an isolated signer, non-custodial
prepare/finalize signing, persisted pre-funding policy state, real outpoint and
chain validation, and funded fee/race testing. Trustless enforcement instead
requires placing the relevant verifier logic in the BitVM dispute circuit.

## Reproduce

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-red-blue.ps1 `
  -UtxoRefRepo C:\projects\UTXORef\UTXO-Ref
```

The runner writes `red-team.json`, `blue-team.json`,
`blue-evidence-audit.json`, and `summary.json` to a unique directory under
`D:\cargo-target\bark-bitvm-showcase\red-blue-runs` by default. A successful
run requires the exploit and all four collisions to reproduce, all twelve
blue-team cases to satisfy their reviewed semantics, and the independent audit
to pass.

Portable LF-normalized sanitized evidence is included under
[`evidence/red-blue`](evidence/red-blue). Its `summary.json` records the source,
runtime, and evidence hashes. The result contains one honest control, eleven
caught attack rows, twelve passed rows, and zero attack cosignatures or funding
authorizations.
