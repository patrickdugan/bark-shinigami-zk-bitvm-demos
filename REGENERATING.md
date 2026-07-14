# Regenerating proof artifacts

No current artifact may authorize the operator-take path. The old STWO proofs
authenticate the legacy linear relation and must not be wrapped or relabelled
as an exact Bark/Shinigami proof.

The replacement pipeline is:

```text
BarkSpendEnvelopeV1
  -> Cairo executes Shinigami and emits accepted + statement digest
  -> STWO under exact StwoPolicyV1
  -> RISC Zero guest verifies program, output, policy, and STWO proof
  -> 32-byte statement-digest journal
  -> Boundless Blake3Groth16V0_1
  -> BitVM2 or BitVMX operator-bond dispute
```

The checked-in `cairo-shinigami` program now builds as a Cairo executable,
computes SHA-256 without syscalls, strictly parses the envelope and transaction,
uses Shinigami for BIP341, and uses Garaga for bound BIP340 verification. Honest
owner/CET fixtures emit `accepted = 1`; dishonest amount and oracle-outcome
fixtures abort before an output is produced.

`verify-cairo-tapout.ps1` is retained as a compatibility filename but is now a
positive build gate. The generated fixture arguments and proofs remain ignored
because they must be regenerated from pinned sources.

Every artifact must use an immutable GitHub release and be recorded in
`Bitvm2ClaimManifestV1` with its exact repository/commit, tag, filename, URL,
byte length, SHA-256, statement, image, Boundless request/scalar, graph hash,
Bitcoin transaction IDs, and Core 31.1 relay results.

Boundless requests are testnet-only (Sepolia or Base Sepolia). Keep the request
wallet key out of the repository, logs, shell history, and chat.
`RISC0_DEV_MODE` must be unset. Mainnet and fake/dev receipts are hard failures.
