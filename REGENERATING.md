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

The checked-in `cairo-shinigami` program is intentionally incomplete and emits
`accepted = 0`. It also hits the reviewed `sha256_process_block_syscall` build
tap-out because Cairo executables do not support syscalls. Run
`verify-cairo-tapout.ps1` to reproduce that exact failure. A software SHA-256
port and the complete envelope parser are prerequisites for a positive proof.

Every artifact must use an immutable GitHub release and be recorded in
`Bitvm2ClaimManifestV1` with its exact repository/commit, tag, filename, URL,
byte length, SHA-256, statement, image, Boundless request/scalar, graph hash,
Bitcoin transaction IDs, and Core 31.1 relay results.

Boundless requests are testnet-only (Sepolia or Base Sepolia). Keep the request
wallet key out of the repository, logs, shell history, and chat.
`RISC0_DEV_MODE` must be unset. Mainnet and fake/dev receipts are hard failures.
