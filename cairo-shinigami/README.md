# Shinigami relation build gate

This source pins Shinigami and invokes its raw-transaction validator. It also
constructs the BIP340-style tagged `BarkZkBitvm/StatementV1` digest.

It deliberately returns `accepted = 0` because its canonical envelope parser
is incomplete. In addition, the executable currently cannot be produced:
Scarb/Cairo 2.18 rejects Shinigami's SHA-256 dependency with:

```text
The function is using libfunc `sha256_process_block_syscall`.
Syscalls are not supported in `#[executable]`.
```

Run `..\verify-cairo-tapout.ps1` to assert this exact reviewed failure. A future
change must implement a STWO-compatible software SHA-256 path and the complete
envelope parser, then replace this negative gate with native/Cairo differential
tests before changing `accepted`.
