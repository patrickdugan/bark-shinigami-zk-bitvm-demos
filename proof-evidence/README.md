# Fixed-fixture STWO proof evidence

GitHub Actions run
[`29304103188`](https://github.com/patrickdugan/bark-shinigami-zk-bitvm-demos/actions/runs/29304103188)
built and ran STWO Cairo at commit
`b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1`. The workflow applied the checked-in
public-segment patch, pinned every input by SHA-256, generated compressed binary
proofs, and passed `run_and_prove --verify` for both valid fixtures.

The checked-in compressed artifacts were also reloaded with the pinned native
`CairoProofForRustVerifier<Blake2sMerkleHasher>` path and independently passed
`verify_cairo`. Both authenticate STWO program hash
`0xbcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0`
and exact 19-felt outputs recorded in the `*.verified-output.json` files. A
one-byte mutation of the serialized owner proof, bytes appended after its
bzip2 stream, and bytes appended after its bincode object are rejected. The
machine-readable `stwo-policy-v1.json` records the exact policy enforced by the
reload verifier.

The dishonest owner-exit fixture changes the output amount without resigning.
It exited 1 at Cairo `ASSERT_EQ` in 0.94 seconds and the workflow asserted that
no nonempty proof was left behind.

| Fixture | Result | Proof SHA-256 | Wall time | Peak RSS |
| --- | --- | --- | ---: | ---: |
| `owner_exit_allow` | proved and internally verified | `3917b6d9fc6b53aef98221a37962034af5109c16036ede06dd16275d94696072` | 39.54 s | 15,188,892 KiB |
| `owner_exit_challenge` | rejected before proof | none | 0.94 s | 66,556 KiB |
| `virtual_cet_guard` | proved and internally verified | `27918852ae2590972f7401873b9f888a459de6a030c2e1c2bc082512e8cdc87e` | 101.77 s | 15,442,736 KiB |

The executable SHA-256 is
`5b1e4c7c4a545b5ee34c06d672cfa1d4e3e38b732951c60a65a5dcdaba4b5c22`.
The exact proof inputs are under [`proof-inputs/`](../proof-inputs/).

These are deterministic reference fixtures, not reusable receipts for new demo
runs: each live demo creates a fresh contract nonce and therefore a new
statement. They are inner STWO proofs only. They do not prove Bitcoin headers,
confirmation, or UTXO inclusion; they are not RISC Zero/Boundless receipts; and
they are not enforced by a BitVM transaction graph. Accordingly they cannot
authorize an operator take.
