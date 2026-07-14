# RISC Zero/STWO boundary red-team notes

Date: 2026-07-14

Scope: malicious host input, stale RISC Zero image identifiers,
proof/executable/envelope substitution, journal serialization ambiguity, and
authorization-prefix confusion. These notes distinguish a tested rejection
from a design requirement that the current guest cannot yet exercise.

## Executed attacks

| Attack | Expected result | Current result |
| --- | --- | --- |
| Interpret only output word 0 as a generic success/authorization bit | reject the interpretation; preserve the independent `1/0/0` meanings | guarded by `relation_only_prefix_cannot_be_confused_with_authorization` |
| Supply 18 or 20 output words | reject | guarded by `output_framing_and_word_byte_order_are_not_ambiguous` |
| Decode digest words as little-endian bytes | reject the alternate interpretation | guarded by `output_framing_and_word_byte_order_are_not_ambiguous` |
| Append bytes after the first bzip2 stream | reject | exposed during this review; guarded by `rejects_bytes_after_the_compressed_proof_stream` after strict-consumption repair |
| Append bytes after the bincode proof object and recompress | reject | exposed during this review; guarded by `rejects_trailing_bytes_inside_the_decompressed_proof` after strict-bincode repair |

The trailing-object issue was concrete: bincode 1.3.3's free
`bincode::deserialize` function uses `allow_trailing_bytes`, and a single-stream
`BzDecoder` can finish before the end of the attacker-controlled input. A proof
hash in a later binding record makes variants distinguishable, but it does not
make a noncanonical parser compliant with the contract. Both layers need exact
consumption.

## Fail-closed gaps that remain untestable

The current `bark-stwo-guest` reads only one host-provided `Vec<u8>` containing
the compressed proof. It does not yet implement `Risc0StwoInputV1`. Therefore
the following mandatory rejection cases are design claims, not executable
security properties:

- wrong-version, nonminimal, truncated, oversized, overflowed, or trailing
  guest-input frames;
- executable byte substitution or executable-derived program memory differing
  from the STWO proof's authenticated public program;
- envelope substitution, duplicate/unknown envelope fields, trailing envelope
  bytes, a stale or zero nonce, and disagreement between envelope and output
  statement digests;
- disagreement among the image ID in the guest input, the image ID in the
  envelope, the actual image ID used to verify the RISC Zero receipt, and the
  image ID used in the Boundless claim; and
- exact fixed-width `Risc0StwoBindingV1` journal emission by the guest.

The existing guest still has zero program/policy pins and emits the old bare
statement digest only after a hypothetical `1/1/1` authorization output. The
artifact-complete profile instead commits a relation-only `1/0/0` prefix. These
must remain separate typed/versioned paths: neither `transaction_relation_valid`
nor successful STWO verification authorizes an operator take.

The in-progress boundary code also has two independently implemented public
types named `Risc0StwoBindingV1`: one in this nested crate and one in the root
outer adapter. The nested encoder does not validate pins or the output prefix;
the outer encoder does. Their identical 378-byte layout is therefore a review
assumption until a shared golden vector proves byte-for-byte and journal-digest
equivalence. Consolidating the codec is preferable. At minimum, the same test
vector must be consumed by both crates.

Similarly, `Risc0StwoInputV1::decode` and `BarkEnvelopeBindingV1::decode` return
their image identifiers without establishing equality. Parsing both objects is
not the security check. The eventual guest needs one typed cross-binding
operation that rejects input/envelope image disagreement, policy disagreement,
and output/envelope statement disagreement before it can construct the journal.

## Required acceptance gate

Do not describe the recursion boundary as enforced until one test drives the
real guest with exact `(executable, envelope, compressed proof, image ID)` bytes,
verifies its RISC Zero receipt under the independently measured image ID, and
then proves that one-byte mutations of each artifact and every length/version
field fail. The same receipt must be rejected when paired with a stale image ID,
a bare statement journal, an ABI/vector-prefixed journal, or an all-true output
prefix.
