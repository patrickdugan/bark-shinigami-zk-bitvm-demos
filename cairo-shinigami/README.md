# Shinigami STWO relation

This package is an executable Cairo relation for the three showcase fixtures.
It pins the STWO-compatible Shinigami fork at
`565d7c7375bd090047137da702b2bfdcd48ec58d` and Garaga at
`0e986ba5133c16a30ac86a7cd07c9551787d0e91`.

An accepting execution proves all of the following inside Cairo:

- the exact canonical `BarkSpendEnvelopeV1` decoder consumed every byte;
- network, Bark fixture VTXO/anchor, relation, and STWO policy pins match;
- a canonical one-input SegWit v1 transaction spends the pinned outpoint;
- amounts, outputs, CSV maturity, witness shape, owner script, and control block
  satisfy the specialized showcase policy;
- Shinigami computes the same BIP341 script-path sighash as rust-bitcoin;
- Garaga verifies the owner BIP340 signature against that exact digest;
- for a virtual CET, the pinned oracle signs both the payout announcement and
  realized outcome, and the payout table exactly equals the Bitcoin outputs.

The relation uses constrained off-chain MSM hints. `generate-garaga-arguments.py`
creates them; they are not trusted because Garaga checks them in Cairo.

This package does not by itself authorize a Bitcoin output. A verified STWO
proof, recursive outer proof, and relay-tested BitVM dispute graph are separate
mandatory gates.
