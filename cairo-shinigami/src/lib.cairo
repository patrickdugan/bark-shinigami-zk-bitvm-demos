use core::sha256::compute_sha256_byte_array;
use shinigami_engine::flags;
use shinigami_engine::transaction::{EngineInternalTransactionTrait, UTXO};
use shinigami_tests::validate;
use shinigami_utils::bytecode::hex_to_bytecode;

// This program deliberately fails closed. It already invokes Shinigami over
// the exact raw transaction and prevouts and computes the statement digest,
// but `accepted` remains zero until the canonical BarkSpendEnvelopeV1 parser
// is implemented in Cairo and proves that those execution inputs are the
// fields committed by `statement_envelope`.
//
// Returning zero is a security feature: no STWO/RISC0/Boundless receipt built
// from this intermediate relation can authorize the operator-take path.

#[derive(Clone, Drop, Serde)]
pub struct UtxoHintV1 {
    pub amount: i64,
    pub pubkey_script: ByteArray,
    pub block_height: u32,
}

#[derive(Drop, Serde)]
pub struct BarkShinigamiInputV1 {
    pub raw_transaction: ByteArray,
    pub utxo_hints: Array<UtxoHintV1>,
    pub flags: ByteArray,
    pub txid: u256,
    pub statement_envelope: ByteArray,
}

#[derive(Copy, Drop, Serde)]
pub struct BarkShinigamiOutputV1 {
    pub accepted: u32,
    pub statement_digest_0: u32,
    pub statement_digest_1: u32,
    pub statement_digest_2: u32,
    pub statement_digest_3: u32,
    pub statement_digest_4: u32,
    pub statement_digest_5: u32,
    pub statement_digest_6: u32,
    pub statement_digest_7: u32,
}

#[executable]
fn main(mut input: BarkShinigamiInputV1) -> BarkShinigamiOutputV1 {
    let script_flags = flags::parse_flags(input.flags);
    let mut utxo_hints: Array<UTXO> = array![];
    for hint in input.utxo_hints.span() {
        utxo_hints.append(
            UTXO {
                amount: *hint.amount,
                pubkey_script: hint.pubkey_script.clone(),
                block_height: *hint.block_height,
            },
        );
    };
    let transaction = EngineInternalTransactionTrait::deserialize(
        input.raw_transaction, input.txid, utxo_hints,
    );
    let shinigami_result = validate::validate_transaction(@transaction, script_flags);
    // BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
    // da7434...876c is SHA256("BarkZkBitvm/StatementV1").
    let mut tagged_preimage = hex_to_bytecode(
        @"0xda743480fe6899b1444382262314a714ca29fb9c204f57b82e3e840283c3876cda743480fe6899b1444382262314a714ca29fb9c204f57b82e3e840283c3876c",
    );
    tagged_preimage.append(@input.statement_envelope);
    let [d0, d1, d2, d3, d4, d5, d6, d7] = compute_sha256_byte_array(@tagged_preimage);

    // Exercise the real engine in both branches while refusing authorization
    // until the envelope-to-engine field linkage exists inside this program.
    let accepted = match shinigami_result {
        Result::Ok(_) => 0,
        Result::Err(_) => 0,
    };

    BarkShinigamiOutputV1 {
        accepted,
        statement_digest_0: d0,
        statement_digest_1: d1,
        statement_digest_2: d2,
        statement_digest_3: d3,
        statement_digest_4: d4,
        statement_digest_5: d5,
        statement_digest_6: d6,
        statement_digest_7: d7,
    }
}
