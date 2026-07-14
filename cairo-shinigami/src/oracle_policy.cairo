use garaga::signatures::schnorr::SchnorrSignatureWithHint;
use shinigami_engine::hash_tag::{HashTag, tagged_hash};
use shinigami_engine::transaction::EngineTransactionOutput;
use shinigami_utils::bytecode::hex_to_bytecode;
use crate::bip340::verify_bound_schnorr;
use crate::envelope::VirtualCetEvidenceV1;

/// Verify that the pinned oracle signed both the announced payout table and the
/// realized outcome, and that the same payout table is the exact Bitcoin spend.
pub fn verify_virtual_cet(
    evidence: VirtualCetEvidenceV1,
    outputs: @Array<EngineTransactionOutput>,
    announcement_witness: SchnorrSignatureWithHint,
    attestation_witness: SchnorrSignatureWithHint,
) {
    let expected_event = tagged_hash(
        HashTag::Other("BarkZkBitvm/OracleEventV1"), @"btc-usd-2026-07-13",
    );
    assert(evidence.event_id == u256_to_bytes(expected_event), 'oracle event mismatch');
    assert(
        evidence
            .oracle_xonly == hex_to_bytecode(
                @"0x1ec816ce4b1d26fbc4331d097287e77fc06374392cc5215a80fd07940cff0d1f",
            ),
        'oracle trust root mismatch',
    );
    assert(evidence.payouts.len() == outputs.len(), 'CET payout count mismatch');

    let mut encoded_payouts: ByteArray = "";
    append_u32_le(ref encoded_payouts, evidence.payouts.len().try_into().unwrap());
    let mut index: usize = 0;
    while index < evidence.payouts.len() {
        let payout = evidence.payouts.at(index);
        let output = outputs.at(index);
        assert(*payout.amount_sats <= 0x7fffffffffffffff, 'CET payout range');
        assert((*payout.amount_sats).try_into().unwrap() == *output.value, 'CET amount mismatch');
        assert(payout.script_pubkey == output.publickey_script, 'CET script mismatch');
        append_u64_le(ref encoded_payouts, *payout.amount_sats);
        append_u32_le(ref encoded_payouts, payout.script_pubkey.len().try_into().unwrap());
        encoded_payouts.append(payout.script_pubkey);
        index += 1;
    }

    let mut announcement_message = evidence.event_id.clone();
    announcement_message.append(@encoded_payouts);
    let announcement_digest = tagged_hash(
        HashTag::Other("BarkZkBitvm/OracleAnnouncementV1"), @announcement_message,
    );
    verify_bound_schnorr(
        announcement_witness,
        @evidence.announcement_signature,
        @evidence.oracle_xonly,
        announcement_digest,
    );

    let mut attestation_message = evidence.event_id.clone();
    append_u32_le(ref attestation_message, evidence.outcome.len().try_into().unwrap());
    attestation_message.append(@evidence.outcome);
    attestation_message.append(@encoded_payouts);
    let attestation_digest = tagged_hash(
        HashTag::Other("BarkZkBitvm/OracleAttestationV1"), @attestation_message,
    );
    verify_bound_schnorr(
        attestation_witness,
        @evidence.attestation_signature,
        @evidence.oracle_xonly,
        attestation_digest,
    );
}

fn u256_to_bytes(value: u256) -> ByteArray {
    let mut bytes: ByteArray = "";
    bytes.append_word(value.high.into(), 16);
    bytes.append_word(value.low.into(), 16);
    bytes
}

fn append_u32_le(ref output: ByteArray, value: u32) {
    output.append_word_rev(value.into(), 4);
}

fn append_u64_le(ref output: ByteArray, value: u64) {
    output.append_word_rev(value.into(), 8);
}
