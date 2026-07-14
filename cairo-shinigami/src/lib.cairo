mod bip340;
mod envelope;
mod oracle_policy;
mod transaction_policy;
use bip340::verify_bound_schnorr;
use envelope::{RoleEvidenceV1, decode};
use garaga::signatures::schnorr::SchnorrSignatureWithHint;
use oracle_policy::verify_virtual_cet;
use shinigami_utils::hash::compute_sha256_byte_array;
use transaction_policy::{u256_words, validate_and_sighash};

#[derive(Drop, Serde)]
pub struct BarkShinigamiInputV2 {
    pub statement_envelope: ByteArray,
    pub signature_witnesses: Array<SchnorrSignatureWithHint>,
}

#[derive(Copy, Drop, Serde)]
pub struct BarkShinigamiOutputV2 {
    pub accepted: u32,
    pub statement_digest_0: u32,
    pub statement_digest_1: u32,
    pub statement_digest_2: u32,
    pub statement_digest_3: u32,
    pub statement_digest_4: u32,
    pub statement_digest_5: u32,
    pub statement_digest_6: u32,
    pub statement_digest_7: u32,
    pub taproot_sighash_0: u32,
    pub taproot_sighash_1: u32,
    pub taproot_sighash_2: u32,
    pub taproot_sighash_3: u32,
    pub taproot_sighash_4: u32,
    pub taproot_sighash_5: u32,
    pub taproot_sighash_6: u32,
    pub taproot_sighash_7: u32,
}

#[executable]
fn main(input: BarkShinigamiInputV2) -> BarkShinigamiOutputV2 {
    let BarkShinigamiInputV2 { statement_envelope, mut signature_witnesses } = input;
    let envelope = decode(@statement_envelope);
    let validated_spend = validate_and_sighash(@envelope);
    assert(signature_witnesses.len() >= 1, 'owner witness missing');
    let owner_witness = signature_witnesses.pop_front().unwrap();
    verify_bound_schnorr(
        owner_witness,
        @validated_spend.owner_signature,
        @validated_spend.owner_public_key,
        validated_spend.taproot_sighash,
    );
    match envelope.evidence {
        RoleEvidenceV1::OwnerExit(owner_evidence) => {
            assert(
                owner_evidence.owner_xonly == validated_spend.owner_public_key, 'owner mismatch',
            );
            assert(owner_evidence.csv_delay == 2016, 'owner csv mismatch');
            assert(signature_witnesses.is_empty(), 'unexpected signature witnesses');
        },
        RoleEvidenceV1::VirtualCet(cet_evidence) => {
            assert(signature_witnesses.len() == 2, 'oracle witnesses missing');
            let announcement_witness = signature_witnesses.pop_front().unwrap();
            let attestation_witness = signature_witnesses.pop_front().unwrap();
            verify_virtual_cet(
                cet_evidence, @validated_spend.outputs, announcement_witness, attestation_witness,
            );
        },
    }

    // BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
    // da7434...876c is SHA256("BarkZkBitvm/StatementV1").
    let mut tagged_preimage: ByteArray = "";
    append_tag_hash(ref tagged_preimage);
    append_tag_hash(ref tagged_preimage);
    tagged_preimage.append(@statement_envelope);
    let [d0, d1, d2, d3, d4, d5, d6, d7] = compute_sha256_byte_array(@tagged_preimage);
    let [s0, s1, s2, s3, s4, s5, s6, s7] = u256_words(validated_spend.taproot_sighash);

    // Reaching this output means the strict envelope/transaction policy,
    // Shinigami BIP341 digest, and every role-specific BIP340 check succeeded.
    BarkShinigamiOutputV2 {
        accepted: 1,
        statement_digest_0: d0,
        statement_digest_1: d1,
        statement_digest_2: d2,
        statement_digest_3: d3,
        statement_digest_4: d4,
        statement_digest_5: d5,
        statement_digest_6: d6,
        statement_digest_7: d7,
        taproot_sighash_0: s0,
        taproot_sighash_1: s1,
        taproot_sighash_2: s2,
        taproot_sighash_3: s3,
        taproot_sighash_4: s4,
        taproot_sighash_5: s5,
        taproot_sighash_6: s6,
        taproot_sighash_7: s7,
    }
}

fn append_tag_hash(ref output: ByteArray) {
    output.append_word(0xda743480fe6899b1444382262314a714ca29fb9c204f57b82e3e840283c387, 31);
    output.append_byte(0x6c);
}
