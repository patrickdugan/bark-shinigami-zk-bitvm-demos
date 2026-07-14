use std::env;
use std::fs;
use std::path::PathBuf;

use ark::bitcoin::consensus::encode::deserialize;
use ark::bitcoin::hashes::{sha256, Hash};
use ark::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use ark::bitcoin::taproot::{LeafVersion, TapLeafHash};
use ark::bitcoin::Transaction;
use ark::bitcoin::{Amount, ScriptBuf, TxOut};
use bark_bitvm_showcase::envelope::{tagged_sha256, BarkSpendEnvelopeV1, Payout, RoleEvidence};
use bark_bitvm_showcase::{build_envelope_with_nonce, DemoCase};
use serde_json::json;

fn main() {
    let case_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "owner_exit_allow".to_owned());
    let output = PathBuf::from(
        env::args()
            .nth(2)
            .unwrap_or_else(|| format!("artifacts/{case_name}.arguments.json")),
    );
    let mutation = env::args().nth(3);
    let semantic_mutation = mutation
        .as_deref()
        .map(is_semantic_mutation)
        .unwrap_or(false);
    let (case, nonce_byte) = match case_name.as_str() {
        "owner_exit_allow" => (DemoCase::OwnerExitAllow, 1),
        "owner_exit_challenge" => (DemoCase::OwnerExitChallenge, 2),
        "virtual_cet_guard" => (DemoCase::VirtualCetGuard, 3),
        _ => panic!(
            "unknown case {case_name}; expected owner_exit_allow, owner_exit_challenge, or virtual_cet_guard"
        ),
    };

    let mut envelope = build_envelope_with_nonce(case, [nonce_byte; 32]);
    if let Some(mutation) = mutation
        .as_deref()
        .filter(|value| is_semantic_mutation(value))
    {
        mutate_envelope(&mut envelope, mutation);
    }
    let digest = envelope
        .statement_digest()
        .expect("bounded deterministic envelope");
    let mut encoded = envelope.encode().expect("bounded deterministic envelope");
    if let Some(mutation) = mutation
        .as_deref()
        .filter(|value| !is_semantic_mutation(value))
    {
        mutate(&mut encoded, mutation);
    }
    let arguments = cairo_byte_array_arguments(&encoded);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).expect("create fixture output directory");
    }
    fs::write(
        &output,
        serde_json::to_vec_pretty(&arguments).expect("serialize Cairo arguments"),
    )
    .expect("write Cairo arguments");
    println!("path={}", output.display());
    if mutation.is_none() || semantic_mutation {
        println!("statement_digest={}", hex(&digest));
        println!("cairo_digest_words={:?}", digest_words(digest));
        println!("vtxo_id={}", hex(&envelope.vtxo_id));
        println!("network_genesis={}", hex(&envelope.network_genesis));
        println!(
            "protocol_vtxo_sha256={}",
            sha256::Hash::hash(&envelope.protocol_vtxo)
        );
        println!(
            "anchor_transaction_sha256={}",
            sha256::Hash::hash(&envelope.anchor_transaction)
        );
        println!("pin_shinigami={}", hex(&envelope.pins.shinigami_program));
        println!("pin_cairo={}", hex(&envelope.pins.cairo_program));
        println!("pin_stwo_policy={}", hex(&envelope.pins.stwo_policy));
        println!("pin_risc0={}", hex(&envelope.pins.risc0_image_id));
        println!("prevout_amount={}", envelope.prevouts[0].amount_sats);
        println!(
            "prevout_script_pubkey={}",
            hex(&envelope.prevouts[0].script_pubkey)
        );
        let spend: Transaction =
            deserialize(&envelope.spend_transaction).expect("fixture spend transaction");
        println!("spend_transaction={}", hex(&envelope.spend_transaction));
        for (index, item) in spend.input[0].witness.iter().enumerate() {
            println!("witness_{index}={}", hex(item));
        }
        let witness: Vec<&[u8]> = spend.input[0].witness.iter().collect();
        let leaf_hash = TapLeafHash::from_script(
            ScriptBuf::from_bytes(witness[1].to_vec()).as_script(),
            LeafVersion::TapScript,
        );
        let prevouts = [TxOut {
            value: Amount::from_sat(envelope.prevouts[0].amount_sats),
            script_pubkey: ScriptBuf::from_bytes(envelope.prevouts[0].script_pubkey.clone()),
        }];
        let sighash = SighashCache::new(&spend)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                leaf_hash,
                TapSighashType::Default,
            )
            .expect("fixture Taproot sighash")
            .to_byte_array();
        println!("taproot_sighash={}", hex(&sighash));
        println!("taproot_sighash_words={:?}", digest_words(sighash));

        let mut signature_jobs = vec![json!({
            "role": "owner",
            "public_key": hex(&witness[1][6..38]),
            "signature": hex(witness[0]),
            "message_hash": hex(&sighash),
        })];
        if let RoleEvidence::VirtualCet {
            event_id,
            oracle_xonly,
            announcement_signature,
            attestation_signature,
            outcome,
            payouts,
        } = &envelope.evidence
        {
            signature_jobs.push(json!({
                "role": "oracle_announcement",
                "public_key": hex(oracle_xonly),
                "signature": hex(announcement_signature),
                "message_hash": hex(&oracle_announcement_digest(event_id, payouts)),
            }));
            signature_jobs.push(json!({
                "role": "oracle_attestation",
                "public_key": hex(oracle_xonly),
                "signature": hex(attestation_signature),
                "message_hash": hex(&oracle_attestation_digest(event_id, outcome, payouts)),
            }));
        }
        let witness_input = output.with_extension("witness-input.json");
        fs::write(
            &witness_input,
            serde_json::to_vec_pretty(&json!({
                "schema": "BarkShinigamiGaragaWitnessInputV1",
                "byte_array_arguments": arguments,
                "signature_jobs": signature_jobs,
                "garaga_commit": "0e986ba5133c16a30ac86a7cd07c9551787d0e91",
            }))
            .expect("serialize Garaga witness input"),
        )
        .expect("write Garaga witness input");
        println!("witness_input={}", witness_input.display());
    }
}

fn is_semantic_mutation(mutation: &str) -> bool {
    matches!(
        mutation,
        "false_oracle_outcome"
            | "false_oracle_payout"
            | "false_oracle_key"
            | "false_network"
            | "false_protocol_vtxo"
            | "false_anchor"
            | "false_stwo_pin"
            | "false_heights"
            | "false_risc0_pin"
            | "phantom_prevout_amount"
    )
}

fn mutate_envelope(envelope: &mut BarkSpendEnvelopeV1, mutation: &str) {
    match mutation {
        "false_oracle_outcome" => match &mut envelope.evidence {
            RoleEvidence::VirtualCet { outcome, .. } => outcome[0] ^= 1,
            _ => panic!("false_oracle_outcome requires virtual_cet_guard"),
        },
        "false_oracle_payout" => match &mut envelope.evidence {
            RoleEvidence::VirtualCet { payouts, .. } => payouts[0].amount_sats -= 1,
            _ => panic!("false_oracle_payout requires virtual_cet_guard"),
        },
        "false_oracle_key" => match &mut envelope.evidence {
            RoleEvidence::VirtualCet { oracle_xonly, .. } => oracle_xonly[0] ^= 1,
            _ => panic!("false_oracle_key requires virtual_cet_guard"),
        },
        "false_network" => envelope.network_genesis[0] ^= 1,
        "false_protocol_vtxo" => envelope.protocol_vtxo[0] ^= 1,
        "false_anchor" => envelope.anchor_transaction[0] ^= 1,
        "false_stwo_pin" => envelope.pins.stwo_policy[0] ^= 1,
        "false_heights" => {
            envelope.chain_height = 2016;
            envelope.prevout_confirmed_height = 0;
        }
        "false_risc0_pin" => envelope.pins.risc0_image_id[31] = 1,
        "phantom_prevout_amount" => envelope.prevouts[0].amount_sats = 9_999,
        _ => unreachable!("semantic mutation was classified above"),
    }
}

fn oracle_announcement_digest(event_id: &[u8; 32], payouts: &[Payout]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(event_id);
    encode_payouts(&mut bytes, payouts);
    tagged_sha256("BarkZkBitvm/OracleAnnouncementV1", &bytes)
}

fn oracle_attestation_digest(event_id: &[u8; 32], outcome: &[u8], payouts: &[Payout]) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(event_id);
    bytes.extend_from_slice(&(outcome.len() as u32).to_le_bytes());
    bytes.extend_from_slice(outcome);
    encode_payouts(&mut bytes, payouts);
    tagged_sha256("BarkZkBitvm/OracleAttestationV1", &bytes)
}

fn encode_payouts(output: &mut Vec<u8>, payouts: &[Payout]) {
    output.extend_from_slice(&(payouts.len() as u32).to_le_bytes());
    for payout in payouts {
        output.extend_from_slice(&payout.amount_sats.to_le_bytes());
        output.extend_from_slice(&(payout.script_pubkey.len() as u32).to_le_bytes());
        output.extend_from_slice(&payout.script_pubkey);
    }
}

fn mutate(encoded: &mut Vec<u8>, mutation: &str) {
    match mutation {
        "truncate" => {
            encoded.pop().expect("nonempty envelope");
        }
        "trailing" => encoded.push(0),
        "bad_magic" => encoded[0] ^= 1,
        "zero_nonce" => encoded[39..71].fill(0),
        "oversized_vtxo" => encoded[107..111].copy_from_slice(&0x0010_0001u32.to_le_bytes()),
        _ => panic!(
            "unknown wire mutation {mutation}; expected truncate, trailing, bad_magic, zero_nonce, or oversized_vtxo"
        ),
    }
}

fn digest_words(digest: [u8; 32]) -> [u32; 8] {
    std::array::from_fn(|index| {
        u32::from_be_bytes(digest[index * 4..index * 4 + 4].try_into().unwrap())
    })
}

/// Cairo `Serde<ByteArray>` is `[full_word_count, full_words..., pending_word,
/// pending_word_len]`. Every word is interpreted big-endian, matching
/// `ByteArray::append_byte` and string literals in Cairo corelib 2.18.
fn cairo_byte_array_arguments(bytes: &[u8]) -> Vec<String> {
    let full_word_count = bytes.len() / 31;
    let pending_len = bytes.len() % 31;
    let mut output = Vec::with_capacity(full_word_count + 3);
    output.push(format!("0x{full_word_count:x}"));
    for word in bytes[..full_word_count * 31].chunks_exact(31) {
        output.push(format!("0x{}", hex(word)));
    }
    let pending = &bytes[full_word_count * 31..];
    output.push(if pending.is_empty() {
        "0x0".to_owned()
    } else {
        format!("0x{}", hex(pending))
    });
    output.push(format!("0x{pending_len:x}"));
    output
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_array_abi_splits_at_thirty_one_bytes() {
        let bytes: Vec<u8> = (1..=35).collect();
        let encoded = cairo_byte_array_arguments(&bytes);
        assert_eq!(encoded[0], "0x1");
        assert_eq!(encoded[1], format!("0x{}", hex(&bytes[..31])));
        assert_eq!(encoded[2], format!("0x{}", hex(&bytes[31..])));
        assert_eq!(encoded[3], "0x4");
    }

    #[test]
    fn exact_word_has_zero_pending_word() {
        let encoded = cairo_byte_array_arguments(&[7; 31]);
        assert_eq!(encoded.len(), 4);
        assert_eq!(encoded[0], "0x1");
        assert_eq!(encoded[2], "0x0");
        assert_eq!(encoded[3], "0x0");
    }

    #[test]
    fn digest_words_use_sha256_display_order() {
        let digest: [u8; 32] = std::array::from_fn(|index| index as u8);
        assert_eq!(digest_words(digest)[0], 0x0001_0203);
        assert_eq!(digest_words(digest)[7], 0x1c1d_1e1f);
    }
}
