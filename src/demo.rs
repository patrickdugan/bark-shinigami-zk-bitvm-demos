use std::str::FromStr;

use ark::bitcoin::absolute::LockTime;
use ark::bitcoin::blockdata::constants::genesis_block;
use ark::bitcoin::consensus::encode::{deserialize, serialize};
use ark::bitcoin::hashes::Hash;
use ark::bitcoin::secp256k1::{Keypair, Message, XOnlyPublicKey};
use ark::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use ark::bitcoin::taproot::{LeafVersion, TapLeafHash};
use ark::bitcoin::transaction::Version;
use ark::bitcoin::{Amount, Network, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use ark::test_util::VTXO_VECTORS;
use ark::vtxo::Full;
use ark::{ProtocolEncoding, Vtxo, SECP};
use serde_json::{json, Value};

use crate::enforcement::{BondPolicy, TimingPolicy};
use crate::envelope::{
    tagged_sha256, ArtifactPins, BarkSpendEnvelopeV1, Payout, Prevout, RoleEvidence,
};
use crate::stwo_policy::StwoPolicyV1;

pub const SHINIGAMI_COMMIT: &str = "565d7c7375bd090047137da702b2bfdcd48ec58d";
pub const CAIRO_RELATION_ID: &str = concat!(
    "bark-shinigami-relation-v3;",
    "shinigami=565d7c7375bd090047137da702b2bfdcd48ec58d;",
    "garaga=0e986ba5133c16a30ac86a7cd07c9551787d0e91;",
    "alexandria=6d2cfcc0954c8d7796f028b25336faa8e9378da8",
);
/// Consensus-critical minimum profile used by the specialized relation:
/// CHECKSEQUENCEVERIFY | WITNESS | TAPROOT.
pub const REQUIRED_SCRIPT_FLAGS: u32 = 0x0001_1010;
const BOARD_OWNER_SECRET: &str = "fab9e598081a3e74b2233d470c4ad87bcc285b6912ed929568e62ac0e9409879";
const ORACLE_SECRET: &str = "7ad15c6334b6d38b9cd97f6afc3fc00620dfbc2add7f17fd673d14631467680f";
const DESTINATION_A_SECRET: &str =
    "3e371eca6f4b04b114c257f4d7f55600670cd78e536ee67e7639d9efde13a812";
const DESTINATION_B_SECRET: &str =
    "1c3a1d9f50d3c2532451b9a54605cb872b7f2b6da47e9d922b87a500368e9f7d";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemoCase {
    OwnerExitAllow,
    OwnerExitChallenge,
    VirtualCetGuard,
}

impl DemoCase {
    pub fn id(self) -> &'static str {
        match self {
            Self::OwnerExitAllow => "owner_exit_allow",
            Self::OwnerExitChallenge => "owner_exit_challenge",
            Self::VirtualCetGuard => "virtual_cet_guard",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostValidation {
    pub bark_vtxo_valid: bool,
    pub exact_spend_valid: bool,
    pub oracle_evidence_valid: Option<bool>,
    pub reason: String,
}

impl HostValidation {
    fn success(oracle_evidence_valid: Option<bool>) -> Self {
        Self {
            bark_vtxo_valid: true,
            exact_spend_valid: true,
            oracle_evidence_valid,
            reason: "exact Bark spend and role evidence validated".to_owned(),
        }
    }

    fn failure(bark_vtxo_valid: bool, reason: impl Into<String>) -> Self {
        Self {
            bark_vtxo_valid,
            exact_spend_valid: false,
            oracle_evidence_valid: None,
            reason: reason.into(),
        }
    }
}

pub fn build_envelope(case: DemoCase) -> BarkSpendEnvelopeV1 {
    let mut contract_nonce = [0u8; 32];
    getrandom::fill(&mut contract_nonce).expect("operating-system randomness for contract nonce");
    build_envelope_with_nonce(case, contract_nonce)
}

pub fn build_envelope_with_nonce(case: DemoCase, contract_nonce: [u8; 32]) -> BarkSpendEnvelopeV1 {
    assert_ne!(
        contract_nonce, [0; 32],
        "contract nonce must be instance-fresh and nonzero"
    );
    let vtxo = &VTXO_VECTORS.board_vtxo;
    vtxo.validate(&VTXO_VECTORS.anchor_tx)
        .expect("Bark vector must validate");
    let destination_a = destination_script(DESTINATION_A_SECRET);
    let destination_b = destination_script(DESTINATION_B_SECRET);

    let (spend, evidence) = match case {
        DemoCase::OwnerExitAllow | DemoCase::OwnerExitChallenge => {
            let outputs = vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: destination_a,
            }];
            let spend = signed_owner_spend(vtxo, outputs);
            let (owner_xonly, _) = vtxo.user_pubkey().x_only_public_key();
            (
                spend,
                RoleEvidence::OwnerExit {
                    owner_xonly: owner_xonly.serialize(),
                    csv_delay: u32::from(vtxo.exit_delta()),
                },
            )
        }
        DemoCase::VirtualCetGuard => {
            let payouts = vec![
                Payout {
                    amount_sats: 6_000,
                    script_pubkey: destination_a.as_bytes().to_vec(),
                },
                Payout {
                    amount_sats: 4_000,
                    script_pubkey: destination_b.as_bytes().to_vec(),
                },
            ];
            let outputs = payouts
                .iter()
                .map(|payout| TxOut {
                    value: Amount::from_sat(payout.amount_sats),
                    script_pubkey: ScriptBuf::from_bytes(payout.script_pubkey.clone()),
                })
                .collect();
            let spend = signed_owner_spend(vtxo, outputs);
            let event_id = tagged_sha256("BarkZkBitvm/OracleEventV1", b"btc-usd-2026-07-13");
            let outcome = b"above-100000".to_vec();
            let oracle = keypair(ORACLE_SECRET);
            let (oracle_xonly, _) = XOnlyPublicKey::from_keypair(&oracle);
            let announcement_digest = oracle_announcement_digest(&event_id, &payouts);
            let attestation_digest = oracle_attestation_digest(&event_id, &outcome, &payouts);
            let announcement_signature = SECP
                .sign_schnorr_no_aux_rand(&Message::from_digest(announcement_digest), &oracle)
                .serialize();
            let attestation_signature = SECP
                .sign_schnorr_no_aux_rand(&Message::from_digest(attestation_digest), &oracle)
                .serialize();
            (
                spend,
                RoleEvidence::VirtualCet {
                    event_id,
                    oracle_xonly: oracle_xonly.serialize(),
                    announcement_signature,
                    attestation_signature,
                    outcome,
                    payouts,
                },
            )
        }
    };

    let mut envelope = BarkSpendEnvelopeV1 {
        network_genesis: genesis_block(Network::Regtest).block_hash().to_byte_array(),
        contract_nonce,
        vtxo_id: vtxo.id().to_bytes(),
        protocol_vtxo: vtxo.serialize(),
        anchor_transaction: serialize(&VTXO_VECTORS.anchor_tx),
        spend_transaction: serialize(&spend),
        input_index: 0,
        prevouts: vec![Prevout {
            amount_sats: vtxo.txout().value.to_sat(),
            script_pubkey: vtxo.txout().script_pubkey.as_bytes().to_vec(),
        }],
        chain_height: 10_000,
        prevout_confirmed_height: 7_984,
        script_flags: REQUIRED_SCRIPT_FLAGS,
        evidence,
        pins: artifact_pins(),
    };

    if case == DemoCase::OwnerExitChallenge {
        let mut dishonest_spend: Transaction = deserialize(&envelope.spend_transaction).unwrap();
        dishonest_spend.output[0].value = Amount::from_sat(9_999);
        // Keep the original signature. The mutation is therefore an exact false
        // assertion and must fail the Taproot sighash check.
        envelope.spend_transaction = serialize(&dishonest_spend);
    }

    envelope
}

pub fn validate_host(envelope: &BarkSpendEnvelopeV1) -> HostValidation {
    let vtxo = match Vtxo::<Full>::deserialize(&envelope.protocol_vtxo) {
        Ok(value) => value,
        Err(error) => {
            return HostValidation::failure(false, format!("VTXO decode failed: {error}"))
        }
    };
    let anchor: Transaction = match deserialize(&envelope.anchor_transaction) {
        Ok(value) => value,
        Err(error) => {
            return HostValidation::failure(false, format!("anchor decode failed: {error}"))
        }
    };
    if let Err(error) = vtxo.validate(&anchor) {
        return HostValidation::failure(false, format!("Bark VTXO validation failed: {error}"));
    }
    if vtxo.id().to_bytes() != envelope.vtxo_id {
        return HostValidation::failure(true, "VTXO ID does not match ProtocolEncoding(VTXO)");
    }
    if envelope.contract_nonce == [0; 32] {
        return HostValidation::failure(true, "contract nonce must be instance-fresh and nonzero");
    }
    if envelope.network_genesis != genesis_block(Network::Regtest).block_hash().to_byte_array() {
        return HostValidation::failure(true, "demo envelope is not bound to regtest genesis");
    }
    if envelope.script_flags != REQUIRED_SCRIPT_FLAGS {
        return HostValidation::failure(true, "script flag policy mismatch");
    }
    if envelope.prevouts.len() != 1 {
        return HostValidation::failure(true, "exactly one prevout is required by these demos");
    }
    let expected_prevout = vtxo.txout();
    if envelope.prevouts[0].amount_sats != expected_prevout.value.to_sat()
        || envelope.prevouts[0].script_pubkey != expected_prevout.script_pubkey.as_bytes()
    {
        return HostValidation::failure(true, "prevout amount or script does not match Bark VTXO");
    }
    let spend: Transaction = match deserialize(&envelope.spend_transaction) {
        Ok(value) => value,
        Err(error) => {
            return HostValidation::failure(true, format!("spend decode failed: {error}"))
        }
    };
    if envelope.input_index != 0 || spend.input.len() != 1 {
        return HostValidation::failure(true, "demo spend must have one input at index zero");
    }
    if !spend.input[0].script_sig.is_empty() {
        return HostValidation::failure(true, "segwit/Taproot spend scriptSig must be empty");
    }
    if spend.output.is_empty() {
        return HostValidation::failure(true, "spend must have at least one output");
    }
    if spend.weight().to_wu() > 400_000 {
        return HostValidation::failure(
            true,
            "spend exceeds the standard transaction weight limit",
        );
    }
    if spend.input[0].previous_output != vtxo.point() {
        return HostValidation::failure(true, "spend outpoint does not match the Bark VTXO");
    }
    if spend.version.0 < 2 {
        return HostValidation::failure(true, "CSV requires transaction version two or later");
    }
    let sequence = spend.input[0].sequence.to_consensus_u32();
    if sequence & (1 << 31) != 0
        || sequence & (1 << 22) != 0
        || sequence & 0xffff < u32::from(vtxo.exit_delta())
    {
        return HostValidation::failure(true, "input sequence does not satisfy the Bark block CSV");
    }
    let maturity = envelope
        .prevout_confirmed_height
        .checked_add(u32::from(vtxo.exit_delta()));
    if maturity.is_none() || envelope.chain_height < maturity.unwrap() {
        return HostValidation::failure(true, "chain-height context is not CSV-mature");
    }
    let output_sum = spend
        .output
        .iter()
        .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
    if output_sum.is_none() || output_sum.unwrap() > expected_prevout.value.to_sat() {
        return HostValidation::failure(true, "spend outputs exceed the Bark VTXO amount");
    }
    if let Err(reason) = verify_owner_script_path(&vtxo, &spend, &expected_prevout) {
        return HostValidation::failure(true, reason);
    }

    match &envelope.evidence {
        RoleEvidence::OwnerExit {
            owner_xonly,
            csv_delay,
        } => {
            let expected_owner = vtxo.user_pubkey().x_only_public_key().0.serialize();
            if owner_xonly != &expected_owner || *csv_delay != u32::from(vtxo.exit_delta()) {
                return HostValidation::failure(
                    true,
                    "owner-exit evidence does not match Bark policy",
                );
            }
            HostValidation::success(None)
        }
        RoleEvidence::VirtualCet {
            event_id,
            oracle_xonly,
            announcement_signature,
            attestation_signature,
            outcome,
            payouts,
        } => {
            let expected_event = tagged_sha256("BarkZkBitvm/OracleEventV1", b"btc-usd-2026-07-13");
            let expected_oracle = XOnlyPublicKey::from_keypair(&keypair(ORACLE_SECRET))
                .0
                .serialize();
            if event_id != &expected_event || oracle_xonly != &expected_oracle {
                return HostValidation::failure(
                    true,
                    "oracle trust root or event is not the pinned showcase policy",
                );
            }
            if payouts.len() != spend.output.len() {
                return HostValidation::failure(
                    true,
                    "CET payout count does not match spend outputs",
                );
            }
            for (payout, output) in payouts.iter().zip(&spend.output) {
                if payout.amount_sats != output.value.to_sat()
                    || payout.script_pubkey != output.script_pubkey.as_bytes()
                {
                    return HostValidation::failure(
                        true,
                        "CET payout table does not exactly match outputs",
                    );
                }
            }
            let oracle_key = match XOnlyPublicKey::from_slice(oracle_xonly) {
                Ok(value) => value,
                Err(_) => return HostValidation::failure(true, "invalid oracle x-only key"),
            };
            let announcement = match ark::bitcoin::secp256k1::schnorr::Signature::from_slice(
                announcement_signature,
            ) {
                Ok(value) => value,
                Err(_) => {
                    return HostValidation::failure(true, "invalid oracle announcement signature")
                }
            };
            let attestation = match ark::bitcoin::secp256k1::schnorr::Signature::from_slice(
                attestation_signature,
            ) {
                Ok(value) => value,
                Err(_) => {
                    return HostValidation::failure(true, "invalid oracle attestation signature")
                }
            };
            let announcement_message =
                Message::from_digest(oracle_announcement_digest(event_id, payouts));
            let attestation_message =
                Message::from_digest(oracle_attestation_digest(event_id, outcome, payouts));
            if SECP
                .verify_schnorr(&announcement, &announcement_message, &oracle_key)
                .is_err()
                || SECP
                    .verify_schnorr(&attestation, &attestation_message, &oracle_key)
                    .is_err()
            {
                return HostValidation::failure(true, "oracle evidence signature check failed");
            }
            HostValidation::success(Some(true))
        }
    }
}

pub fn build_receipt(case: DemoCase) -> Value {
    let envelope = build_envelope(case);
    let validation = validate_host(&envelope);
    let digest = envelope.statement_digest().expect("bounded fixture");
    let expected_valid = case != DemoCase::OwnerExitChallenge;
    assert_eq!(validation.exact_spend_valid, expected_valid);
    let bond = BondPolicy {
        protected_value_sats: VTXO_VECTORS.board_vtxo.amount().to_sat(),
        watcher_reward_sats: 10_000,
        graph_vbytes: 200_000,
        fee_rate_sat_per_vbyte: 2,
    }
    .required_bond_sats()
    .expect("fixture bond arithmetic");
    json!({
        "schema": "bark-zk-bitvm-showcase-v3",
        "case_id": case.id(),
        "network": "regtest",
        "statement": {
            "encoding": "BarkSpendEnvelopeV1",
            "digest_tag": "BarkZkBitvm/StatementV1",
            "digest": hex(&digest),
            "encoded_bytes": envelope.encode().unwrap().len(),
            "vtxo_id": VTXO_VECTORS.board_vtxo.id().to_string(),
        },
        "host_preflight": {
            "bark_vtxo_valid": validation.bark_vtxo_valid,
            "exact_spend_valid": validation.exact_spend_valid,
            "oracle_evidence_valid": validation.oracle_evidence_valid,
            "reason": validation.reason,
        },
        "proof_pipeline": {
            "shinigami_relation": "ready: syscall-free SHA-256, strict envelope/transaction policy, Shinigami BIP341, and constrained Garaga BIP340 checks execute successfully; a verified STWO proof artifact is still required",
            "accepted_for_authorization": false,
            "stwo_policy_digest": hex(&StwoPolicyV1::REQUIRED.digest()),
            "risc0_receipt": "unavailable",
            "boundless_blake3_groth16": "unavailable",
            "risc0_dev_mode_allowed": false,
        },
        "bitvm_enforcement": {
            "status": "not_enforced",
            "reason": "no real Boundless receipt and no relay-tested BitVM graph are present",
            "operator_take_authorized": false,
            "protected_object": "operator bond/reimbursement UTXO",
            "bitvm2": "blocked_missing_real_receipt_and_core_relay_results",
            "bitvmx": "blocked_missing_rv32im_resource_and_permissionless_watcher_measurements",
            "permissionless_watcher_required": true,
            "required_fixture_bond_sats": bond,
            "signet_timing": {
                "challenge_blocks": TimingPolicy::SIGNET.challenge_blocks,
                "response_window_blocks": TimingPolicy::SIGNET.response_window_blocks,
                "response_rounds": TimingPolicy::SIGNET.response_rounds,
                "operator_take_delta": TimingPolicy::SIGNET.operator_take_height_delta,
                "emergency_recovery_delta": TimingPolicy::SIGNET.emergency_recovery_height_delta,
            },
        },
        "security_boundary": {
            "mainnet": false,
            "funded": false,
            "broadcast": false,
            "host_validation_is_a_zk_proof": false,
            "fail_closed": true,
        }
    })
}

pub fn emit(case: DemoCase) {
    println!(
        "{}",
        serde_json::to_string_pretty(&build_receipt(case)).unwrap()
    );
}

fn signed_owner_spend(vtxo: &Vtxo<Full>, outputs: Vec<TxOut>) -> Transaction {
    let owner = keypair(BOARD_OWNER_SECRET);
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: vtxo.point(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(vtxo.exit_delta()),
            witness: Witness::new(),
        }],
        output: outputs,
    };
    let script =
        ark::scripts::delayed_sign(vtxo.exit_delta(), vtxo.user_pubkey().x_only_public_key().0);
    let control = vtxo
        .output_taproot()
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("owner exit leaf is present");
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let prevouts = [vtxo.txout()];
    let sighash = SighashCache::new(&transaction)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("one exact prevout");
    let signature =
        SECP.sign_schnorr_no_aux_rand(&Message::from_digest(sighash.to_byte_array()), &owner);
    let mut witness = Witness::new();
    witness.push(signature.as_ref());
    witness.push(script.as_bytes());
    witness.push(control.serialize());
    transaction.input[0].witness = witness;
    transaction
}

fn verify_owner_script_path(
    vtxo: &Vtxo<Full>,
    spend: &Transaction,
    prevout: &TxOut,
) -> Result<(), String> {
    let witness = &spend.input[0].witness;
    if witness.len() != 3 {
        return Err("owner exit witness must be signature, script, control block".to_owned());
    }
    let expected_script =
        ark::scripts::delayed_sign(vtxo.exit_delta(), vtxo.user_pubkey().x_only_public_key().0);
    let expected_control = vtxo
        .output_taproot()
        .control_block(&(expected_script.clone(), LeafVersion::TapScript))
        .ok_or_else(|| "Bark owner-exit leaf is absent".to_owned())?;
    let elements: Vec<&[u8]> = witness.iter().collect();
    if elements[1] != expected_script.as_bytes() || elements[2] != expected_control.serialize() {
        return Err(
            "owner exit script or control block does not match Bark Taproot policy".to_owned(),
        );
    }
    let signature = ark::bitcoin::secp256k1::schnorr::Signature::from_slice(elements[0])
        .map_err(|_| "owner exit signature is malformed".to_owned())?;
    let leaf_hash = TapLeafHash::from_script(&expected_script, LeafVersion::TapScript);
    let prevouts = [prevout.clone()];
    let sighash = SighashCache::new(spend)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map_err(|error| format!("owner exit sighash failed: {error}"))?;
    let owner_xonly = vtxo.user_pubkey().x_only_public_key().0;
    SECP.verify_schnorr(
        &signature,
        &Message::from_digest(sighash.to_byte_array()),
        &owner_xonly,
    )
    .map_err(|_| "owner exit signature does not authorize the exact transaction".to_owned())
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

fn encode_payouts(out: &mut Vec<u8>, payouts: &[Payout]) {
    out.extend_from_slice(&(payouts.len() as u32).to_le_bytes());
    for payout in payouts {
        out.extend_from_slice(&payout.amount_sats.to_le_bytes());
        out.extend_from_slice(&(payout.script_pubkey.len() as u32).to_le_bytes());
        out.extend_from_slice(&payout.script_pubkey);
    }
}

fn artifact_pins() -> ArtifactPins {
    ArtifactPins {
        shinigami_program: tagged_sha256(
            "BarkZkBitvm/ShinigamiCommitV1",
            SHINIGAMI_COMMIT.as_bytes(),
        ),
        cairo_program: tagged_sha256(
            "BarkZkBitvm/CairoRelationIdV1",
            CAIRO_RELATION_ID.as_bytes(),
        ),
        stwo_policy: StwoPolicyV1::REQUIRED.digest(),
        // A real RISC Zero image ID must replace this before a receipt can pass.
        risc0_image_id: [0; 32],
    }
}

fn destination_script(secret: &str) -> ScriptBuf {
    let keypair = keypair(secret);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    ScriptBuf::new_p2tr(&SECP, xonly, None)
}

fn keypair(secret: &str) -> Keypair {
    Keypair::from_str(secret).expect("fixed valid test key")
}

pub fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::BarkSpendEnvelopeV1;

    #[test]
    fn honest_owner_exit_is_an_exact_signed_bark_spend() {
        let envelope = build_envelope_with_nonce(DemoCase::OwnerExitAllow, [1; 32]);
        assert!(validate_host(&envelope).exact_spend_valid);
    }

    #[test]
    fn dishonest_amount_mutation_is_rejected() {
        let envelope = build_envelope_with_nonce(DemoCase::OwnerExitChallenge, [2; 32]);
        let result = validate_host(&envelope);
        assert!(!result.exact_spend_valid);
        assert!(result.reason.contains("signature"));
    }

    #[test]
    fn virtual_cet_binds_oracle_outcome_and_exact_payouts() {
        let envelope = build_envelope_with_nonce(DemoCase::VirtualCetGuard, [3; 32]);
        let result = validate_host(&envelope);
        assert!(result.exact_spend_valid);
        assert_eq!(result.oracle_evidence_valid, Some(true));
        let mut changed = envelope.clone();
        if let RoleEvidence::VirtualCet { outcome, .. } = &mut changed.evidence {
            outcome[0] ^= 1;
        }
        assert!(!validate_host(&changed).exact_spend_valid);
    }

    #[test]
    fn thirty_thousand_seeded_mutations_cannot_replay_the_original_digest() {
        for case in [
            DemoCase::OwnerExitAllow,
            DemoCase::OwnerExitChallenge,
            DemoCase::VirtualCetGuard,
        ] {
            let envelope = build_envelope_with_nonce(case, [case as u8 + 1; 32]);
            let encoded = envelope.encode().unwrap();
            let digest = envelope.statement_digest().unwrap();
            let mut state = u64::from_le_bytes(digest[..8].try_into().unwrap());
            for iteration in 0..10_000 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let mut changed = encoded.clone();
                let index = (state as usize) % changed.len();
                let shift = ((state >> 32) & 7) as u32;
                changed[index] ^= 1u8 << shift;
                if let Ok(decoded) = BarkSpendEnvelopeV1::decode(&changed) {
                    assert_ne!(
                        decoded.statement_digest().unwrap(),
                        digest,
                        "case {case:?}, mutation {iteration}"
                    );
                }
            }
        }
    }
}
