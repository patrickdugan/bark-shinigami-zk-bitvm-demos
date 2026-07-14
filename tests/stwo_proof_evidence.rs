use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use bark_bitvm_showcase::envelope::BarkSpendEnvelopeV1;
use bark_bitvm_showcase::{build_envelope_with_nonce, build_receipt, DemoCase};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq, Eq)]
struct ReferenceEvidence {
    // A checksum match is provenance evidence, not STWO verification.
    cryptographically_verified: bool,
    authorizes_operator_take: bool,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn canonical_lf(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.windows(2).any(|window| window == b"\r\n") {
        let mut normalized = Vec::with_capacity(bytes.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index..].starts_with(b"\r\n") {
                normalized.push(b'\n');
                index += 2;
            } else {
                normalized.push(bytes[index]);
                index += 1;
            }
        }
        bytes = normalized;
    }
    bytes
}

fn read_prover_bytes(path: &Path) -> Vec<u8> {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    match path.extension().and_then(|value| value.to_str()) {
        // GitHub Actions consumed the LF Git blob. Normalize legacy Windows
        // worktrees so this hashes the actual prover input/evidence bytes.
        Some("json" | "txt") => canonical_lf(bytes),
        _ => bytes,
    }
}

fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> &'a str {
    let mut current = value;
    for component in path {
        current = &current[*component];
    }
    current
        .as_str()
        .unwrap_or_else(|| panic!("{} must be a string", path.join(".")))
}

fn reference_fixture(receipt: &Value) -> &Value {
    &receipt["proof_pipeline"]["reference_fixture"]
}

fn check_reference_provenance(
    expected_case: DemoCase,
    receipt: &Value,
    arguments: &[u8],
    proof: &[u8],
    reference_statement_digest: [u8; 32],
    current_statement_digest: [u8; 32],
) -> Result<ReferenceEvidence, &'static str> {
    if string_at(receipt, &["case_id"]) != expected_case.id() {
        return Err("cross-case receipt substitution");
    }
    let fixture = reference_fixture(receipt);
    if fixture["status"] != "verified_fixed_fixture" {
        return Err("fixture was not recorded as verified");
    }
    if string_at(fixture, &["arguments_sha256"]) != sha256(arguments) {
        return Err("argument checksum mismatch");
    }
    if string_at(fixture, &["proof_sha256"]) != sha256(proof) {
        return Err("proof checksum mismatch");
    }
    if current_statement_digest != reference_statement_digest {
        return Err("fixed proof replayed against another statement");
    }

    Ok(ReferenceEvidence {
        // This test deliberately has no STWO verifier. Checksums can establish
        // provenance and substitution resistance, never proof validity.
        cryptographically_verified: false,
        authorizes_operator_take: false,
    })
}

fn parse_sha256sums() -> BTreeMap<String, String> {
    let path = root().join("proof-evidence/SHA256SUMS.txt");
    let text = String::from_utf8(read_prover_bytes(&path)).expect("checksum manifest is UTF-8");
    let mut entries = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        let (digest, file_name) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("malformed checksum line {}", line_number + 1));
        assert_eq!(
            digest.len(),
            64,
            "SHA-256 width on line {}",
            line_number + 1
        );
        assert!(
            digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "checksum must be canonical lowercase hex on line {}",
            line_number + 1
        );
        assert!(
            !file_name.is_empty()
                && Path::new(file_name).components().count() == 1
                && file_name != "."
                && file_name != "..",
            "checksum path must be one local file on line {}",
            line_number + 1
        );
        assert!(
            entries
                .insert(file_name.to_owned(), digest.to_owned())
                .is_none(),
            "duplicate checksum entry for {file_name}"
        );
    }
    entries
}

fn fixed_input(case: DemoCase) -> Vec<u8> {
    read_prover_bytes(
        &root()
            .join("proof-inputs")
            .join(format!("{}.arguments.json", case.id())),
    )
}

fn fixed_proof(case: DemoCase) -> Vec<u8> {
    fs::read(
        root()
            .join("proof-evidence")
            .join(format!("{}.stwo.bin", case.id())),
    )
    .unwrap()
}

fn verified_output(case: DemoCase) -> Value {
    let path = root()
        .join("proof-evidence")
        .join(format!("{}.verified-output.json", case.id()));
    serde_json::from_slice(&read_prover_bytes(&path)).expect("verified output JSON")
}

fn felt_bytes(value: &str) -> Vec<u8> {
    let digits = value.strip_prefix("0x").expect("Cairo felt has 0x prefix");
    if digits == "0" || digits.is_empty() {
        return vec![];
    }
    let mut padded = String::with_capacity(digits.len() + digits.len() % 2);
    if digits.len() % 2 != 0 {
        padded.push('0');
    }
    padded.push_str(digits);
    (0..padded.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&padded[index..index + 2], 16).expect("hex felt"))
        .collect()
}

fn felt_usize(value: &str) -> usize {
    usize::from_str_radix(value.strip_prefix("0x").expect("0x felt"), 16).expect("small felt")
}

fn fixed_envelope(case: DemoCase) -> BarkSpendEnvelopeV1 {
    let arguments: Vec<String> =
        serde_json::from_slice(&fixed_input(case)).expect("Cairo arguments");
    let full_words = felt_usize(&arguments[0]);
    let mut encoded = Vec::new();
    for word in &arguments[1..=full_words] {
        let bytes = felt_bytes(word);
        assert!(bytes.len() <= 31, "ByteArray word exceeds 31 bytes");
        encoded.resize(encoded.len() + 31 - bytes.len(), 0);
        encoded.extend(bytes);
    }
    let pending = felt_bytes(&arguments[full_words + 1]);
    let pending_len = felt_usize(&arguments[full_words + 2]);
    assert!(pending.len() <= pending_len && pending_len < 31);
    encoded.resize(encoded.len() + pending_len - pending.len(), 0);
    encoded.extend(pending);
    BarkSpendEnvelopeV1::decode(&encoded).expect("fixed input starts with a canonical envelope")
}

#[test]
fn checksum_manifest_covers_every_payload_and_every_entry_matches() {
    let evidence_dir = root().join("proof-evidence");
    let manifest = parse_sha256sums();
    let actual_payloads: BTreeSet<String> = fs::read_dir(&evidence_dir)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.file_name().into_string().unwrap())
        .filter(|name| name != "README.md" && name != "SHA256SUMS.txt")
        .collect();
    let covered: BTreeSet<String> = manifest.keys().cloned().collect();
    assert_eq!(covered, actual_payloads, "checksum coverage changed");

    for (file_name, expected) in manifest {
        let bytes = read_prover_bytes(&evidence_dir.join(&file_name));
        assert_eq!(
            sha256(&bytes),
            expected,
            "checksum mismatch for {file_name}"
        );
    }
}

#[test]
fn receipt_metadata_pins_the_exact_github_prover_inputs_and_proofs() {
    for case in [DemoCase::OwnerExitAllow, DemoCase::VirtualCetGuard] {
        let receipt = build_receipt(case);
        let fixture = reference_fixture(&receipt);
        assert_eq!(
            sha256(&fixed_input(case)),
            string_at(fixture, &["arguments_sha256"]),
            "{} prover input drifted",
            case.id()
        );
        assert_eq!(
            sha256(&fixed_proof(case)),
            string_at(fixture, &["proof_sha256"]),
            "{} proof drifted",
            case.id()
        );
        assert_eq!(
            receipt["proof_pipeline"]["accepted_for_authorization"],
            false
        );
        assert_eq!(
            receipt["bitvm_enforcement"]["operator_take_authorized"],
            false
        );
    }
}

#[test]
fn reloaded_verifier_outputs_bind_program_prefix_and_statement_digest() {
    for case in [DemoCase::OwnerExitAllow, DemoCase::VirtualCetGuard] {
        let receipt = build_receipt(case);
        let fixture = reference_fixture(&receipt);
        let verified = verified_output(case);
        assert_eq!(verified["program_hash"], fixture["stwo_program_hash"]);
        assert_eq!(verified["output"].as_array().unwrap().len(), 19);
        let authenticated_prefix = verified["output"].as_array().unwrap()[..3]
            .iter()
            .map(|word| felt_usize(word.as_str().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(authenticated_prefix, [1, 0, 0]);
        assert_eq!(
            fixture["relation_output_prefix"],
            serde_json::json!([1, 0, 0])
        );

        let mut authenticated_digest = [0u8; 32];
        for (chunk, word) in authenticated_digest
            .chunks_exact_mut(4)
            .zip(&verified["output"].as_array().unwrap()[3..11])
        {
            let value = felt_usize(word.as_str().unwrap());
            let value: u32 = value.try_into().expect("statement word is u32");
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        assert_eq!(
            authenticated_digest,
            fixed_envelope(case).statement_digest().unwrap(),
            "{} authenticated the wrong statement digest",
            case.id()
        );
    }
}

#[test]
fn one_byte_proof_tamper_and_cross_case_substitution_fail_closed() {
    let case = DemoCase::OwnerExitAllow;
    let receipt = build_receipt(case);
    let arguments = fixed_input(case);
    let reference_digest = fixed_envelope(case).statement_digest().unwrap();
    let mut proof = fixed_proof(case);
    let tamper_index = proof.len() / 2;
    proof[tamper_index] ^= 1;
    assert_eq!(
        check_reference_provenance(
            case,
            &receipt,
            &arguments,
            &proof,
            reference_digest,
            reference_digest
        ),
        Err("proof checksum mismatch")
    );

    let cet_receipt = build_receipt(DemoCase::VirtualCetGuard);
    let cet_proof = fixed_proof(DemoCase::VirtualCetGuard);
    assert_eq!(
        check_reference_provenance(
            case,
            &cet_receipt,
            &arguments,
            &cet_proof,
            reference_digest,
            reference_digest,
        ),
        Err("cross-case receipt substitution")
    );
    assert_eq!(
        check_reference_provenance(
            case,
            &receipt,
            &arguments,
            &cet_proof,
            reference_digest,
            reference_digest,
        ),
        Err("proof checksum mismatch")
    );
}

#[test]
fn fixed_proof_replay_against_a_fresh_nonce_and_receipt_fails_closed() {
    let case = DemoCase::OwnerExitAllow;
    let receipt = build_receipt(case);
    let fixed = fixed_envelope(case);
    let fixed_digest = fixed.statement_digest().unwrap();
    let fresh = build_envelope_with_nonce(case, [0xa5; 32]);
    let fresh_digest = fresh.statement_digest().unwrap();
    assert_ne!(fresh.contract_nonce, fixed.contract_nonce);
    assert_ne!(fresh_digest, fixed_digest);
    assert_eq!(
        check_reference_provenance(
            case,
            &receipt,
            &fixed_input(case),
            &fixed_proof(case),
            fixed_digest,
            fresh_digest,
        ),
        Err("fixed proof replayed against another statement")
    );
    assert_eq!(
        receipt["proof_pipeline"]["current_instance_stwo_proof"],
        "not_generated_for_fresh_nonce"
    );
    assert_eq!(
        receipt["proof_pipeline"]["accepted_for_authorization"],
        false
    );
    assert_eq!(
        receipt["bitvm_enforcement"]["operator_take_authorized"],
        false
    );
}

#[test]
fn dishonest_case_has_a_rejection_receipt_and_no_proof_to_relabel() {
    let case = DemoCase::OwnerExitChallenge;
    let receipt = build_receipt(case);
    let fixture = reference_fixture(&receipt);
    assert_eq!(fixture["status"], "rejected_before_proof");
    assert!(fixture["proof_sha256"].is_null());
    assert!(fixture.get("proof_path").is_none());
    assert_eq!(
        sha256(&fixed_input(case)),
        string_at(fixture, &["arguments_sha256"]),
        "dishonest prover input drifted"
    );
    assert!(
        !root()
            .join("proof-evidence/owner_exit_challenge.stwo.bin")
            .exists(),
        "a dishonest-case proof must never appear"
    );
    let metrics = String::from_utf8(read_prover_bytes(
        &root().join("proof-evidence/owner_exit_challenge.metrics.txt"),
    ))
    .unwrap();
    assert!(metrics.contains("Exit status: 1"));
    assert_eq!(
        receipt["proof_pipeline"]["accepted_for_authorization"],
        false
    );
    assert_eq!(
        receipt["bitvm_enforcement"]["operator_take_authorized"],
        false
    );
}

#[test]
fn checksum_success_is_explicitly_not_cryptographic_verification() {
    let case = DemoCase::OwnerExitAllow;
    let receipt = build_receipt(case);
    let fixed_digest = fixed_envelope(case).statement_digest().unwrap();
    let evidence = check_reference_provenance(
        case,
        &receipt,
        &fixed_input(case),
        &fixed_proof(case),
        fixed_digest,
        fixed_digest,
    )
    .unwrap();
    assert!(!evidence.cryptographically_verified);
    assert!(!evidence.authorizes_operator_take);
}
