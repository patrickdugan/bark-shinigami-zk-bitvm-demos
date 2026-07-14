#![cfg(feature = "upstream-stwo")]

use std::fs;
use std::path::PathBuf;

use bark_risc0_stwo_verifier::upstream_stwo::verify_compressed_binary;
use bark_risc0_stwo_verifier::{BindingError, VerificationPolicy};

fn showcase_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("scaffold is nested under the showcase")
        .to_owned()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut decoded = [0u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}

#[test]
fn checked_in_proofs_verify_but_cannot_emit_an_authorization_journal() {
    for (case_name, expected_statement_digest) in [
        (
            "owner_exit_allow",
            "34962f16168196bd39f9b516c9ef5afb8da4bfd70638d0fd3767defc266cb9be",
        ),
        (
            "virtual_cet_guard",
            "672e302333c83d08a943dc21873f9cb80d0057c3a9869cda38e9f74290361245",
        ),
    ] {
        let proof = fs::read(
            showcase_root()
                .join("proof-evidence")
                .join(format!("{case_name}.stwo.bin")),
        )
        .unwrap();
        let verified = verify_compressed_binary(&proof).expect("real STWO proof must verify");
        assert!(verified.output().transaction_relation_valid());
        assert!(!verified.output().chain_state_verified());
        assert!(!verified.output().operator_take_authorized());
        assert_eq!(
            verified.output().statement_digest(),
            decode_hex_32(expected_statement_digest)
        );
        assert_eq!(
            verified.authorization_journal(&VerificationPolicy::new([0; 32], [0; 32])),
            Err(BindingError::MissingProgramPin)
        );
    }
}
