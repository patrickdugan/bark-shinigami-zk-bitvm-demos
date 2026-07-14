use bark_risc0_stwo_verifier::{BindingError, RelationOutputV3, OUTPUT_WORDS_V3};

fn output_words(prefix: [u32; 3]) -> [u32; OUTPUT_WORDS_V3] {
    let mut words = [0u32; OUTPUT_WORDS_V3];
    words[..3].copy_from_slice(&prefix);
    words[3..11].copy_from_slice(&[
        0x0001_0203,
        0x1011_1213,
        0x2021_2223,
        0x3031_3233,
        0x4041_4243,
        0x5051_5253,
        0x6061_6263,
        0x7071_7273,
    ]);
    words[11..19].copy_from_slice(&[
        0x8081_8283,
        0x9091_9293,
        0xa0a1_a2a3,
        0xb0b1_b2b3,
        0xc0c1_c2c3,
        0xd0d1_d2d3,
        0xe0e1_e2e3,
        0xf0f1_f2f3,
    ]);
    words
}

#[test]
fn relation_only_prefix_cannot_be_confused_with_authorization() {
    let relation_only = RelationOutputV3::parse(&output_words([1, 0, 0])).unwrap();
    assert!(relation_only.transaction_relation_valid());
    assert!(!relation_only.chain_state_verified());
    assert!(!relation_only.operator_take_authorized());

    // A host that treats the first word as a generic success bit would turn
    // the checked-in relation proof into an operator authorization. Keep the
    // three meanings independently observable and exact.
    assert_ne!(
        [
            relation_only.transaction_relation_valid() as u8,
            relation_only.chain_state_verified() as u8,
            relation_only.operator_take_authorized() as u8,
        ],
        [1, 1, 1]
    );
}

#[test]
fn output_framing_and_word_byte_order_are_not_ambiguous() {
    let words = output_words([1, 0, 0]);
    assert!(matches!(
        RelationOutputV3::parse(&words[..OUTPUT_WORDS_V3 - 1]),
        Err(BindingError::WrongOutputWordCount { actual: 18, .. })
    ));

    let mut extended = words.to_vec();
    extended.push(0);
    assert!(matches!(
        RelationOutputV3::parse(&extended),
        Err(BindingError::WrongOutputWordCount { actual: 20, .. })
    ));

    let parsed = RelationOutputV3::parse(&words).unwrap();
    assert_eq!(
        &parsed.statement_digest()[..8],
        &[0, 1, 2, 3, 16, 17, 18, 19]
    );
    assert_ne!(&parsed.statement_digest()[..4], &words[3].to_le_bytes());
}

#[cfg(feature = "upstream-stwo")]
mod upstream_adversarial {
    use std::fs;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use bark_risc0_stwo_verifier::upstream_stwo::verify_compressed_binary;
    use bzip2::read::BzDecoder;
    use bzip2::write::BzEncoder;
    use bzip2::Compression;

    fn proof_bytes() -> Vec<u8> {
        let showcase_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("scaffold is nested under the showcase")
            .to_owned();
        fs::read(
            showcase_root
                .join("proof-evidence")
                .join("owner_exit_allow.stwo.bin"),
        )
        .unwrap()
    }

    #[test]
    fn rejects_bytes_after_the_compressed_proof_stream() {
        let canonical = proof_bytes();
        assert!(
            verify_compressed_binary(&canonical).is_ok(),
            "the strict decoder must retain the canonical proof as a control"
        );
        let mut attacker = canonical;
        attacker.extend_from_slice(b"host-controlled-trailer");
        assert!(
            verify_compressed_binary(&attacker).is_err(),
            "a valid first bzip2 stream must not hide trailing host bytes"
        );
    }

    #[test]
    fn rejects_trailing_bytes_inside_the_decompressed_proof() {
        let mut decompressed = Vec::new();
        BzDecoder::new(proof_bytes().as_slice())
            .read_to_end(&mut decompressed)
            .unwrap();
        decompressed.extend_from_slice(b"host-controlled-trailer");

        let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(&decompressed).unwrap();
        let attacker = encoder.finish().unwrap();

        assert!(
            verify_compressed_binary(&attacker).is_err(),
            "bincode must reject bytes after the canonical proof object"
        );
    }
}
