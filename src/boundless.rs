//! Strict parsing for the Boundless `Blake3Groth16V0_1` wire format.
//!
//! This module deliberately does not claim to verify Groth16. It validates the
//! bytes which are handed to a verifier and, critically, binds them to the
//! single public scalar expected by the BitVM2 graph. Cryptographic acceptance
//! still requires the pinned Boundless verification key.

use core::fmt;

/// Boundless `Blake3Groth16V0_1` selector, in wire order.
pub const BLAKE3_GROTH16_V0_1_SELECTOR: [u8; 4] = [0x62, 0xf0, 0x49, 0xf6];
pub const BLAKE3_GROTH16_JOURNAL_LEN: usize = 32;
pub const BLAKE3_GROTH16_PROOF_LEN: usize = 256;
pub const BLAKE3_GROTH16_SEAL_LEN: usize = 4 + BLAKE3_GROTH16_PROOF_LEN;

// BN254 scalar-field modulus, encoded as a canonical 32-byte big-endian
// integer. Boundless interprets the claim digest with
// `Fr::from_be_bytes_mod_order`; rejecting values >= r prevents two byte
// strings from naming the same public scalar through modular reduction.
const BN254_SCALAR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptParseError {
    SealLength { actual: usize },
    SelectorLength { actual: usize },
    SelectorMismatch { actual: Vec<u8> },
    JournalLength { actual: usize },
    ProofLength { actual: usize },
    ClaimDigestLength { actual: usize },
    PublicInputCount { actual: usize },
    PublicInputLength { actual: usize },
    NonCanonicalPublicScalar,
    PublicInputMismatch,
}

impl fmt::Display for ReceiptParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealLength { actual } => write!(
                f,
                "Blake3Groth16 seal must be {BLAKE3_GROTH16_SEAL_LEN} bytes, got {actual}"
            ),
            Self::SelectorLength { actual } => {
                write!(f, "Blake3Groth16 selector must be 4 bytes, got {actual}")
            }
            Self::SelectorMismatch { actual } => write!(
                f,
                "unexpected Blake3Groth16 selector {}; expected 62f049f6",
                encode_hex(actual)
            ),
            Self::JournalLength { actual } => write!(
                f,
                "Blake3Groth16 journal must be {BLAKE3_GROTH16_JOURNAL_LEN} bytes, got {actual}"
            ),
            Self::ProofLength { actual } => write!(
                f,
                "Blake3Groth16 raw proof must be {BLAKE3_GROTH16_PROOF_LEN} bytes, got {actual}"
            ),
            Self::ClaimDigestLength { actual } => {
                write!(f, "Boundless claim digest must be 32 bytes, got {actual}")
            }
            Self::PublicInputCount { actual } => write!(
                f,
                "BitVM2 Boundless verifier requires exactly one public input, got {actual}"
            ),
            Self::PublicInputLength { actual } => {
                write!(f, "public scalar must be 32 bytes, got {actual}")
            }
            Self::NonCanonicalPublicScalar => {
                write!(
                    f,
                    "public scalar is not canonical in the BN254 scalar field"
                )
            }
            Self::PublicInputMismatch => write!(
                f,
                "BitVM2 public scalar does not equal the Boundless claim digest"
            ),
        }
    }
}

impl std::error::Error for ReceiptParseError {}

/// A unique, non-reduced BN254 scalar encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CanonicalPublicScalar([u8; 32]);

impl CanonicalPublicScalar {
    pub fn parse(bytes: &[u8]) -> Result<Self, ReceiptParseError> {
        let value: [u8; 32] =
            bytes
                .try_into()
                .map_err(|_| ReceiptParseError::PublicInputLength {
                    actual: bytes.len(),
                })?;
        if value >= BN254_SCALAR_MODULUS_BE {
            return Err(ReceiptParseError::NonCanonicalPublicScalar);
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Parsed receipt material already bound to the only public input accepted by
/// the intended BitVM2 verifier graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blake3Groth16Receipt {
    journal: [u8; 32],
    claim_digest: [u8; 32],
    raw_proof: [u8; BLAKE3_GROTH16_PROOF_LEN],
    public_scalar: CanonicalPublicScalar,
}

impl Blake3Groth16Receipt {
    /// Parse a Boundless seal (`selector || raw Groth16 proof`) and require the
    /// caller's BitVM2 public-input vector to contain the exact claim scalar.
    pub fn parse_seal(
        seal: &[u8],
        journal: &[u8],
        claim_digest: &[u8],
        expected_public_inputs: &[&[u8]],
    ) -> Result<Self, ReceiptParseError> {
        if seal.len() != BLAKE3_GROTH16_SEAL_LEN {
            return Err(ReceiptParseError::SealLength { actual: seal.len() });
        }
        Self::parse_parts(
            &seal[..4],
            &seal[4..],
            journal,
            claim_digest,
            expected_public_inputs,
        )
    }

    /// Parse an already separated selector and proof. This is useful for
    /// Boundless APIs which return the selector outside the proof payload.
    pub fn parse_parts(
        selector: &[u8],
        raw_proof: &[u8],
        journal: &[u8],
        claim_digest: &[u8],
        expected_public_inputs: &[&[u8]],
    ) -> Result<Self, ReceiptParseError> {
        if selector.len() != BLAKE3_GROTH16_V0_1_SELECTOR.len() {
            return Err(ReceiptParseError::SelectorLength {
                actual: selector.len(),
            });
        }
        if selector != BLAKE3_GROTH16_V0_1_SELECTOR {
            return Err(ReceiptParseError::SelectorMismatch {
                actual: selector.to_vec(),
            });
        }
        let raw_proof: [u8; BLAKE3_GROTH16_PROOF_LEN] =
            raw_proof
                .try_into()
                .map_err(|_| ReceiptParseError::ProofLength {
                    actual: raw_proof.len(),
                })?;
        let journal: [u8; BLAKE3_GROTH16_JOURNAL_LEN] =
            journal
                .try_into()
                .map_err(|_| ReceiptParseError::JournalLength {
                    actual: journal.len(),
                })?;
        let claim_digest: [u8; 32] =
            claim_digest
                .try_into()
                .map_err(|_| ReceiptParseError::ClaimDigestLength {
                    actual: claim_digest.len(),
                })?;
        let claim_scalar = CanonicalPublicScalar::parse(&claim_digest)?;

        if expected_public_inputs.len() != 1 {
            return Err(ReceiptParseError::PublicInputCount {
                actual: expected_public_inputs.len(),
            });
        }
        let expected_scalar = CanonicalPublicScalar::parse(expected_public_inputs[0])?;
        if expected_scalar != claim_scalar {
            return Err(ReceiptParseError::PublicInputMismatch);
        }

        Ok(Self {
            journal,
            claim_digest,
            raw_proof,
            public_scalar: claim_scalar,
        })
    }

    pub fn selector(&self) -> [u8; 4] {
        BLAKE3_GROTH16_V0_1_SELECTOR
    }

    pub fn journal(&self) -> &[u8; 32] {
        &self.journal
    }

    pub fn claim_digest(&self) -> &[u8; 32] {
        &self.claim_digest
    }

    pub fn raw_proof(&self) -> &[u8; BLAKE3_GROTH16_PROOF_LEN] {
        &self.raw_proof
    }

    pub fn public_scalar(&self) -> CanonicalPublicScalar {
        self.public_scalar
    }

    pub fn seal(&self) -> [u8; BLAKE3_GROTH16_SEAL_LEN] {
        let mut seal = [0u8; BLAKE3_GROTH16_SEAL_LEN];
        seal[..4].copy_from_slice(&BLAKE3_GROTH16_V0_1_SELECTOR);
        seal[4..].copy_from_slice(&self.raw_proof);
        seal
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_material() -> ([u8; BLAKE3_GROTH16_SEAL_LEN], [u8; 32], [u8; 32]) {
        let mut seal = [0x5au8; BLAKE3_GROTH16_SEAL_LEN];
        seal[..4].copy_from_slice(&BLAKE3_GROTH16_V0_1_SELECTOR);
        let journal = [0x11; 32];
        // Boundless rotates a zeroed final digest byte to the front, so real
        // Blake3Groth16 claim digests are comfortably canonical.
        let mut claim_digest = [0x22; 32];
        claim_digest[0] = 0;
        (seal, journal, claim_digest)
    }

    fn parse(
        seal: &[u8],
        journal: &[u8],
        claim_digest: &[u8],
    ) -> Result<Blake3Groth16Receipt, ReceiptParseError> {
        Blake3Groth16Receipt::parse_seal(seal, journal, claim_digest, &[claim_digest])
    }

    #[test]
    fn accepts_exact_boundless_wire_shape_and_one_scalar() {
        let (seal, journal, digest) = valid_material();
        let receipt = parse(&seal, &journal, &digest).unwrap();
        assert_eq!(receipt.selector(), BLAKE3_GROTH16_V0_1_SELECTOR);
        assert_eq!(receipt.seal(), seal);
        assert_eq!(receipt.journal(), &journal);
        assert_eq!(receipt.claim_digest(), &digest);
        assert_eq!(receipt.public_scalar().as_bytes(), &digest);
    }

    #[test]
    fn rejects_dev_or_other_selectors() {
        let (mut seal, journal, digest) = valid_material();
        seal[..4].copy_from_slice(&[0xff, 0xff, 0x00, 0x00]);
        assert!(matches!(
            parse(&seal, &journal, &digest),
            Err(ReceiptParseError::SelectorMismatch { .. })
        ));
    }

    #[test]
    fn rejects_truncation_and_trailing_seal_bytes() {
        let (seal, journal, digest) = valid_material();
        assert!(matches!(
            parse(&seal[..seal.len() - 1], &journal, &digest),
            Err(ReceiptParseError::SealLength { actual: 259 })
        ));
        let mut trailing = seal.to_vec();
        trailing.push(0);
        assert!(matches!(
            parse(&trailing, &journal, &digest),
            Err(ReceiptParseError::SealLength { actual: 261 })
        ));
    }

    #[test]
    fn rejects_wrong_journal_and_raw_proof_lengths() {
        let (seal, journal, digest) = valid_material();
        assert!(matches!(
            parse(&seal, &journal[..31], &digest),
            Err(ReceiptParseError::JournalLength { actual: 31 })
        ));
        assert!(matches!(
            Blake3Groth16Receipt::parse_parts(
                &BLAKE3_GROTH16_V0_1_SELECTOR,
                &seal[4..259],
                &journal,
                &digest,
                &[&digest]
            ),
            Err(ReceiptParseError::ProofLength { actual: 255 })
        ));
    }

    #[test]
    fn rejects_malformed_selector_digest_and_scalar_widths() {
        let (seal, journal, digest) = valid_material();
        assert!(matches!(
            Blake3Groth16Receipt::parse_parts(
                &BLAKE3_GROTH16_V0_1_SELECTOR[..3],
                &seal[4..],
                &journal,
                &digest,
                &[&digest]
            ),
            Err(ReceiptParseError::SelectorLength { actual: 3 })
        ));
        assert!(matches!(
            Blake3Groth16Receipt::parse_seal(&seal, &journal, &digest[..31], &[&digest]),
            Err(ReceiptParseError::ClaimDigestLength { actual: 31 })
        ));
        assert!(matches!(
            Blake3Groth16Receipt::parse_seal(&seal, &journal, &digest, &[&digest[..31]]),
            Err(ReceiptParseError::PublicInputLength { actual: 31 })
        ));
    }

    #[test]
    fn rejects_zero_or_multiple_public_inputs() {
        let (seal, journal, digest) = valid_material();
        assert!(matches!(
            Blake3Groth16Receipt::parse_seal(&seal, &journal, &digest, &[]),
            Err(ReceiptParseError::PublicInputCount { actual: 0 })
        ));
        assert!(matches!(
            Blake3Groth16Receipt::parse_seal(&seal, &journal, &digest, &[&digest, &digest]),
            Err(ReceiptParseError::PublicInputCount { actual: 2 })
        ));
    }

    #[test]
    fn rejects_a_scalar_for_a_different_claim() {
        let (seal, journal, digest) = valid_material();
        let mut attacker_scalar = digest;
        attacker_scalar[31] ^= 1;
        assert_eq!(
            Blake3Groth16Receipt::parse_seal(&seal, &journal, &digest, &[&attacker_scalar]),
            Err(ReceiptParseError::PublicInputMismatch)
        );
    }

    #[test]
    fn rejects_modular_aliases_instead_of_reducing_them() {
        assert_eq!(
            CanonicalPublicScalar::parse(&BN254_SCALAR_MODULUS_BE),
            Err(ReceiptParseError::NonCanonicalPublicScalar)
        );
        let mut modulus_minus_one = BN254_SCALAR_MODULUS_BE;
        modulus_minus_one[31] -= 1;
        assert!(CanonicalPublicScalar::parse(&modulus_minus_one).is_ok());
    }
}
