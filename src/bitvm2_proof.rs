//! Cryptographic adapter from a Boundless Blake3-Groth16 seal to the exact
//! Arkworks objects consumed by the official BitVM Groth16 chunker.
//!
//! The byte order follows Boundless' pinned verifier implementation. Unlike
//! the upstream helper, this parser rejects modular aliases and malformed
//! curve points before constructing a proof. A successful value has also been
//! verified against the pinned Boundless verification key.

use crate::boundless::Blake3Groth16Receipt;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use core::{fmt, str::FromStr};
use sha2::{Digest as ShaDigest, Sha256};

// BN254 base-field modulus. This differs from the scalar modulus used for the
// one public input.
const BN254_BASE_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BitvmProofError {
    NonCanonicalCoordinate { index: usize },
    PointAtInfinity(&'static str),
    PointNotOnCurve(&'static str),
    PointNotInSubgroup(&'static str),
    InvalidPinnedVerifierKey,
    JournalStatementMismatch,
    BoundlessClaimMismatch,
    Groth16VerificationFailed,
}

impl fmt::Display for BitvmProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonicalCoordinate { index } => {
                write!(
                    f,
                    "Boundless proof coordinate {index} is not canonical BN254 Fq"
                )
            }
            Self::PointAtInfinity(name) => write!(f, "Boundless proof point {name} is infinity"),
            Self::PointNotOnCurve(name) => {
                write!(f, "Boundless proof point {name} is not on BN254")
            }
            Self::PointNotInSubgroup(name) => {
                write!(
                    f,
                    "Boundless proof point {name} is outside the prime-order subgroup"
                )
            }
            Self::InvalidPinnedVerifierKey => {
                write!(f, "pinned Boundless verifying key is invalid")
            }
            Self::JournalStatementMismatch => {
                write!(
                    f,
                    "RISC Zero journal does not equal the Bark statement digest"
                )
            }
            Self::BoundlessClaimMismatch => write!(
                f,
                "Boundless claim digest does not bind the pinned image and Bark statement"
            ),
            Self::Groth16VerificationFailed => {
                write!(
                    f,
                    "Boundless Groth16 proof failed cryptographic verification"
                )
            }
        }
    }
}

impl std::error::Error for BitvmProofError {}

/// Inputs accepted by `BitVM::chunk::api::generate_assertions` at official
/// BitVM commit `7d1ca3660cac08aab62e76f3aa4daec0d7403ecc`.
#[derive(Debug, Clone)]
pub struct VerifiedBitvmGroth16Input {
    proof: Proof<Bn254>,
    fixed_claim_scalar: Fr,
    public_inputs: Vec<Fr>,
    verifying_key: VerifyingKey<Bn254>,
}

impl VerifiedBitvmGroth16Input {
    pub fn proof(&self) -> &Proof<Bn254> {
        &self.proof
    }

    pub fn public_inputs(&self) -> &[Fr] {
        &self.public_inputs
    }

    pub fn fixed_claim_scalar(&self) -> &Fr {
        &self.fixed_claim_scalar
    }

    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }

    /// The returned public input is zero because the actual claim scalar has
    /// already been folded into the claim-specialized verifying key.
    pub fn into_parts(self) -> (Proof<Bn254>, Vec<Fr>, VerifyingKey<Bn254>) {
        (self.proof, self.public_inputs, self.verifying_key)
    }
}

/// Parse and verify a receipt before it is handed to the official BitVM
/// chunker. Passing wire-shape checks alone is never sufficient.
pub fn verify_for_official_bitvm(
    receipt: &Blake3Groth16Receipt,
    expected_risc0_image_id: &[u8; 32],
    expected_statement_digest: &[u8; 32],
) -> Result<VerifiedBitvmGroth16Input, BitvmProofError> {
    if receipt.journal() != expected_statement_digest {
        return Err(BitvmProofError::JournalStatementMismatch);
    }
    let expected_claim =
        expected_boundless_claim_digest(expected_risc0_image_id, expected_statement_digest)?;
    if receipt.claim_digest() != &expected_claim {
        return Err(BitvmProofError::BoundlessClaimMismatch);
    }
    verify_groth16_only(receipt)
}

fn verify_groth16_only(
    receipt: &Blake3Groth16Receipt,
) -> Result<VerifiedBitvmGroth16Input, BitvmProofError> {
    let proof = parse_proof(receipt.raw_proof())?;
    let public_input = Fr::from_be_bytes_mod_order(receipt.public_scalar().as_bytes());
    let verifying_key = pinned_verifying_key()?;
    let prepared = ark_groth16::prepare_verifying_key(&verifying_key);
    let accepted = Groth16::<Bn254>::verify_proof(&prepared, &proof, &[public_input])
        .map_err(|_| BitvmProofError::Groth16VerificationFailed)?;
    if !accepted {
        return Err(BitvmProofError::Groth16VerificationFailed);
    }
    let claim_bound_key = claim_bound_verifying_key(&verifying_key, public_input)?;
    let zero_input = Fr::zero();
    let claim_bound_prepared = ark_groth16::prepare_verifying_key(&claim_bound_key);
    if !Groth16::<Bn254>::verify_proof(&claim_bound_prepared, &proof, &[zero_input])
        .map_err(|_| BitvmProofError::Groth16VerificationFailed)?
    {
        return Err(BitvmProofError::Groth16VerificationFailed);
    }
    Ok(VerifiedBitvmGroth16Input {
        proof,
        fixed_claim_scalar: public_input,
        public_inputs: vec![zero_input],
        verifying_key: claim_bound_key,
    })
}

/// Fold the one expected public scalar into the constant term. Official
/// BitVM still sees a two-element `gamma_abc_g1`, but the runtime scalar's base
/// is the identity and therefore cannot select a different valid claim.
fn claim_bound_verifying_key(
    verifying_key: &VerifyingKey<Bn254>,
    expected_claim: Fr,
) -> Result<VerifyingKey<Bn254>, BitvmProofError> {
    if verifying_key.gamma_abc_g1.len() != 2 {
        return Err(BitvmProofError::InvalidPinnedVerifierKey);
    }
    let fixed = (verifying_key.gamma_abc_g1[0].into_group()
        + verifying_key.gamma_abc_g1[1] * expected_claim)
        .into_affine();
    let mut bound = verifying_key.clone();
    bound.gamma_abc_g1 = vec![fixed, G1Affine::identity()];
    Ok(bound)
}

/// Recompute Boundless' public scalar from independently pinned inputs. This
/// is the binding that prevents substituting an unrelated valid receipt.
fn expected_boundless_claim_digest(
    image_id: &[u8; 32],
    journal: &[u8; 32],
) -> Result<[u8; 32], BitvmProofError> {
    // RISC Zero 3.0 default ALLOWED_CONTROL_ROOT and BN254 identity control ID,
    // pinned by Boundless 1c334e. Digest bytes use their displayed byte order.
    let mut control_root_bytes =
        decode_hex32("a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56");
    let control_id =
        decode_hex32("c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404");
    for byte in &mut control_root_bytes {
        *byte = byte.reverse_bits();
    }

    // `tagged_struct("risc0.SystemState", [zero merkle root], [pc=0])`.
    let mut system_state = Vec::with_capacity(32 + 32 + 4 + 2);
    system_state.extend_from_slice(&Sha256::digest(b"risc0.SystemState"));
    system_state.extend_from_slice(&[0u8; 32]);
    system_state.extend_from_slice(&0u32.to_le_bytes());
    system_state.extend_from_slice(&1u16.to_le_bytes());
    let post_digest: [u8; 32] = Sha256::digest(&system_state).into();

    let mut buffer = [0u8; 128];
    buffer[0..32].copy_from_slice(&control_root_bytes);
    buffer[32..64].copy_from_slice(image_id);
    buffer[64..96].copy_from_slice(&post_digest);
    buffer[96..128].copy_from_slice(&control_id);
    let output_prefix: [u8; 32] = Sha256::digest(buffer).into();

    let mut hasher = blake3::Hasher::new();
    hasher.update(&output_prefix);
    hasher.update(journal);
    let mut digest: [u8; 32] = hasher.finalize().into();
    digest[31] = 0;
    digest.rotate_right(1);
    Ok(digest)
}

fn decode_hex32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("pinned lowercase hex constant");
    }
    out
}

fn parse_proof(bytes: &[u8; 256]) -> Result<Proof<Bn254>, BitvmProofError> {
    let coordinate = |index: usize| -> Result<Fq, BitvmProofError> {
        let start = index * 32;
        let encoded: &[u8; 32] = bytes[start..start + 32].try_into().unwrap();
        if encoded >= &BN254_BASE_MODULUS_BE {
            return Err(BitvmProofError::NonCanonicalCoordinate { index });
        }
        Ok(Fq::from_be_bytes_mod_order(encoded))
    };

    // Boundless encodes G2 as x.c1 || x.c0 || y.c1 || y.c0.
    let a = G1Affine::new_unchecked(coordinate(0)?, coordinate(1)?);
    let b = G2Affine::new_unchecked(
        Fq2::new(coordinate(3)?, coordinate(2)?),
        Fq2::new(coordinate(5)?, coordinate(4)?),
    );
    let c = G1Affine::new_unchecked(coordinate(6)?, coordinate(7)?);
    validate_g1("A", &a)?;
    validate_g2("B", &b)?;
    validate_g1("C", &c)?;
    Ok(Proof { a, b, c })
}

fn validate_g1(name: &'static str, point: &G1Affine) -> Result<(), BitvmProofError> {
    if point.infinity {
        return Err(BitvmProofError::PointAtInfinity(name));
    }
    if !point.is_on_curve() {
        return Err(BitvmProofError::PointNotOnCurve(name));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(BitvmProofError::PointNotInSubgroup(name));
    }
    Ok(())
}

fn validate_g2(name: &'static str, point: &G2Affine) -> Result<(), BitvmProofError> {
    if point.infinity {
        return Err(BitvmProofError::PointAtInfinity(name));
    }
    if !point.is_on_curve() {
        return Err(BitvmProofError::PointNotOnCurve(name));
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(BitvmProofError::PointNotInSubgroup(name));
    }
    Ok(())
}

fn fq(value: &str) -> Result<Fq, BitvmProofError> {
    Fq::from_str(value).map_err(|_| BitvmProofError::InvalidPinnedVerifierKey)
}

fn pinned_verifying_key() -> Result<VerifyingKey<Bn254>, BitvmProofError> {
    // Constants from Boundless' Blake3 Groth16 verifier at commit
    // 1c334eb77717089c835652b9483bb79c82fbdafe.
    let alpha_g1 = G1Affine::new_unchecked(
        fq("16428432848801857252194528405604668803277877773566238944394625302971855135431")?,
        fq("16846502678714586896801519656441059708016666274385668027902869494772365009666")?,
    );
    let beta_g2 = G2Affine::new_unchecked(
        Fq2::new(
            fq("16348171800823588416173124589066524623406261996681292662100840445103873053252")?,
            fq("3182164110458002340215786955198810119980427837186618912744689678939861918171")?,
        ),
        Fq2::new(
            fq("19687132236965066906216944365591810874384658708175106803089633851114028275753")?,
            fq("4920802715848186258981584729175884379674325733638798907835771393452862684714")?,
        ),
    );
    let gamma_g2 = G2Affine::new_unchecked(
        Fq2::new(
            fq("10857046999023057135944570762232829481370756359578518086990519993285655852781")?,
            fq("11559732032986387107991004021392285783925812861821192530917403151452391805634")?,
        ),
        Fq2::new(
            fq("8495653923123431417604973247489272438418190587263600148770280649306958101930")?,
            fq("4082367875863433681332203403145435568316851327593401208105741076214120093531")?,
        ),
    );
    let delta_g2 = G2Affine::new_unchecked(
        Fq2::new(
            fq("17296777349791701671871010047490559682924748762983962242018229225890177681165")?,
            fq("18786665442134809547367793008388252094276956707083189371748822844215202271178")?,
        ),
        Fq2::new(
            fq("7214627676570978956115414107903354102221009447018809863680303520130992055423")?,
            fq("21546884238630900902634517213362010321565339505810557359182294051078510536811")?,
        ),
    );
    let gamma_abc_g1 = vec![
        G1Affine::new_unchecked(
            fq("1396989810128049774239906514097458055670219613079348950494410066757721605523")?,
            fq("20069629286434534534516684991063672335613842540347999544849171590987775766961")?,
        ),
        G1Affine::new_unchecked(
            fq("19282603452922066135228857769519044667044696173320493211119861249451600114594")?,
            fq("11966256187809052800087108088094647243345273965264062329687482664981607072161")?,
        ),
    ];

    validate_g1("vk.alpha", &alpha_g1)?;
    validate_g2("vk.beta", &beta_g2)?;
    validate_g2("vk.gamma", &gamma_g2)?;
    validate_g2("vk.delta", &delta_g2)?;
    for point in &gamma_abc_g1 {
        validate_g1("vk.gamma_abc", point)?;
    }
    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundless::{Blake3Groth16Receipt, BLAKE3_GROTH16_V0_1_SELECTOR};

    const CLAIM: [u8; 32] =
        hex32("00518e3981d8f63a944afd3d1d2b5c23ba7968488981875b7659e1beb2a95a63");
    const PROOF: [u8; 256] = hex256(concat!(
        "09e5e571a5daab1c3a3c4e02e4e3f3104218cb0bc39a1067859858d09eefd910",
        "2809fbb55dd140c09cf131dae9c271d7d386b021389e929f791e7aa4ffdb9074",
        "1b8f4159cc9d57fce7c4bb5a7da795cb15cd35da3f1067218e1359fe2430af",
        "2b24b5ac63cdaf40cdb240039372942207e1432496eb7efa4dec0cee4bef90ce",
        "ce1ae0027bc89807ac1293ce8d9c8ce3dd999f6926ea0b5904acd0182c85a20",
        "3b325b504efe9bcef7d9dca9cbf7f2d1b312bd189352e7a50a969b2175dc3a3",
        "079615a8fa448aba2fc439af0a5f01949a47507210c5f3088a485ecbe6c4343",
        "e7227145675020b043e2b1211be05c0dbab20d5e5423b5b53d193b7a8cb91455dca86"
    ));

    fn receipt(proof: &[u8; 256], claim: &[u8; 32]) -> Blake3Groth16Receipt {
        Blake3Groth16Receipt::parse_parts(
            &BLAKE3_GROTH16_V0_1_SELECTOR,
            proof,
            &[0u8; 32],
            claim,
            &[claim],
        )
        .unwrap()
    }

    #[test]
    fn verifies_boundless_reference_receipt_and_emits_one_bitvm_scalar() {
        let input = verify_groth16_only(&receipt(&PROOF, &CLAIM)).unwrap();
        assert_eq!(input.public_inputs().len(), 1);
        assert!(input.public_inputs()[0].is_zero());
        assert_eq!(input.verifying_key().gamma_abc_g1.len(), 2);
        assert!(input.verifying_key().gamma_abc_g1[1].is_zero());
    }

    #[test]
    fn rejects_a_well_formed_but_false_operator_proof() {
        let mut proof = PROOF;
        proof[31] ^= 1;
        assert!(verify_groth16_only(&receipt(&proof, &CLAIM)).is_err());
    }

    #[test]
    fn rejects_coordinate_aliases_before_field_reduction() {
        let mut proof = PROOF;
        proof[..32].copy_from_slice(&BN254_BASE_MODULUS_BE);
        assert_eq!(
            parse_proof(&proof),
            Err(BitvmProofError::NonCanonicalCoordinate { index: 0 })
        );
    }

    #[test]
    fn rejects_a_valid_but_unrelated_receipt_before_bitvm() {
        let reference = receipt(&PROOF, &CLAIM);
        assert_eq!(
            verify_for_official_bitvm(&reference, &[7; 32], &[9; 32]).unwrap_err(),
            BitvmProofError::JournalStatementMismatch
        );
    }

    #[test]
    fn image_and_statement_both_change_the_boundless_claim() {
        let base = expected_boundless_claim_digest(&[1; 32], &[2; 32]).unwrap();
        assert_ne!(
            base,
            expected_boundless_claim_digest(&[3; 32], &[2; 32]).unwrap()
        );
        assert_ne!(
            base,
            expected_boundless_claim_digest(&[1; 32], &[4; 32]).unwrap()
        );
        assert_eq!(base[0], 0);
    }

    #[test]
    fn a_different_fixed_claim_rejects_the_same_valid_proof() {
        let receipt = receipt(&PROOF, &CLAIM);
        let verified = verify_groth16_only(&receipt).unwrap();
        let mut other = *verified.fixed_claim_scalar();
        other += Fr::from(1u64);
        let original_key = pinned_verifying_key().unwrap();
        let wrong_key = claim_bound_verifying_key(&original_key, other).unwrap();
        let prepared = ark_groth16::prepare_verifying_key(&wrong_key);
        assert!(
            !Groth16::<Bn254>::verify_proof(&prepared, verified.proof(), &[Fr::zero()]).unwrap()
        );
    }

    const fn nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("invalid hex"),
        }
    }

    const fn hex32(value: &str) -> [u8; 32] {
        let bytes = value.as_bytes();
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }

    const fn hex256(value: &str) -> [u8; 256] {
        let bytes = value.as_bytes();
        let mut out = [0u8; 256];
        let mut i = 0;
        while i < 256 {
            out[i] = (nibble(bytes[i * 2]) << 4) | nibble(bytes[i * 2 + 1]);
            i += 1;
        }
        out
    }
}
