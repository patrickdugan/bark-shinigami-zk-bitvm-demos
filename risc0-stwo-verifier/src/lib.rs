#![cfg_attr(not(any(test, feature = "std")), no_std)]

//! Fail-closed binding between a cryptographically verified STWO Cairo proof
//! and the single 32-byte journal accepted by the Boundless outer proof.
//!
//! This crate does not expose an `accepted: bool` input. A [`VerifiedExecution`]
//! can only be constructed inside the cryptographic verifier adapter.

use core::fmt;

#[cfg(any(test, feature = "upstream-stwo"))]
use sha2::{Digest, Sha256};

#[cfg(feature = "upstream-stwo")]
pub mod upstream_stwo;

// The STWO core verifier is no_std-capable, but cairo-air at the pinned commit
// unconditionally compiles std/file/Rayon/portable-SIMD modules. Keeping this
// as a hard compile error is safer than silently replacing verification in the
// zkVM guest.
#[cfg(all(feature = "upstream-stwo", target_os = "zkvm"))]
compile_error!(
    "pinned cairo-air b1acf8b is not RISC Zero RV32-compatible: port its verifier-only claim/AIR modules before building this guest"
);

pub const OUTPUT_WORDS_V3: usize = 19;
#[cfg(any(test, feature = "upstream-stwo"))]
const PROGRAM_DOMAIN: &[u8] = b"BarkShinigami/CairoProgramV1\0";
#[cfg(any(test, feature = "upstream-stwo"))]
const POLICY_DOMAIN: &[u8] = b"BarkShinigami/StwoPolicyV1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    WrongOutputWordCount { expected: usize, actual: usize },
    NonBooleanFlag { field: &'static str, value: u32 },
    MissingProgramPin,
    MissingPolicyPin,
    ProgramMismatch,
    PolicyMismatch,
    TransactionRelationInvalid,
    ChainStateNotVerified,
    OperatorTakeNotAuthorized,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongOutputWordCount { expected, actual } => {
                write!(
                    f,
                    "BarkShinigamiOutputV3 needs {expected} words, got {actual}"
                )
            }
            Self::NonBooleanFlag { field, value } => {
                write!(f, "{field} must be 0 or 1, got {value}")
            }
            Self::MissingProgramPin => write!(f, "Cairo program commitment is not pinned"),
            Self::MissingPolicyPin => write!(f, "STWO policy commitment is not pinned"),
            Self::ProgramMismatch => write!(f, "verified Cairo program does not match the pin"),
            Self::PolicyMismatch => write!(f, "verified STWO policy does not match the pin"),
            Self::TransactionRelationInvalid => {
                write!(f, "the signed transaction relation is not valid")
            }
            Self::ChainStateNotVerified => write!(f, "Bitcoin chain state is not verified"),
            Self::OperatorTakeNotAuthorized => {
                write!(f, "the relation does not authorize an operator take")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindingError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationOutputV3 {
    transaction_relation_valid: u32,
    chain_state_verified: u32,
    operator_take_authorized: u32,
    statement_digest_words: [u32; 8],
    taproot_sighash_words: [u32; 8],
}

impl RelationOutputV3 {
    pub fn parse(words: &[u32]) -> Result<Self, BindingError> {
        let words: [u32; OUTPUT_WORDS_V3] =
            words
                .try_into()
                .map_err(|_| BindingError::WrongOutputWordCount {
                    expected: OUTPUT_WORDS_V3,
                    actual: words.len(),
                })?;

        for (field, value) in [
            ("transaction_relation_valid", words[0]),
            ("chain_state_verified", words[1]),
            ("operator_take_authorized", words[2]),
        ] {
            if value > 1 {
                return Err(BindingError::NonBooleanFlag { field, value });
            }
        }

        Ok(Self {
            transaction_relation_valid: words[0],
            chain_state_verified: words[1],
            operator_take_authorized: words[2],
            statement_digest_words: words[3..11].try_into().expect("fixed slice"),
            taproot_sighash_words: words[11..19].try_into().expect("fixed slice"),
        })
    }

    pub fn transaction_relation_valid(&self) -> bool {
        self.transaction_relation_valid == 1
    }

    pub fn chain_state_verified(&self) -> bool {
        self.chain_state_verified == 1
    }

    pub fn operator_take_authorized(&self) -> bool {
        self.operator_take_authorized == 1
    }

    pub fn statement_digest(&self) -> [u8; 32] {
        words_to_be_bytes(self.statement_digest_words)
    }

    pub fn taproot_sighash(&self) -> [u8; 32] {
        words_to_be_bytes(self.taproot_sighash_words)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationPolicy {
    expected_program_commitment: [u8; 32],
    expected_stwo_policy_commitment: [u8; 32],
}

impl VerificationPolicy {
    /// These values must be constants in the RISC Zero guest. The guest image
    /// ID then authenticates the pins to the outer verifier.
    pub const fn new(
        expected_program_commitment: [u8; 32],
        expected_stwo_policy_commitment: [u8; 32],
    ) -> Self {
        Self {
            expected_program_commitment,
            expected_stwo_policy_commitment,
        }
    }

    fn validate(&self) -> Result<(), BindingError> {
        if self.expected_program_commitment == [0; 32] {
            return Err(BindingError::MissingProgramPin);
        }
        if self.expected_stwo_policy_commitment == [0; 32] {
            return Err(BindingError::MissingPolicyPin);
        }
        Ok(())
    }
}

/// A claim extracted from a proof only after `verify_cairo` succeeds.
///
/// Its fields are private and there is no public constructor. This prevents a
/// host-provided success flag from being confused with cryptographic evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedExecution {
    output: RelationOutputV3,
    program_commitment: [u8; 32],
    stwo_policy_commitment: [u8; 32],
}

impl VerifiedExecution {
    #[cfg(any(test, feature = "upstream-stwo"))]
    pub(crate) fn from_cryptographic_verifier(
        output: RelationOutputV3,
        program_commitment: [u8; 32],
        stwo_policy_commitment: [u8; 32],
    ) -> Self {
        Self {
            output,
            program_commitment,
            stwo_policy_commitment,
        }
    }

    pub fn output(&self) -> &RelationOutputV3 {
        &self.output
    }

    /// Returns the only journal shape allowed to reach Boundless. Failure means
    /// the guest must abort and commit no authorization journal.
    pub fn authorization_journal(
        &self,
        policy: &VerificationPolicy,
    ) -> Result<AuthorizationJournal, BindingError> {
        policy.validate()?;
        if self.program_commitment != policy.expected_program_commitment {
            return Err(BindingError::ProgramMismatch);
        }
        if self.stwo_policy_commitment != policy.expected_stwo_policy_commitment {
            return Err(BindingError::PolicyMismatch);
        }
        if !self.output.transaction_relation_valid() {
            return Err(BindingError::TransactionRelationInvalid);
        }
        if !self.output.chain_state_verified() {
            return Err(BindingError::ChainStateNotVerified);
        }
        if !self.output.operator_take_authorized() {
            return Err(BindingError::OperatorTakeNotAuthorized);
        }
        Ok(AuthorizationJournal(self.output.statement_digest()))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationJournal([u8; 32]);

impl AuthorizationJournal {
    pub const LEN: usize = 32;

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[cfg(any(test, feature = "upstream-stwo"))]
pub(crate) fn program_commitment_from_cells(cells: &[(u32, [u32; 8])]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROGRAM_DOMAIN);
    hasher.update((cells.len() as u64).to_be_bytes());
    for (id, limbs) in cells {
        hasher.update(id.to_be_bytes());
        for limb in limbs {
            hasher.update(limb.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

#[cfg(any(test, feature = "upstream-stwo"))]
pub(crate) fn stwo_policy_commitment(serialized_policy: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_DOMAIN);
    hasher.update((serialized_policy.len() as u64).to_be_bytes());
    hasher.update(serialized_policy);
    hasher.finalize().into()
}

fn words_to_be_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROGRAM: [u8; 32] = [0x11; 32];
    const STWO_POLICY: [u8; 32] = [0x22; 32];

    fn words(flags: [u32; 3]) -> [u32; OUTPUT_WORDS_V3] {
        let mut words = [0u32; OUTPUT_WORDS_V3];
        words[..3].copy_from_slice(&flags);
        words[3..11].copy_from_slice(&[
            0x0102_0304,
            0x1112_1314,
            0x2122_2324,
            0x3132_3334,
            0x4142_4344,
            0x5152_5354,
            0x6162_6364,
            0x7172_7374,
        ]);
        words[11..].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        words
    }

    fn verified(flags: [u32; 3]) -> VerifiedExecution {
        VerifiedExecution::from_cryptographic_verifier(
            RelationOutputV3::parse(&words(flags)).unwrap(),
            PROGRAM,
            STWO_POLICY,
        )
    }

    fn policy() -> VerificationPolicy {
        VerificationPolicy::new(PROGRAM, STWO_POLICY)
    }

    #[test]
    fn exact_output_schema_and_big_endian_digest_are_bound() {
        let output = RelationOutputV3::parse(&words([1, 1, 1])).unwrap();
        assert_eq!(
            &output.statement_digest()[..8],
            &[1, 2, 3, 4, 0x11, 0x12, 0x13, 0x14]
        );
        assert!(matches!(
            RelationOutputV3::parse(&words([1, 1, 1])[..18]),
            Err(BindingError::WrongOutputWordCount { actual: 18, .. })
        ));
    }

    #[test]
    fn non_boolean_flags_are_rejected() {
        assert_eq!(
            RelationOutputV3::parse(&words([1, 2, 1])),
            Err(BindingError::NonBooleanFlag {
                field: "chain_state_verified",
                value: 2,
            })
        );
    }

    #[test]
    fn current_relation_output_cannot_authorize() {
        let current = verified([1, 0, 0]);
        assert_eq!(
            current.authorization_journal(&policy()),
            Err(BindingError::ChainStateNotVerified)
        );
    }

    #[test]
    fn every_authorization_flag_is_required() {
        assert_eq!(
            verified([0, 1, 1]).authorization_journal(&policy()),
            Err(BindingError::TransactionRelationInvalid)
        );
        assert_eq!(
            verified([1, 0, 1]).authorization_journal(&policy()),
            Err(BindingError::ChainStateNotVerified)
        );
        assert_eq!(
            verified([1, 1, 0]).authorization_journal(&policy()),
            Err(BindingError::OperatorTakeNotAuthorized)
        );
    }

    #[test]
    fn pins_are_mandatory_and_exact() {
        assert_eq!(
            verified([1, 1, 1])
                .authorization_journal(&VerificationPolicy::new([0; 32], STWO_POLICY)),
            Err(BindingError::MissingProgramPin)
        );
        assert_eq!(
            verified([1, 1, 1]).authorization_journal(&VerificationPolicy::new(PROGRAM, [0; 32])),
            Err(BindingError::MissingPolicyPin)
        );
        assert_eq!(
            verified([1, 1, 1])
                .authorization_journal(&VerificationPolicy::new([0x33; 32], STWO_POLICY)),
            Err(BindingError::ProgramMismatch)
        );
        assert_eq!(
            verified([1, 1, 1])
                .authorization_journal(&VerificationPolicy::new(PROGRAM, [0x44; 32])),
            Err(BindingError::PolicyMismatch)
        );
    }

    #[test]
    fn fully_verified_bound_claim_emits_exactly_32_bytes() {
        let output = words([1, 1, 1]);
        let journal = verified([1, 1, 1])
            .authorization_journal(&policy())
            .unwrap();
        assert_eq!(AuthorizationJournal::LEN, 32);
        assert_eq!(
            journal.as_bytes(),
            &RelationOutputV3::parse(&output).unwrap().statement_digest()
        );
    }

    #[test]
    fn commitments_are_domain_separated_and_length_bound() {
        let a = program_commitment_from_cells(&[(7, [1, 2, 3, 4, 5, 6, 7, 8])]);
        let b = program_commitment_from_cells(&[(8, [1, 2, 3, 4, 5, 6, 7, 8])]);
        let c = stwo_policy_commitment(&[7, 1, 2, 3, 4]);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }
}
