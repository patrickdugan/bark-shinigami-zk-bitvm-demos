//! Claim-specific BitVM2 manifest for the Boundless-wrapped proof path.

use crate::bitvm2_proof::{
    expected_boundless_claim_digest, Risc0StwoBindingError, Risc0StwoBindingV1,
    RISC0_STWO_BINDING_V1_LEN,
};
use crate::boundless::{
    encode_hex, Blake3Groth16Receipt, CanonicalPublicScalar, BLAKE3_GROTH16_V0_1_SELECTOR,
};
use ark::bitcoin::hashes::{sha256, Hash};
use core::fmt;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const BITVM2_CLAIM_MANIFEST_SCHEMA: &str = "bark-bitvm2-claim-manifest-v1";
pub const BITVM2_ARTIFACT_COMPLETE_MANIFEST_SCHEMA: &str =
    "bark-bitvm2-artifact-complete-manifest-v2";
pub const BOUNDLESS_SEPOLIA_CHAIN_ID: u64 = 11_155_111;
pub const BOUNDLESS_BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Regtest,
    Signet,
}

impl BitcoinNetwork {
    fn as_str(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Signet => "signet",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactKind {
    StatementEnvelope,
    StwoProgram,
    StwoProof,
    StwoPolicy,
    Risc0GuestElf,
    Risc0GuestInput,
    BoundlessSeal,
    Bitvm2Graph,
    CairoExecutable,
    Risc0StwoBinding,
    ClaimSpecializedKey,
}

impl ArtifactKind {
    const REQUIRED: [Self; 8] = [
        Self::StatementEnvelope,
        Self::StwoProgram,
        Self::StwoProof,
        Self::StwoPolicy,
        Self::Risc0GuestElf,
        Self::Risc0GuestInput,
        Self::BoundlessSeal,
        Self::Bitvm2Graph,
    ];

    const REQUIRED_V2: [Self; 10] = [
        Self::StatementEnvelope,
        Self::CairoExecutable,
        Self::StwoProof,
        Self::StwoPolicy,
        Self::Risc0GuestElf,
        Self::Risc0GuestInput,
        Self::Risc0StwoBinding,
        Self::BoundlessSeal,
        Self::ClaimSpecializedKey,
        Self::Bitvm2Graph,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::StatementEnvelope => "statement_envelope",
            Self::StwoProgram => "stwo_program",
            Self::StwoProof => "stwo_proof",
            Self::StwoPolicy => "stwo_policy",
            Self::Risc0GuestElf => "risc0_guest_elf",
            Self::Risc0GuestInput => "risc0_guest_input",
            Self::BoundlessSeal => "boundless_seal",
            Self::Bitvm2Graph => "bitvm2_graph",
            Self::CairoExecutable => "cairo_executable",
            Self::Risc0StwoBinding => "risc0_stwo_binding",
            Self::ClaimSpecializedKey => "claim_specialized_key",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactProvenance {
    pub kind: ArtifactKind,
    pub github_repository: String,
    pub git_commit: String,
    pub release_tag: String,
    pub file_name: String,
    pub download_url: String,
    pub sha256: [u8; 32],
    pub byte_len: u64,
}

impl ArtifactProvenance {
    pub fn validate(&self) -> Result<(), ManifestError> {
        validate_github_repository(&self.github_repository)?;
        if !is_lower_hex(&self.git_commit, 40) {
            return Err(ManifestError::NonCanonicalGitCommit { kind: self.kind });
        }
        if !is_safe_release_component(&self.release_tag)
            || !is_safe_release_component(&self.file_name)
        {
            return Err(ManifestError::UnsafeReleasePath { kind: self.kind });
        }
        let expected_url = format!(
            "{}/releases/download/{}/{}",
            self.github_repository, self.release_tag, self.file_name
        );
        if self.download_url != expected_url {
            return Err(ManifestError::ReleaseUrlMismatch { kind: self.kind });
        }
        if self.byte_len == 0 {
            return Err(ManifestError::EmptyArtifact { kind: self.kind });
        }
        if self.sha256 == [0; 32] {
            return Err(ManifestError::ZeroArtifactHash { kind: self.kind });
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "github_repository": self.github_repository,
            "git_commit": self.git_commit,
            "release_tag": self.release_tag,
            "file_name": self.file_name,
            "download_url": self.download_url,
            "sha256": encode_hex(&self.sha256),
            "byte_len": self.byte_len,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundlessRequestProvenance {
    pub chain_id: u64,
    pub market_contract: [u8; 20],
    pub request_id: [u8; 32],
    pub boundless_git_commit: String,
}

impl BoundlessRequestProvenance {
    fn validate(&self) -> Result<(), ManifestError> {
        if !matches!(
            self.chain_id,
            BOUNDLESS_SEPOLIA_CHAIN_ID | BOUNDLESS_BASE_SEPOLIA_CHAIN_ID
        ) {
            return Err(ManifestError::UnsupportedBoundlessChain(self.chain_id));
        }
        if self.market_contract == [0; 20] {
            return Err(ManifestError::ZeroMarketContract);
        }
        if self.request_id == [0; 32] {
            return Err(ManifestError::ZeroRequestId);
        }
        if !is_lower_hex(&self.boundless_git_commit, 40) {
            return Err(ManifestError::NonCanonicalBoundlessCommit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ManifestParams {
    pub network: BitcoinNetwork,
    pub contract_nonce: [u8; 32],
    pub statement_digest: [u8; 32],
    pub risc0_image_id: [u8; 32],
    pub expected_boundless_claim_digest: [u8; 32],
    pub boundless_request: BoundlessRequestProvenance,
    /// Hash of the claim-specialized key (IC0 + claim*IC1, identity runtime
    /// base), not the generic Boundless verification key.
    pub boundless_verifying_key_sha256: [u8; 32],
    pub bitvm2_graph_sha256: [u8; 32],
    pub verifier_public_input_count: usize,
    /// Claim scalar folded into the specialized key. The official BitVM API is
    /// invoked with a zero runtime scalar after this specialization.
    pub bitvm2_expected_public_scalar: [u8; 32],
    pub artifacts: Vec<ArtifactProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    ZeroContractNonce,
    ZeroCriticalDigest { field: &'static str },
    JournalStatementMismatch,
    ClaimDigestMismatch,
    VerifierPublicInputCount { actual: usize },
    NonCanonicalBitvm2PublicScalar,
    Bitvm2PublicScalarMismatch,
    UnsupportedBoundlessChain(u64),
    ZeroMarketContract,
    ZeroRequestId,
    NonCanonicalBoundlessCommit,
    NotGithubRepository,
    NonCanonicalGithubRepository,
    NonCanonicalGitCommit { kind: ArtifactKind },
    UnsafeReleasePath { kind: ArtifactKind },
    ReleaseUrlMismatch { kind: ArtifactKind },
    EmptyArtifact { kind: ArtifactKind },
    ZeroArtifactHash { kind: ArtifactKind },
    DuplicateArtifact { kind: ArtifactKind },
    MissingArtifact { kind: ArtifactKind },
    BoundlessSealLength { actual: u64 },
    BoundlessSealHashMismatch,
    Bitvm2GraphHashMismatch,
    InvalidRisc0StwoBinding(Risc0StwoBindingError),
    JournalArtifactBindingMismatch,
    ClaimDigestForBindingMismatch,
    RuntimePublicInputCount { actual: usize },
    NonzeroRuntimePublicInput,
    ArtifactBindingMismatch { kind: ArtifactKind },
    ClaimSpecializedKeyHashMismatch,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroContractNonce => write!(f, "contract nonce must not be zero"),
            Self::ZeroCriticalDigest { field } => {
                write!(f, "critical digest {field} must not be zero")
            }
            Self::JournalStatementMismatch => {
                write!(
                    f,
                    "the 32-byte Boundless journal is not the statement digest"
                )
            }
            Self::ClaimDigestMismatch => {
                write!(f, "receipt claim digest differs from the request predicate")
            }
            Self::VerifierPublicInputCount { actual } => write!(
                f,
                "BitVM2 graph must expose exactly one public input, got {actual}"
            ),
            Self::NonCanonicalBitvm2PublicScalar => {
                write!(f, "BitVM2 graph public scalar is not canonical BN254")
            }
            Self::Bitvm2PublicScalarMismatch => {
                write!(f, "BitVM2 graph is bound to a different public scalar")
            }
            Self::UnsupportedBoundlessChain(chain) => {
                write!(f, "Boundless chain {chain} is not an approved test network")
            }
            Self::ZeroMarketContract => write!(f, "Boundless market contract must not be zero"),
            Self::ZeroRequestId => write!(f, "Boundless request id must not be zero"),
            Self::NonCanonicalBoundlessCommit => {
                write!(
                    f,
                    "Boundless commit must be 40 lowercase hexadecimal characters"
                )
            }
            Self::NotGithubRepository => write!(f, "artifact repository must be on github.com"),
            Self::NonCanonicalGithubRepository => {
                write!(f, "GitHub repository URL is not canonical")
            }
            Self::NonCanonicalGitCommit { kind } => write!(
                f,
                "{} commit must be 40 lowercase hexadecimal characters",
                kind.as_str()
            ),
            Self::UnsafeReleasePath { kind } => {
                write!(f, "{} has an unsafe release tag or filename", kind.as_str())
            }
            Self::ReleaseUrlMismatch { kind } => write!(
                f,
                "{} download URL does not match its pinned GitHub release",
                kind.as_str()
            ),
            Self::EmptyArtifact { kind } => {
                write!(f, "{} artifact must not be empty", kind.as_str())
            }
            Self::ZeroArtifactHash { kind } => {
                write!(f, "{} artifact hash must not be zero", kind.as_str())
            }
            Self::DuplicateArtifact { kind } => {
                write!(f, "duplicate {} artifact", kind.as_str())
            }
            Self::MissingArtifact { kind } => write!(f, "missing {} artifact", kind.as_str()),
            Self::BoundlessSealLength { actual } => {
                write!(f, "Boundless seal artifact must be 260 bytes, got {actual}")
            }
            Self::BoundlessSealHashMismatch => {
                write!(
                    f,
                    "Boundless seal artifact hash does not match parsed receipt"
                )
            }
            Self::Bitvm2GraphHashMismatch => {
                write!(
                    f,
                    "BitVM2 graph artifact hash does not match verifier binding"
                )
            }
            Self::InvalidRisc0StwoBinding(error) => {
                write!(f, "invalid RISC Zero/STWO binding: {error}")
            }
            Self::JournalArtifactBindingMismatch => write!(
                f,
                "the Boundless journal is not the artifact-complete binding digest"
            ),
            Self::ClaimDigestForBindingMismatch => write!(
                f,
                "the Boundless claim does not bind the v2 image ID and journal"
            ),
            Self::RuntimePublicInputCount { actual } => write!(
                f,
                "claim-specialized BitVM graph must have one runtime input, got {actual}"
            ),
            Self::NonzeroRuntimePublicInput => write!(
                f,
                "claim-specialized BitVM graph runtime input must be zero"
            ),
            Self::ArtifactBindingMismatch { kind } => write!(
                f,
                "{} artifact does not match the journal binding",
                kind.as_str()
            ),
            Self::ClaimSpecializedKeyHashMismatch => write!(
                f,
                "claim-specialized key artifact hash does not match the verifier binding"
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<Risc0StwoBindingError> for ManifestError {
    fn from(value: Risc0StwoBindingError) -> Self {
        Self::InvalidRisc0StwoBinding(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitvm2ClaimManifestV1 {
    network: BitcoinNetwork,
    contract_nonce: [u8; 32],
    statement_digest: [u8; 32],
    risc0_image_id: [u8; 32],
    boundless_claim_digest: [u8; 32],
    boundless_public_scalar: [u8; 32],
    boundless_request: BoundlessRequestProvenance,
    boundless_verifying_key_sha256: [u8; 32],
    bitvm2_graph_sha256: [u8; 32],
    artifacts: Vec<ArtifactProvenance>,
}

impl Bitvm2ClaimManifestV1 {
    pub fn new(
        params: ManifestParams,
        receipt: &Blake3Groth16Receipt,
    ) -> Result<Self, ManifestError> {
        if params.contract_nonce == [0; 32] {
            return Err(ManifestError::ZeroContractNonce);
        }
        for (field, digest) in [
            ("statement_digest", &params.statement_digest),
            ("risc0_image_id", &params.risc0_image_id),
            (
                "expected_boundless_claim_digest",
                &params.expected_boundless_claim_digest,
            ),
            (
                "boundless_verifying_key_sha256",
                &params.boundless_verifying_key_sha256,
            ),
            ("bitvm2_graph_sha256", &params.bitvm2_graph_sha256),
        ] {
            if digest == &[0; 32] {
                return Err(ManifestError::ZeroCriticalDigest { field });
            }
        }
        if receipt.journal() != &params.statement_digest {
            return Err(ManifestError::JournalStatementMismatch);
        }
        if receipt.claim_digest() != &params.expected_boundless_claim_digest {
            return Err(ManifestError::ClaimDigestMismatch);
        }
        if params.verifier_public_input_count != 1 {
            return Err(ManifestError::VerifierPublicInputCount {
                actual: params.verifier_public_input_count,
            });
        }
        let graph_scalar = CanonicalPublicScalar::parse(&params.bitvm2_expected_public_scalar)
            .map_err(|_| ManifestError::NonCanonicalBitvm2PublicScalar)?;
        if graph_scalar != receipt.public_scalar() {
            return Err(ManifestError::Bitvm2PublicScalarMismatch);
        }
        params.boundless_request.validate()?;

        let mut kinds = BTreeSet::new();
        for artifact in &params.artifacts {
            artifact.validate()?;
            if !kinds.insert(artifact.kind) {
                return Err(ManifestError::DuplicateArtifact {
                    kind: artifact.kind,
                });
            }
        }
        for kind in ArtifactKind::REQUIRED {
            if !kinds.contains(&kind) {
                return Err(ManifestError::MissingArtifact { kind });
            }
        }

        let seal_artifact = params
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == ArtifactKind::BoundlessSeal)
            .expect("required kind checked above");
        if seal_artifact.byte_len != 260 {
            return Err(ManifestError::BoundlessSealLength {
                actual: seal_artifact.byte_len,
            });
        }
        let seal_hash = sha256::Hash::hash(&receipt.seal()).to_byte_array();
        if seal_artifact.sha256 != seal_hash {
            return Err(ManifestError::BoundlessSealHashMismatch);
        }

        let graph_artifact = params
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == ArtifactKind::Bitvm2Graph)
            .expect("required kind checked above");
        if graph_artifact.sha256 != params.bitvm2_graph_sha256 {
            return Err(ManifestError::Bitvm2GraphHashMismatch);
        }

        let mut artifacts = params.artifacts;
        artifacts.sort_by_key(|artifact| artifact.kind);

        Ok(Self {
            network: params.network,
            contract_nonce: params.contract_nonce,
            statement_digest: params.statement_digest,
            risc0_image_id: params.risc0_image_id,
            boundless_claim_digest: params.expected_boundless_claim_digest,
            boundless_public_scalar: *receipt.public_scalar().as_bytes(),
            boundless_request: params.boundless_request,
            boundless_verifying_key_sha256: params.boundless_verifying_key_sha256,
            bitvm2_graph_sha256: params.bitvm2_graph_sha256,
            artifacts,
        })
    }

    pub fn statement_digest(&self) -> &[u8; 32] {
        &self.statement_digest
    }

    pub fn boundless_public_scalar(&self) -> &[u8; 32] {
        &self.boundless_public_scalar
    }

    pub fn to_json_value(&self) -> Value {
        json!({
            "schema": BITVM2_CLAIM_MANIFEST_SCHEMA,
            "bitcoin_network": self.network.as_str(),
            "contract_nonce": encode_hex(&self.contract_nonce),
            "statement_digest": encode_hex(&self.statement_digest),
            "risc0_image_id": encode_hex(&self.risc0_image_id),
            "boundless": {
                "selector": encode_hex(&BLAKE3_GROTH16_V0_1_SELECTOR),
                "claim_digest": encode_hex(&self.boundless_claim_digest),
                "public_inputs": [encode_hex(&self.boundless_public_scalar)],
                "request": {
                    "chain_id": self.boundless_request.chain_id,
                    "market_contract": encode_hex(&self.boundless_request.market_contract),
                    "request_id": encode_hex(&self.boundless_request.request_id),
                    "boundless_git_commit": self.boundless_request.boundless_git_commit,
                },
                "verifying_key_sha256": encode_hex(&self.boundless_verifying_key_sha256),
            },
            "bitvm2": {
                "public_input_count": 1,
                "graph_sha256": encode_hex(&self.bitvm2_graph_sha256),
            },
            "artifacts": self.artifacts.iter().map(ArtifactProvenance::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Inputs for the artifact-complete recursion profile. Unlike v1, the Bark
/// statement digest is nested inside `risc0_stwo_binding`; the receipt journal
/// is the tagged digest of that entire record.
#[derive(Debug, Clone)]
pub struct ManifestParamsV2 {
    pub network: BitcoinNetwork,
    pub risc0_stwo_binding: Risc0StwoBindingV1,
    pub expected_boundless_claim_digest: [u8; 32],
    pub boundless_request: BoundlessRequestProvenance,
    /// SHA-256 of the canonical claim-specialized `VK_C` bytes.
    pub claim_specialized_verifying_key_sha256: [u8; 32],
    pub bitvm2_graph_sha256: [u8; 32],
    /// Must be exactly `[Fr::ZERO]`: the claim scalar is already folded into
    /// the specialized key.
    pub bitvm2_runtime_public_inputs: Vec<[u8; 32]>,
    pub artifacts: Vec<ArtifactProvenance>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bitvm2ArtifactCompleteManifestV2 {
    network: BitcoinNetwork,
    binding: Risc0StwoBindingV1,
    journal_digest: [u8; 32],
    boundless_claim_digest: [u8; 32],
    boundless_request: BoundlessRequestProvenance,
    claim_specialized_verifying_key_sha256: [u8; 32],
    bitvm2_graph_sha256: [u8; 32],
    artifacts: Vec<ArtifactProvenance>,
}

impl Bitvm2ArtifactCompleteManifestV2 {
    pub fn new(
        params: ManifestParamsV2,
        receipt: &Blake3Groth16Receipt,
    ) -> Result<Self, ManifestError> {
        params.risc0_stwo_binding.validate()?;
        for (field, digest) in [
            (
                "expected_boundless_claim_digest",
                &params.expected_boundless_claim_digest,
            ),
            (
                "claim_specialized_verifying_key_sha256",
                &params.claim_specialized_verifying_key_sha256,
            ),
            ("bitvm2_graph_sha256", &params.bitvm2_graph_sha256),
        ] {
            if digest == &[0; 32] {
                return Err(ManifestError::ZeroCriticalDigest { field });
            }
        }

        let binding_bytes = params.risc0_stwo_binding.canonical_bytes()?;
        let journal_digest = params.risc0_stwo_binding.journal_digest()?;
        if receipt.journal() != &journal_digest {
            return Err(ManifestError::JournalArtifactBindingMismatch);
        }
        if receipt.claim_digest() != &params.expected_boundless_claim_digest {
            return Err(ManifestError::ClaimDigestMismatch);
        }
        let reconstructed_claim = expected_boundless_claim_digest(
            &params.risc0_stwo_binding.expected_risc0_image_id,
            &journal_digest,
        )
        .map_err(|_| ManifestError::ClaimDigestForBindingMismatch)?;
        if reconstructed_claim != params.expected_boundless_claim_digest {
            return Err(ManifestError::ClaimDigestForBindingMismatch);
        }
        if params.bitvm2_runtime_public_inputs.len() != 1 {
            return Err(ManifestError::RuntimePublicInputCount {
                actual: params.bitvm2_runtime_public_inputs.len(),
            });
        }
        if params.bitvm2_runtime_public_inputs[0] != [0; 32] {
            return Err(ManifestError::NonzeroRuntimePublicInput);
        }
        params.boundless_request.validate()?;

        let mut kinds = BTreeSet::new();
        for artifact in &params.artifacts {
            artifact.validate()?;
            if !kinds.insert(artifact.kind) {
                return Err(ManifestError::DuplicateArtifact {
                    kind: artifact.kind,
                });
            }
        }
        for kind in ArtifactKind::REQUIRED_V2 {
            if !kinds.contains(&kind) {
                return Err(ManifestError::MissingArtifact { kind });
            }
        }

        let artifact = |kind| {
            params
                .artifacts
                .iter()
                .find(|artifact| artifact.kind == kind)
                .expect("required v2 kind checked above")
        };
        let seal_artifact = artifact(ArtifactKind::BoundlessSeal);
        if seal_artifact.byte_len != 260 {
            return Err(ManifestError::BoundlessSealLength {
                actual: seal_artifact.byte_len,
            });
        }
        if seal_artifact.sha256 != sha256::Hash::hash(&receipt.seal()).to_byte_array() {
            return Err(ManifestError::BoundlessSealHashMismatch);
        }

        for (kind, expected_hash, expected_len) in [
            (
                ArtifactKind::StatementEnvelope,
                params.risc0_stwo_binding.envelope_sha256,
                Some(params.risc0_stwo_binding.envelope_len as u64),
            ),
            (
                ArtifactKind::CairoExecutable,
                params.risc0_stwo_binding.executable_sha256,
                None,
            ),
            (
                ArtifactKind::StwoProof,
                params.risc0_stwo_binding.compressed_proof_sha256,
                Some(params.risc0_stwo_binding.compressed_proof_len),
            ),
            (
                ArtifactKind::StwoPolicy,
                params.risc0_stwo_binding.stwo_policy_digest,
                None,
            ),
            (
                ArtifactKind::Risc0StwoBinding,
                sha256::Hash::hash(&binding_bytes).to_byte_array(),
                Some(RISC0_STWO_BINDING_V1_LEN as u64),
            ),
        ] {
            let candidate = artifact(kind);
            if candidate.sha256 != expected_hash
                || expected_len.is_some_and(|length| candidate.byte_len != length)
            {
                return Err(ManifestError::ArtifactBindingMismatch { kind });
            }
        }

        if artifact(ArtifactKind::ClaimSpecializedKey).sha256
            != params.claim_specialized_verifying_key_sha256
        {
            return Err(ManifestError::ClaimSpecializedKeyHashMismatch);
        }
        if artifact(ArtifactKind::Bitvm2Graph).sha256 != params.bitvm2_graph_sha256 {
            return Err(ManifestError::Bitvm2GraphHashMismatch);
        }

        let mut artifacts = params.artifacts;
        artifacts.sort_by_key(|artifact| artifact.kind);
        Ok(Self {
            network: params.network,
            binding: params.risc0_stwo_binding,
            journal_digest,
            boundless_claim_digest: params.expected_boundless_claim_digest,
            boundless_request: params.boundless_request,
            claim_specialized_verifying_key_sha256: params.claim_specialized_verifying_key_sha256,
            bitvm2_graph_sha256: params.bitvm2_graph_sha256,
            artifacts,
        })
    }

    pub fn journal_digest(&self) -> &[u8; 32] {
        &self.journal_digest
    }

    pub fn to_json_value(&self) -> Value {
        json!({
            "schema": BITVM2_ARTIFACT_COMPLETE_MANIFEST_SCHEMA,
            "bitcoin_network": self.network.as_str(),
            "journal": {
                "profile": "risc0-stwo-journal-v1",
                "digest": encode_hex(&self.journal_digest),
                "binding": {
                    "stwo_cairo_git_commit": encode_hex(&self.binding.stwo_cairo_git_commit),
                    "public_segment_patch_sha256": encode_hex(&self.binding.public_segment_patch_sha256),
                    "executable_sha256": encode_hex(&self.binding.executable_sha256),
                    "stwo_program_hash_be": encode_hex(&self.binding.stwo_program_hash_be),
                    "stwo_policy_digest": encode_hex(&self.binding.stwo_policy_digest),
                    "compressed_proof_len": self.binding.compressed_proof_len,
                    "compressed_proof_sha256": encode_hex(&self.binding.compressed_proof_sha256),
                    "envelope_len": self.binding.envelope_len,
                    "envelope_sha256": encode_hex(&self.binding.envelope_sha256),
                    "contract_nonce": encode_hex(&self.binding.contract_nonce),
                    "bark_statement_digest": encode_hex(&self.binding.bark_statement_digest),
                    "output_schema": self.binding.output_schema,
                    "output_word_count": self.binding.output_word_count,
                    "output_prefix": self.binding.output_prefix,
                    "full_output_sha256": encode_hex(&self.binding.full_output_sha256),
                    "expected_risc0_image_id": encode_hex(&self.binding.expected_risc0_image_id),
                },
            },
            "boundless": {
                "selector": encode_hex(&BLAKE3_GROTH16_V0_1_SELECTOR),
                "claim_digest": encode_hex(&self.boundless_claim_digest),
                "verification_public_inputs": [encode_hex(&self.boundless_claim_digest)],
                "request": {
                    "chain_id": self.boundless_request.chain_id,
                    "market_contract": encode_hex(&self.boundless_request.market_contract),
                    "request_id": encode_hex(&self.boundless_request.request_id),
                    "boundless_git_commit": self.boundless_request.boundless_git_commit,
                },
            },
            "bitvm2": {
                "claim_specialized_verifying_key_sha256": encode_hex(
                    &self.claim_specialized_verifying_key_sha256
                ),
                "runtime_public_inputs": [encode_hex(&[0; 32])],
                "graph_sha256": encode_hex(&self.bitvm2_graph_sha256),
            },
            "artifacts": self.artifacts.iter().map(ArtifactProvenance::to_json).collect::<Vec<_>>(),
        })
    }
}

fn validate_github_repository(repository: &str) -> Result<(), ManifestError> {
    let Some(path) = repository.strip_prefix("https://github.com/") else {
        return Err(ManifestError::NotGithubRepository);
    };
    let mut components = path.split('/');
    let owner = components.next().unwrap_or_default();
    let repo = components.next().unwrap_or_default();
    if owner.is_empty()
        || repo.is_empty()
        || matches!(owner, "." | "..")
        || matches!(repo, "." | "..")
        || components.next().is_some()
        || repo.ends_with(".git")
        || !owner.bytes().all(is_github_component_byte)
        || !repo.bytes().all(is_github_component_byte)
    {
        return Err(ManifestError::NonCanonicalGithubRepository);
    }
    Ok(())
}

fn is_github_component_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn is_safe_release_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundless::{Blake3Groth16Receipt, BLAKE3_GROTH16_SEAL_LEN};

    const REPO: &str = "https://github.com/example/bark-zk-showcase";
    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn receipt() -> Blake3Groth16Receipt {
        let mut seal = [0xabu8; BLAKE3_GROTH16_SEAL_LEN];
        seal[..4].copy_from_slice(&BLAKE3_GROTH16_V0_1_SELECTOR);
        let statement = [0x11; 32];
        let mut claim = [0x22; 32];
        claim[0] = 0;
        Blake3Groth16Receipt::parse_seal(&seal, &statement, &claim, &[&claim]).unwrap()
    }

    fn artifact(kind: ArtifactKind, sha256: [u8; 32], byte_len: u64) -> ArtifactProvenance {
        let file_name = format!("{}.bin", kind.as_str());
        ArtifactProvenance {
            kind,
            github_repository: REPO.to_owned(),
            git_commit: COMMIT.to_owned(),
            release_tag: "v0.1.0-test".to_owned(),
            download_url: format!("{REPO}/releases/download/v0.1.0-test/{file_name}"),
            file_name,
            sha256,
            byte_len,
        }
    }

    fn params(receipt: &Blake3Groth16Receipt) -> ManifestParams {
        let seal_hash = sha256::Hash::hash(&receipt.seal()).to_byte_array();
        let graph_hash = [0x88; 32];
        let artifacts = ArtifactKind::REQUIRED
            .into_iter()
            .map(|kind| match kind {
                ArtifactKind::BoundlessSeal => artifact(kind, seal_hash, 260),
                ArtifactKind::Bitvm2Graph => artifact(kind, graph_hash, 8_000),
                _ => artifact(kind, [kind as u8 + 1; 32], 100),
            })
            .collect();
        ManifestParams {
            network: BitcoinNetwork::Signet,
            contract_nonce: [0x44; 32],
            statement_digest: *receipt.journal(),
            risc0_image_id: [0x55; 32],
            expected_boundless_claim_digest: *receipt.claim_digest(),
            boundless_request: BoundlessRequestProvenance {
                chain_id: BOUNDLESS_SEPOLIA_CHAIN_ID,
                market_contract: [0x66; 20],
                request_id: [0x77; 32],
                boundless_git_commit: COMMIT.to_owned(),
            },
            boundless_verifying_key_sha256: [0x99; 32],
            bitvm2_graph_sha256: graph_hash,
            verifier_public_input_count: 1,
            bitvm2_expected_public_scalar: *receipt.claim_digest(),
            artifacts,
        }
    }

    fn decode<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    fn binding_v2() -> Risc0StwoBindingV1 {
        Risc0StwoBindingV1 {
            stwo_cairo_git_commit: decode("b1acf8bfd9fda45e7c2c28553b750f87aefeb9b1"),
            public_segment_patch_sha256: decode(
                "ed5027b67ee3798ef2f1467604816cc5efb8e44cedf6083d329ae8f8e4227a71",
            ),
            executable_sha256: [0x11; 32],
            stwo_program_hash_be: decode(
                "00bcd09f617edcfc9ee2bbbb74192f42dfed6b7a505578a3748ac93f8ad697f0",
            ),
            stwo_policy_digest: decode(
                "cc48a057589ddbcf51c8458db65640609f21dac3afa485f717089806567dbece",
            ),
            compressed_proof_len: 1_117_271,
            compressed_proof_sha256: [0x22; 32],
            envelope_len: 4096,
            envelope_sha256: [0x33; 32],
            contract_nonce: [0x44; 32],
            bark_statement_digest: [0x55; 32],
            output_schema: 3,
            output_word_count: 19,
            output_prefix: [1, 0, 0],
            full_output_sha256: [0x66; 32],
            expected_risc0_image_id: [0x77; 32],
        }
    }

    fn receipt_v2(binding: &Risc0StwoBindingV1) -> Blake3Groth16Receipt {
        let journal = binding.journal_digest().unwrap();
        let claim =
            expected_boundless_claim_digest(&binding.expected_risc0_image_id, &journal).unwrap();
        let mut seal = [0xabu8; BLAKE3_GROTH16_SEAL_LEN];
        seal[..4].copy_from_slice(&BLAKE3_GROTH16_V0_1_SELECTOR);
        Blake3Groth16Receipt::parse_seal(&seal, &journal, &claim, &[&claim]).unwrap()
    }

    fn params_v2(binding: Risc0StwoBindingV1, receipt: &Blake3Groth16Receipt) -> ManifestParamsV2 {
        let binding_bytes = binding.canonical_bytes().unwrap();
        let seal_hash = sha256::Hash::hash(&receipt.seal()).to_byte_array();
        let key_hash = [0x99; 32];
        let graph_hash = [0x88; 32];
        let artifacts = ArtifactKind::REQUIRED_V2
            .into_iter()
            .map(|kind| match kind {
                ArtifactKind::StatementEnvelope => {
                    artifact(kind, binding.envelope_sha256, binding.envelope_len as u64)
                }
                ArtifactKind::CairoExecutable => {
                    artifact(kind, binding.executable_sha256, 1_000_000)
                }
                ArtifactKind::StwoProof => artifact(
                    kind,
                    binding.compressed_proof_sha256,
                    binding.compressed_proof_len,
                ),
                ArtifactKind::StwoPolicy => artifact(kind, binding.stwo_policy_digest, 100),
                ArtifactKind::Risc0StwoBinding => artifact(
                    kind,
                    sha256::Hash::hash(&binding_bytes).to_byte_array(),
                    RISC0_STWO_BINDING_V1_LEN as u64,
                ),
                ArtifactKind::BoundlessSeal => artifact(kind, seal_hash, 260),
                ArtifactKind::ClaimSpecializedKey => artifact(kind, key_hash, 1024),
                ArtifactKind::Bitvm2Graph => artifact(kind, graph_hash, 8_000),
                _ => artifact(kind, [kind as u8 + 1; 32], 100),
            })
            .collect();
        ManifestParamsV2 {
            network: BitcoinNetwork::Signet,
            risc0_stwo_binding: binding,
            expected_boundless_claim_digest: *receipt.claim_digest(),
            boundless_request: BoundlessRequestProvenance {
                chain_id: BOUNDLESS_SEPOLIA_CHAIN_ID,
                market_contract: [0x66; 20],
                request_id: [0x77; 32],
                boundless_git_commit: COMMIT.to_owned(),
            },
            claim_specialized_verifying_key_sha256: key_hash,
            bitvm2_graph_sha256: graph_hash,
            bitvm2_runtime_public_inputs: vec![[0; 32]],
            artifacts,
        }
    }

    #[test]
    fn builds_a_claim_bound_single_input_manifest() {
        let receipt = receipt();
        let manifest = Bitvm2ClaimManifestV1::new(params(&receipt), &receipt).unwrap();
        assert_eq!(manifest.statement_digest(), receipt.journal());
        assert_eq!(manifest.boundless_public_scalar(), receipt.claim_digest());
        let json = manifest.to_json_value();
        assert_eq!(json["schema"], BITVM2_CLAIM_MANIFEST_SCHEMA);
        assert_eq!(json["boundless"]["selector"], "62f049f6");
        assert_eq!(
            json["boundless"]["public_inputs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(json["bitvm2"]["public_input_count"], 1);
        assert_eq!(json["artifacts"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn builds_an_artifact_complete_manifest_with_zero_bitvm_runtime_scalar() {
        let binding = binding_v2();
        let receipt = receipt_v2(&binding);
        let manifest =
            Bitvm2ArtifactCompleteManifestV2::new(params_v2(binding, &receipt), &receipt).unwrap();
        assert_eq!(manifest.journal_digest(), receipt.journal());
        assert_ne!(manifest.journal_digest(), &[0x55; 32]);

        let json = manifest.to_json_value();
        assert_eq!(json["schema"], BITVM2_ARTIFACT_COMPLETE_MANIFEST_SCHEMA);
        assert_eq!(json["journal"]["profile"], "risc0-stwo-journal-v1");
        assert_eq!(
            json["journal"]["binding"]["output_prefix"],
            json!([1, 0, 0])
        );
        assert_eq!(
            json["bitvm2"]["runtime_public_inputs"],
            json!(["0000000000000000000000000000000000000000000000000000000000000000"])
        );
        assert_ne!(
            json["boundless"]["verification_public_inputs"],
            json["bitvm2"]["runtime_public_inputs"]
        );
        assert_eq!(json["artifacts"].as_array().unwrap().len(), 10);
    }

    #[test]
    fn v2_rejects_bare_statement_journals_and_nonzero_runtime_scalars() {
        let binding = binding_v2();
        let receipt = receipt_v2(&binding);
        let bare_statement_receipt = {
            let claim = expected_boundless_claim_digest(
                &binding.expected_risc0_image_id,
                &binding.bark_statement_digest,
            )
            .unwrap();
            let mut seal = [0xabu8; BLAKE3_GROTH16_SEAL_LEN];
            seal[..4].copy_from_slice(&BLAKE3_GROTH16_V0_1_SELECTOR);
            Blake3Groth16Receipt::parse_seal(
                &seal,
                &binding.bark_statement_digest,
                &claim,
                &[&claim],
            )
            .unwrap()
        };
        assert_eq!(
            Bitvm2ArtifactCompleteManifestV2::new(
                params_v2(binding.clone(), &bare_statement_receipt),
                &bare_statement_receipt,
            ),
            Err(ManifestError::JournalArtifactBindingMismatch)
        );

        let mut nonzero = params_v2(binding, &receipt);
        nonzero.bitvm2_runtime_public_inputs[0][31] = 1;
        assert_eq!(
            Bitvm2ArtifactCompleteManifestV2::new(nonzero, &receipt),
            Err(ManifestError::NonzeroRuntimePublicInput)
        );
    }

    #[test]
    fn v2_rejects_artifact_substitution_even_with_valid_provenance_shape() {
        let binding = binding_v2();
        let receipt = receipt_v2(&binding);
        let mut substituted = params_v2(binding, &receipt);
        let proof = substituted
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == ArtifactKind::StwoProof)
            .unwrap();
        proof.sha256[0] ^= 1;
        assert_eq!(
            Bitvm2ArtifactCompleteManifestV2::new(substituted, &receipt),
            Err(ManifestError::ArtifactBindingMismatch {
                kind: ArtifactKind::StwoProof,
            })
        );
    }

    #[test]
    fn rejects_proof_for_another_statement_or_claim() {
        let receipt = receipt();
        let mut wrong_statement = params(&receipt);
        wrong_statement.statement_digest[0] ^= 1;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(wrong_statement, &receipt),
            Err(ManifestError::JournalStatementMismatch)
        ));

        let mut wrong_claim = params(&receipt);
        wrong_claim.expected_boundless_claim_digest[31] ^= 1;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(wrong_claim, &receipt),
            Err(ManifestError::ClaimDigestMismatch)
        ));
    }

    #[test]
    fn rejects_a_graph_with_more_than_one_public_input() {
        let receipt = receipt();
        let mut attacker = params(&receipt);
        attacker.verifier_public_input_count = 2;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(attacker, &receipt),
            Err(ManifestError::VerifierPublicInputCount { actual: 2 })
        ));
    }

    #[test]
    fn rejects_a_graph_hardcoded_for_another_scalar() {
        let receipt = receipt();
        let mut attacker = params(&receipt);
        attacker.bitvm2_expected_public_scalar[31] ^= 1;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(attacker, &receipt),
            Err(ManifestError::Bitvm2PublicScalarMismatch)
        ));
    }

    #[test]
    fn rejects_gitlab_mutable_or_path_traversal_artifacts() {
        let receipt = receipt();
        let mut gitlab = params(&receipt);
        gitlab.artifacts[0].github_repository = "https://gitlab.com/example/demo".to_owned();
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(gitlab, &receipt),
            Err(ManifestError::NotGithubRepository)
        ));

        let mut mutable = params(&receipt);
        mutable.artifacts[0].git_commit = "main".to_owned();
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(mutable, &receipt),
            Err(ManifestError::NonCanonicalGitCommit { .. })
        ));

        let mut traversal = params(&receipt);
        traversal.artifacts[0].file_name = "../proof.bin".to_owned();
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(traversal, &receipt),
            Err(ManifestError::UnsafeReleasePath { .. })
        ));

        for repository in [
            "https://github.com/./demo",
            "https://github.com/../demo",
            "https://github.com/example/.",
            "https://github.com/example/..",
        ] {
            let mut normalized = params(&receipt);
            normalized.artifacts[0].github_repository = repository.to_owned();
            assert!(matches!(
                Bitvm2ClaimManifestV1::new(normalized, &receipt),
                Err(ManifestError::NonCanonicalGithubRepository)
            ));
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_relabelled_artifacts() {
        let receipt = receipt();
        let mut missing = params(&receipt);
        missing.artifacts.pop();
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(missing, &receipt),
            Err(ManifestError::MissingArtifact { .. })
        ));

        let mut duplicate = params(&receipt);
        duplicate.artifacts[1].kind = duplicate.artifacts[0].kind;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(duplicate, &receipt),
            Err(ManifestError::DuplicateArtifact { .. })
        ));

        let mut wrong_graph = params(&receipt);
        let graph = wrong_graph
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == ArtifactKind::Bitvm2Graph)
            .unwrap();
        graph.sha256[0] ^= 1;
        assert!(matches!(
            Bitvm2ClaimManifestV1::new(wrong_graph, &receipt),
            Err(ManifestError::Bitvm2GraphHashMismatch)
        ));
    }

    #[test]
    fn rejects_a_seal_artifact_that_is_not_the_parsed_receipt() {
        let receipt = receipt();
        let mut attacker = params(&receipt);
        let seal = attacker
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == ArtifactKind::BoundlessSeal)
            .unwrap();
        seal.sha256[0] ^= 1;
        assert_eq!(
            Bitvm2ClaimManifestV1::new(attacker, &receipt),
            Err(ManifestError::BoundlessSealHashMismatch)
        );
    }

    #[test]
    fn rejects_mainnet_and_unpinned_request_provenance() {
        let receipt = receipt();
        let mut ethereum_mainnet = params(&receipt);
        ethereum_mainnet.boundless_request.chain_id = 1;
        assert_eq!(
            Bitvm2ClaimManifestV1::new(ethereum_mainnet, &receipt),
            Err(ManifestError::UnsupportedBoundlessChain(1))
        );

        let mut branch_name = params(&receipt);
        branch_name.boundless_request.boundless_git_commit = "release-2.0".to_owned();
        assert_eq!(
            Bitvm2ClaimManifestV1::new(branch_name, &receipt),
            Err(ManifestError::NonCanonicalBoundlessCommit)
        );
    }

    #[test]
    fn rejects_zero_placeholder_digests_and_artifact_hashes() {
        let receipt = receipt();
        for (field, mutate) in [
            (
                "statement_digest",
                (|params: &mut ManifestParams| params.statement_digest = [0; 32])
                    as fn(&mut ManifestParams),
            ),
            (
                "risc0_image_id",
                (|params: &mut ManifestParams| params.risc0_image_id = [0; 32])
                    as fn(&mut ManifestParams),
            ),
            (
                "expected_boundless_claim_digest",
                (|params: &mut ManifestParams| params.expected_boundless_claim_digest = [0; 32])
                    as fn(&mut ManifestParams),
            ),
            (
                "boundless_verifying_key_sha256",
                (|params: &mut ManifestParams| params.boundless_verifying_key_sha256 = [0; 32])
                    as fn(&mut ManifestParams),
            ),
            (
                "bitvm2_graph_sha256",
                (|params: &mut ManifestParams| params.bitvm2_graph_sha256 = [0; 32])
                    as fn(&mut ManifestParams),
            ),
        ] {
            let mut placeholder = params(&receipt);
            mutate(&mut placeholder);
            assert_eq!(
                Bitvm2ClaimManifestV1::new(placeholder, &receipt),
                Err(ManifestError::ZeroCriticalDigest { field })
            );
        }

        let mut zero_artifact = params(&receipt);
        let kind = zero_artifact.artifacts[0].kind;
        zero_artifact.artifacts[0].sha256 = [0; 32];
        assert_eq!(
            Bitvm2ClaimManifestV1::new(zero_artifact, &receipt),
            Err(ManifestError::ZeroArtifactHash { kind })
        );
    }
}
