//! Claim-specific BitVM2 manifest for the Boundless-wrapped proof path.

use crate::boundless::{
    encode_hex, Blake3Groth16Receipt, CanonicalPublicScalar, BLAKE3_GROTH16_V0_1_SELECTOR,
};
use ark::bitcoin::hashes::{sha256, Hash};
use core::fmt;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const BITVM2_CLAIM_MANIFEST_SCHEMA: &str = "bark-bitvm2-claim-manifest-v1";
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
    pub boundless_verifying_key_sha256: [u8; 32],
    pub bitvm2_graph_sha256: [u8; 32],
    pub verifier_public_input_count: usize,
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
        }
    }
}

impl std::error::Error for ManifestError {}

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
