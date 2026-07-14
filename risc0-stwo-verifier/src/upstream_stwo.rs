//! Native adapter for the pinned upstream STWO Cairo verifier.
//!
//! This is deliberately unavailable on `target_os = "zkvm"` until cairo-air
//! has a verifier-only RV32-compatible crate graph.

use std::io::Read;

use bincode::Options;
use bzip2::bufread::BzDecoder;
use cairo_air::utils::get_verification_output;
use cairo_air::verifier::{verify_cairo, INTERACTION_POW_BITS};
use cairo_air::CairoProofForRustVerifier;
use stwo::core::vcs_lifted::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_common::preprocessed_columns::preprocessed_trace::PreProcessedTraceVariant;

use crate::{
    program_commitment_from_cells, stwo_policy_commitment, BindingError, RelationOutputV3,
    VerifiedExecution,
};

/// Bounds attacker-controlled decompression before bincode allocation.
pub const MAX_DECOMPRESSED_PROOF_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug)]
pub enum VerifyError {
    Decompression(std::io::Error),
    TrailingCompressedBytes { consumed: u64, actual: u64 },
    DecompressedProofTooLarge,
    Deserialization(Box<bincode::ErrorKind>),
    ProofRejected,
    PolicyMismatch(&'static str),
    PublicOutputNotU32 { index: usize },
    OutputBinding(BindingError),
    PolicySerialization(Box<bincode::ErrorKind>),
}

/// Verify a compressed binary proof emitted by
/// `run_and_prove --proof-format binary`, then extract its authenticated public
/// program, STWO policy and `BarkShinigamiOutputV3`.
pub fn verify_compressed_binary(compressed: &[u8]) -> Result<VerifiedExecution, VerifyError> {
    let mut decompressed = Vec::new();
    let mut decoder = BzDecoder::new(compressed);
    (&mut decoder)
        .take(MAX_DECOMPRESSED_PROOF_BYTES + 1)
        .read_to_end(&mut decompressed)
        .map_err(VerifyError::Decompression)?;
    if decompressed.len() as u64 > MAX_DECOMPRESSED_PROOF_BYTES {
        return Err(VerifyError::DecompressedProofTooLarge);
    }
    let consumed = decoder.total_in();
    if consumed != compressed.len() as u64 {
        return Err(VerifyError::TrailingCompressedBytes {
            consumed,
            actual: compressed.len() as u64,
        });
    }

    let proof: CairoProofForRustVerifier<Blake2sMerkleHasher> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_DECOMPRESSED_PROOF_BYTES)
        .reject_trailing_bytes()
        .deserialize(&decompressed)
        .map_err(VerifyError::Deserialization)?;

    let config = proof.stark_proof.config;
    if proof.channel_salt != 0 {
        return Err(VerifyError::PolicyMismatch("channel_salt"));
    }
    if config.pow_bits != 26 {
        return Err(VerifyError::PolicyMismatch("pcs_pow_bits"));
    }
    if config.fri_config.log_blowup_factor != 1 {
        return Err(VerifyError::PolicyMismatch("fri_log_blowup_factor"));
    }
    if config.fri_config.n_queries != 70 {
        return Err(VerifyError::PolicyMismatch("fri_queries"));
    }
    if config.fri_config.log_last_layer_degree_bound != 0 {
        return Err(VerifyError::PolicyMismatch("fri_last_layer_degree_log"));
    }
    if config.fri_config.fold_step != 1 {
        return Err(VerifyError::PolicyMismatch("fri_fold_step"));
    }
    if config.lifting_log_size.is_some() {
        return Err(VerifyError::PolicyMismatch("lifting_log_size"));
    }
    if proof.preprocessed_trace_variant != PreProcessedTraceVariant::Canonical {
        return Err(VerifyError::PolicyMismatch("preprocessed_trace"));
    }
    if INTERACTION_POW_BITS != 24 {
        return Err(VerifyError::PolicyMismatch("interaction_pow_bits"));
    }

    // Extract only public values authenticated by the proof. Do this before
    // verify_cairo consumes the proof object, but do not return anything unless
    // verification succeeds.
    let output_words = proof
        .claim
        .public_data
        .public_memory
        .output
        .iter()
        .enumerate()
        .map(|(index, (_, felt_limbs))| {
            if felt_limbs[1..] != [0; 7] {
                return Err(VerifyError::PublicOutputNotU32 { index });
            }
            Ok(felt_limbs[0])
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output = RelationOutputV3::parse(&output_words).map_err(VerifyError::OutputBinding)?;
    let stwo_program_hash_be = get_verification_output(&proof.claim.public_data.public_memory)
        .program_hash
        .to_bytes_be();

    let program_cells = proof
        .claim
        .public_data
        .public_memory
        .program
        .iter()
        .map(|(id, felt_limbs)| (*id, *felt_limbs))
        .collect::<Vec<_>>();
    let program_commitment = program_commitment_from_cells(&program_cells);

    // The PCS/FRI config is part of stark_proof and channel_salt plus the
    // preprocessed variant select the remaining verifier policy. Bincode is
    // acceptable here because every dependency and the encoding version are
    // pinned by Cargo.lock and the guest image ID.
    let policy_bytes = bincode::serialize(&(
        proof.channel_salt,
        &proof.preprocessed_trace_variant,
        &proof.stark_proof.config,
    ))
    .map_err(VerifyError::PolicySerialization)?;
    let policy_commitment = stwo_policy_commitment(&policy_bytes);

    verify_cairo::<Blake2sMerkleChannel>(proof).map_err(|_| VerifyError::ProofRejected)?;

    Ok(VerifiedExecution::from_cryptographic_verifier(
        output,
        stwo_program_hash_be,
        program_commitment,
        policy_commitment,
    ))
}
