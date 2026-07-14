#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
fn main() {
    use bark_risc0_stwo_verifier::{upstream_stwo, BindingError, VerificationPolicy};

    // Independently reproduced by both checked-in STWO proofs. The RISC Zero
    // image ID authenticates these policy constants to the outer verifier.
    const PROGRAM_COMMITMENT: [u8; 32] = [
        0x4c, 0x75, 0x02, 0x3e, 0xf3, 0x74, 0x07, 0xbe, 0x73, 0x9a, 0x93, 0xea, 0xb0, 0xf1, 0x7f,
        0xf6, 0x24, 0xba, 0x71, 0x6e, 0x07, 0xef, 0xab, 0x79, 0x6a, 0xf5, 0x98, 0x46, 0x71, 0x4e,
        0xf0, 0x67,
    ];
    const STWO_POLICY_COMMITMENT: [u8; 32] = [
        0x62, 0x6c, 0xd3, 0x8f, 0x63, 0x85, 0x1c, 0x10, 0x67, 0xc7, 0xee, 0x15, 0x94, 0xae, 0x88,
        0x06, 0x94, 0x25, 0x53, 0x46, 0xc0, 0xa1, 0x79, 0xd6, 0x8c, 0x0b, 0xff, 0xf5, 0x71, 0x95,
        0x53, 0x14,
    ];
    const POLICY: VerificationPolicy =
        VerificationPolicy::new(PROGRAM_COMMITMENT, STWO_POLICY_COMMITMENT);

    let compressed_proof: Vec<u8> = env::read();
    let verified = upstream_stwo::verify_compressed_binary(&compressed_proof)
        .expect("STWO Cairo proof verification failed");
    let evidence = verified
        .verification_evidence_journal(&POLICY)
        .expect("verified STWO proof did not match the pinned program and policy");

    match verified.authorization_journal(&POLICY) {
        Ok(journal) => env::commit_slice(journal.as_bytes()),
        Err(
            BindingError::TransactionRelationInvalid
            | BindingError::ChainStateNotVerified
            | BindingError::OperatorTakeNotAuthorized,
        ) => env::commit_slice(evidence.as_bytes()),
        Err(error) => panic!("authorization policy mismatch: {error}"),
    }
}

#[cfg(not(target_os = "zkvm"))]
fn main() {
    panic!("bark-stwo-guest must be compiled for the RISC Zero zkVM target");
}
