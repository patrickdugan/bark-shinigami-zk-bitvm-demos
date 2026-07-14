#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
fn main() {
    use bark_risc0_stwo_verifier::{upstream_stwo, VerificationPolicy};

    // These zero placeholders make the scaffold fail closed. Replace them with
    // measured commitments only after the verifier-only upstream port builds
    // and the values are independently reproduced. The RISC Zero image ID then
    // authenticates the constants.
    const POLICY: VerificationPolicy = VerificationPolicy::new([0; 32], [0; 32]);

    let compressed_proof: Vec<u8> = env::read();
    let verified = upstream_stwo::verify_compressed_binary(&compressed_proof)
        .expect("STWO Cairo proof verification failed");
    let journal = verified
        .authorization_journal(&POLICY)
        .expect("operator-take authorization is not proven");
    env::commit_slice(journal.as_bytes());
}

#[cfg(not(target_os = "zkvm"))]
fn main() {
    panic!("bark-stwo-guest must be compiled for the RISC Zero zkVM target");
}
