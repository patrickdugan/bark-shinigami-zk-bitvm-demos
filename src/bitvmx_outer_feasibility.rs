//! Fail-closed feasibility gates for a BitVMX verifier of a Boundless outer proof.
//!
//! This module deliberately does not claim that a proof was verified or that an
//! on-chain dispute is enforceable. It only assesses measurements from a future
//! RV32IM implementation. The only permitted dynamic verifier input is the raw
//! 256-byte BN254 Groth16 proof. The Boundless selector, RISC Zero image ID,
//! verifying-key digest, and expected public scalar must all be fixed in the
//! verifier program.

/// Raw BN254 Groth16 proof size returned after removing the four-byte Boundless
/// proof-type selector from the seal.
pub const BOUNDLESS_GROTH16_PROOF_BYTES: usize = 256;

/// Boundless `Blake3Groth16V0_1` selector. It is a fixed verifier-program
/// constant, not part of the dynamic BitVMX input.
pub const BLAKE3_GROTH16_SELECTOR: [u8; 4] = [0x62, 0xf0, 0x49, 0xf6];

pub const SIGNET_STEP_LIMIT: u64 = 500_000_000;
pub const SIGNET_MEMORY_LIMIT_BYTES: u64 = 64 * 1024 * 1024;
pub const REGTEST_STEP_LIMIT: u64 = 1_u64 << 31;
pub const REGTEST_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetProfile {
    Regtest,
    Signet,
}

impl TargetProfile {
    pub const fn step_limit(self) -> u64 {
        match self {
            Self::Regtest => REGTEST_STEP_LIMIT,
            Self::Signet => SIGNET_STEP_LIMIT,
        }
    }

    pub const fn memory_limit_bytes(self) -> u64 {
        match self {
            Self::Regtest => REGTEST_MEMORY_LIMIT_BYTES,
            Self::Signet => SIGNET_MEMORY_LIMIT_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicInputKind {
    BoundlessGroth16Proof,
    VerifyingKey,
    ExpectedPublicScalar,
    ProofTypeSelector,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicInput {
    pub kind: DynamicInputKind,
    pub bytes: Vec<u8>,
}

impl DynamicInput {
    pub fn boundless_groth16(bytes: Vec<u8>) -> Self {
        Self {
            kind: DynamicInputKind::BoundlessGroth16Proof,
            bytes,
        }
    }
}

/// Values that must be compiled into and authenticated as part of the verifier
/// program. This assessment checks only that their pins are present and that the
/// expected Boundless selector is used; it does not perform Groth16 verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedVerifierBindings {
    pub proof_type_selector: [u8; 4],
    pub risc0_image_id: [u8; 32],
    pub verifying_key_digest: [u8; 32],
    pub expected_public_scalar: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceObservation {
    pub executed_steps: Option<u64>,
    pub peak_memory_bytes: Option<u64>,
    pub unsupported_syscalls: Option<u32>,
    pub reachable_panic_paths: Option<u32>,
    pub all_dispute_transactions_standard: Option<bool>,
}

/// Evidence required for the permissionless-watcher gate.
///
/// A challenger is considered fresh only when its key is absent from every key
/// committed during setup. A successful simulation alone is insufficient: the
/// challenge path must also be observed not to require setup authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatcherObservation {
    pub setup_key_fingerprints: Vec<[u8; 32]>,
    pub challenger_key_fingerprint: Option<[u8; 32]>,
    pub challenge_requires_setup_authorization: Option<bool>,
    pub fresh_watcher_challenge_exercised: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeasibilityMeasurement {
    pub target: TargetProfile,
    pub dynamic_inputs: Vec<DynamicInput>,
    pub fixed_bindings: FixedVerifierBindings,
    pub resources: ResourceObservation,
    pub watcher: WatcherObservation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateFailure {
    UnexpectedDynamicInputCount {
        expected: usize,
        actual: usize,
    },
    UnexpectedDynamicInputKind {
        index: usize,
        actual: DynamicInputKind,
    },
    WrongOuterProofSize {
        expected: usize,
        actual: usize,
    },
    WrongProofTypeSelector {
        expected: [u8; 4],
        actual: [u8; 4],
    },
    MissingFixedBinding(&'static str),
    MissingObservation(&'static str),
    StepLimitExceeded {
        limit: u64,
        observed: u64,
    },
    MemoryLimitExceeded {
        limit: u64,
        observed: u64,
    },
    UnsupportedSyscallsObserved(u32),
    ReachablePanicPathsObserved(u32),
    NonStandardDisputeTransaction,
    ChallengerKeyCommittedDuringSetup,
    ChallengeRequiresSetupAuthorization,
    FreshWatcherChallengeNotExercised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeasibilityVerdict {
    /// All bounded checks passed. This is only permission to continue the
    /// implementation experiment, not a claim of Bitcoin enforcement.
    Candidate,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeasibilityAssessment {
    pub verdict: FeasibilityVerdict,
    pub failures: Vec<GateFailure>,
}

impl FeasibilityAssessment {
    pub fn is_candidate(&self) -> bool {
        self.verdict == FeasibilityVerdict::Candidate
    }
}

pub fn assess(measurement: &FeasibilityMeasurement) -> FeasibilityAssessment {
    let mut failures = Vec::new();

    if measurement.dynamic_inputs.len() != 1 {
        failures.push(GateFailure::UnexpectedDynamicInputCount {
            expected: 1,
            actual: measurement.dynamic_inputs.len(),
        });
    }
    for (index, input) in measurement.dynamic_inputs.iter().enumerate() {
        if input.kind != DynamicInputKind::BoundlessGroth16Proof {
            failures.push(GateFailure::UnexpectedDynamicInputKind {
                index,
                actual: input.kind,
            });
        }
        if input.kind == DynamicInputKind::BoundlessGroth16Proof
            && input.bytes.len() != BOUNDLESS_GROTH16_PROOF_BYTES
        {
            failures.push(GateFailure::WrongOuterProofSize {
                expected: BOUNDLESS_GROTH16_PROOF_BYTES,
                actual: input.bytes.len(),
            });
        }
    }

    let bindings = &measurement.fixed_bindings;
    if bindings.proof_type_selector != BLAKE3_GROTH16_SELECTOR {
        failures.push(GateFailure::WrongProofTypeSelector {
            expected: BLAKE3_GROTH16_SELECTOR,
            actual: bindings.proof_type_selector,
        });
    }
    check_nonzero_binding(&mut failures, "risc0_image_id", &bindings.risc0_image_id);
    check_nonzero_binding(
        &mut failures,
        "verifying_key_digest",
        &bindings.verifying_key_digest,
    );
    check_nonzero_binding(
        &mut failures,
        "expected_public_scalar",
        &bindings.expected_public_scalar,
    );

    let resources = &measurement.resources;
    match resources.executed_steps {
        Some(observed) if observed > measurement.target.step_limit() => {
            failures.push(GateFailure::StepLimitExceeded {
                limit: measurement.target.step_limit(),
                observed,
            });
        }
        Some(_) => {}
        None => failures.push(GateFailure::MissingObservation("executed_steps")),
    }
    match resources.peak_memory_bytes {
        Some(observed) if observed > measurement.target.memory_limit_bytes() => {
            failures.push(GateFailure::MemoryLimitExceeded {
                limit: measurement.target.memory_limit_bytes(),
                observed,
            });
        }
        Some(_) => {}
        None => failures.push(GateFailure::MissingObservation("peak_memory_bytes")),
    }
    match resources.unsupported_syscalls {
        Some(0) => {}
        Some(count) => failures.push(GateFailure::UnsupportedSyscallsObserved(count)),
        None => failures.push(GateFailure::MissingObservation("unsupported_syscalls")),
    }
    match resources.reachable_panic_paths {
        Some(0) => {}
        Some(count) => failures.push(GateFailure::ReachablePanicPathsObserved(count)),
        None => failures.push(GateFailure::MissingObservation("reachable_panic_paths")),
    }
    match resources.all_dispute_transactions_standard {
        Some(true) => {}
        Some(false) => failures.push(GateFailure::NonStandardDisputeTransaction),
        None => failures.push(GateFailure::MissingObservation(
            "all_dispute_transactions_standard",
        )),
    }

    let watcher = &measurement.watcher;
    match watcher.challenger_key_fingerprint {
        Some(key) if watcher.setup_key_fingerprints.contains(&key) => {
            failures.push(GateFailure::ChallengerKeyCommittedDuringSetup);
        }
        Some(_) => {}
        None => failures.push(GateFailure::MissingObservation(
            "challenger_key_fingerprint",
        )),
    }
    match watcher.challenge_requires_setup_authorization {
        Some(false) => {}
        Some(true) => failures.push(GateFailure::ChallengeRequiresSetupAuthorization),
        None => failures.push(GateFailure::MissingObservation(
            "challenge_requires_setup_authorization",
        )),
    }
    match watcher.fresh_watcher_challenge_exercised {
        Some(true) => {}
        Some(false) => failures.push(GateFailure::FreshWatcherChallengeNotExercised),
        None => failures.push(GateFailure::MissingObservation(
            "fresh_watcher_challenge_exercised",
        )),
    }

    let verdict = if failures.is_empty() {
        FeasibilityVerdict::Candidate
    } else {
        FeasibilityVerdict::Rejected
    };
    FeasibilityAssessment { verdict, failures }
}

fn check_nonzero_binding(failures: &mut Vec<GateFailure>, name: &'static str, binding: &[u8; 32]) {
    if binding.iter().all(|byte| *byte == 0) {
        failures.push(GateFailure::MissingFixedBinding(name));
    }
}
