#[path = "../src/bitvmx_outer_feasibility.rs"]
mod bitvmx_outer_feasibility;

use bitvmx_outer_feasibility::*;

fn candidate(target: TargetProfile) -> FeasibilityMeasurement {
    FeasibilityMeasurement {
        target,
        dynamic_inputs: vec![DynamicInput::boundless_groth16(vec![
            0x5a;
            BOUNDLESS_GROTH16_PROOF_BYTES
        ])],
        fixed_bindings: FixedVerifierBindings {
            proof_type_selector: BLAKE3_GROTH16_SELECTOR,
            risc0_image_id: [1; 32],
            verifying_key_digest: [2; 32],
            expected_public_scalar: [3; 32],
        },
        resources: ResourceObservation {
            executed_steps: Some(target.step_limit()),
            peak_memory_bytes: Some(target.memory_limit_bytes()),
            unsupported_syscalls: Some(0),
            reachable_panic_paths: Some(0),
            all_dispute_transactions_standard: Some(true),
        },
        watcher: WatcherObservation {
            setup_key_fingerprints: vec![[10; 32], [11; 32], [12; 32]],
            challenger_key_fingerprint: Some([99; 32]),
            challenge_requires_setup_authorization: Some(false),
            fresh_watcher_challenge_exercised: Some(true),
        },
    }
}

fn assert_rejected_with(
    measurement: &FeasibilityMeasurement,
    expected: impl Fn(&GateFailure) -> bool,
) {
    let assessment = assess(measurement);
    assert_eq!(assessment.verdict, FeasibilityVerdict::Rejected);
    assert!(!assessment.is_candidate());
    assert!(assessment.failures.iter().any(expected), "{assessment:#?}");
}

#[test]
fn exact_limits_are_feasibility_candidates_for_both_profiles() {
    for target in [TargetProfile::Regtest, TargetProfile::Signet] {
        let assessment = assess(&candidate(target));
        assert!(assessment.is_candidate(), "{assessment:#?}");
        assert!(assessment.failures.is_empty());
    }
}

#[test]
fn proof_must_be_exactly_256_bytes() {
    for size in [0, 255, 257, 1024] {
        let mut measurement = candidate(TargetProfile::Signet);
        measurement.dynamic_inputs[0].bytes = vec![1; size];
        assert_rejected_with(&measurement, |failure| {
            matches!(
                failure,
                GateFailure::WrongOuterProofSize {
                    expected: 256,
                    actual
                } if *actual == size
            )
        });
    }
}

#[test]
fn proof_is_the_only_dynamic_input() {
    let mut none = candidate(TargetProfile::Signet);
    none.dynamic_inputs.clear();
    assert_rejected_with(&none, |failure| {
        matches!(
            failure,
            GateFailure::UnexpectedDynamicInputCount {
                expected: 1,
                actual: 0
            }
        )
    });

    for kind in [
        DynamicInputKind::VerifyingKey,
        DynamicInputKind::ExpectedPublicScalar,
        DynamicInputKind::ProofTypeSelector,
        DynamicInputKind::Other,
    ] {
        let mut extra = candidate(TargetProfile::Signet);
        extra.dynamic_inputs.push(DynamicInput {
            kind,
            bytes: vec![7; 32],
        });
        let index = extra.dynamic_inputs.len() - 1;
        assert_rejected_with(&extra, |failure| {
            matches!(
                failure,
                GateFailure::UnexpectedDynamicInputKind { index: observed, actual }
                    if *observed == index && *actual == kind
            )
        });
    }
}

#[test]
fn fixed_selector_and_commitments_are_mandatory() {
    let mut wrong_selector = candidate(TargetProfile::Signet);
    wrong_selector.fixed_bindings.proof_type_selector = [0; 4];
    assert_rejected_with(&wrong_selector, |failure| {
        matches!(failure, GateFailure::WrongProofTypeSelector { .. })
    });

    for field in [
        "risc0_image_id",
        "verifying_key_digest",
        "expected_public_scalar",
    ] {
        let mut missing = candidate(TargetProfile::Signet);
        match field {
            "risc0_image_id" => missing.fixed_bindings.risc0_image_id = [0; 32],
            "verifying_key_digest" => missing.fixed_bindings.verifying_key_digest = [0; 32],
            "expected_public_scalar" => missing.fixed_bindings.expected_public_scalar = [0; 32],
            _ => unreachable!(),
        }
        assert_rejected_with(
            &missing,
            |failure| matches!(failure, GateFailure::MissingFixedBinding(name) if *name == field),
        );
    }
}

#[test]
fn signet_step_and_memory_caps_are_strict() {
    let mut steps = candidate(TargetProfile::Signet);
    steps.resources.executed_steps = Some(SIGNET_STEP_LIMIT + 1);
    assert_rejected_with(&steps, |failure| {
        matches!(
            failure,
            GateFailure::StepLimitExceeded { limit, observed }
                if *limit == SIGNET_STEP_LIMIT && *observed == SIGNET_STEP_LIMIT + 1
        )
    });

    let mut memory = candidate(TargetProfile::Signet);
    memory.resources.peak_memory_bytes = Some(SIGNET_MEMORY_LIMIT_BYTES + 1);
    assert_rejected_with(&memory, |failure| {
        matches!(
            failure,
            GateFailure::MemoryLimitExceeded { limit, observed }
                if *limit == SIGNET_MEMORY_LIMIT_BYTES
                    && *observed == SIGNET_MEMORY_LIMIT_BYTES + 1
        )
    });
}

#[test]
fn regtest_does_not_relax_its_absolute_caps() {
    let mut measurement = candidate(TargetProfile::Regtest);
    measurement.resources.executed_steps = Some(REGTEST_STEP_LIMIT + 1);
    measurement.resources.peak_memory_bytes = Some(REGTEST_MEMORY_LIMIT_BYTES + 1);
    let assessment = assess(&measurement);
    assert_eq!(assessment.verdict, FeasibilityVerdict::Rejected);
    assert!(assessment
        .failures
        .iter()
        .any(|failure| matches!(failure, GateFailure::StepLimitExceeded { .. })));
    assert!(assessment
        .failures
        .iter()
        .any(|failure| matches!(failure, GateFailure::MemoryLimitExceeded { .. })));
}

#[test]
fn every_missing_resource_observation_fails_closed() {
    let resource_fields = [
        "executed_steps",
        "peak_memory_bytes",
        "unsupported_syscalls",
        "reachable_panic_paths",
        "all_dispute_transactions_standard",
    ];
    for field in resource_fields {
        let mut measurement = candidate(TargetProfile::Signet);
        match field {
            "executed_steps" => measurement.resources.executed_steps = None,
            "peak_memory_bytes" => measurement.resources.peak_memory_bytes = None,
            "unsupported_syscalls" => measurement.resources.unsupported_syscalls = None,
            "reachable_panic_paths" => measurement.resources.reachable_panic_paths = None,
            "all_dispute_transactions_standard" => {
                measurement.resources.all_dispute_transactions_standard = None
            }
            _ => unreachable!(),
        }
        assert_rejected_with(
            &measurement,
            |failure| matches!(failure, GateFailure::MissingObservation(name) if *name == field),
        );
    }
}

#[test]
fn unsupported_execution_features_and_nonstandard_transactions_reject() {
    let mut measurement = candidate(TargetProfile::Signet);
    measurement.resources.unsupported_syscalls = Some(1);
    measurement.resources.reachable_panic_paths = Some(2);
    measurement.resources.all_dispute_transactions_standard = Some(false);
    let assessment = assess(&measurement);
    assert_eq!(assessment.verdict, FeasibilityVerdict::Rejected);
    assert!(assessment
        .failures
        .contains(&GateFailure::UnsupportedSyscallsObserved(1)));
    assert!(assessment
        .failures
        .contains(&GateFailure::ReachablePanicPathsObserved(2)));
    assert!(assessment
        .failures
        .contains(&GateFailure::NonStandardDisputeTransaction));
}

#[test]
fn challenger_must_be_fresh_and_need_no_setup_authorization() {
    let mut setup_challenger = candidate(TargetProfile::Signet);
    setup_challenger.watcher.challenger_key_fingerprint = Some([10; 32]);
    assert_rejected_with(&setup_challenger, |failure| {
        matches!(failure, GateFailure::ChallengerKeyCommittedDuringSetup)
    });

    let mut authorized = candidate(TargetProfile::Signet);
    authorized.watcher.challenge_requires_setup_authorization = Some(true);
    assert_rejected_with(&authorized, |failure| {
        matches!(failure, GateFailure::ChallengeRequiresSetupAuthorization)
    });

    let mut unexercised = candidate(TargetProfile::Signet);
    unexercised.watcher.fresh_watcher_challenge_exercised = Some(false);
    assert_rejected_with(&unexercised, |failure| {
        matches!(failure, GateFailure::FreshWatcherChallengeNotExercised)
    });
}

#[test]
fn every_missing_watcher_observation_fails_closed() {
    let mut no_key = candidate(TargetProfile::Signet);
    no_key.watcher.challenger_key_fingerprint = None;
    assert_rejected_with(&no_key, |failure| {
        matches!(
            failure,
            GateFailure::MissingObservation("challenger_key_fingerprint")
        )
    });

    let mut no_authorization_result = candidate(TargetProfile::Signet);
    no_authorization_result
        .watcher
        .challenge_requires_setup_authorization = None;
    assert_rejected_with(&no_authorization_result, |failure| {
        matches!(
            failure,
            GateFailure::MissingObservation("challenge_requires_setup_authorization")
        )
    });

    let mut no_exercise_result = candidate(TargetProfile::Signet);
    no_exercise_result.watcher.fresh_watcher_challenge_exercised = None;
    assert_rejected_with(&no_exercise_result, |failure| {
        matches!(
            failure,
            GateFailure::MissingObservation("fresh_watcher_challenge_exercised")
        )
    });
}

#[test]
fn independent_failures_accumulate_in_one_report() {
    let mut measurement = candidate(TargetProfile::Signet);
    measurement.dynamic_inputs.clear();
    measurement.resources.executed_steps = None;
    measurement.resources.peak_memory_bytes = Some(SIGNET_MEMORY_LIMIT_BYTES + 1);
    measurement.watcher.challenger_key_fingerprint = Some([10; 32]);
    let assessment = assess(&measurement);
    assert_eq!(assessment.verdict, FeasibilityVerdict::Rejected);
    assert_eq!(assessment.failures.len(), 4, "{assessment:#?}");
}
