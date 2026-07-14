//! Fail-closed policy around a future BitVM assertion graph.
//!
//! This is a deterministic test-only state-machine model, not a Bitcoin
//! transaction builder or authorization API. Its Boolean evidence and decision
//! function are private so production callers cannot mint an `OperatorTake`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingPolicy {
    pub challenge_blocks: u32,
    pub response_window_blocks: u32,
    pub response_rounds: u32,
    pub reorg_margin_blocks: u32,
    pub operator_take_height_delta: u32,
    pub emergency_recovery_height_delta: u32,
}

impl TimingPolicy {
    pub const REGTEST: Self = Self {
        challenge_blocks: 6,
        response_window_blocks: 2,
        response_rounds: 4,
        reorg_margin_blocks: 2,
        operator_take_height_delta: 16,
        emergency_recovery_height_delta: 24,
    };

    pub const SIGNET: Self = Self {
        challenge_blocks: 144,
        response_window_blocks: 24,
        response_rounds: 4,
        reorg_margin_blocks: 12,
        operator_take_height_delta: 252,
        emergency_recovery_height_delta: 432,
    };

    pub fn validate(self) -> bool {
        let dispute = self
            .response_window_blocks
            .checked_mul(self.response_rounds)
            .and_then(|responses| self.challenge_blocks.checked_add(responses))
            .and_then(|blocks| blocks.checked_add(self.reorg_margin_blocks));
        matches!(dispute, Some(blocks) if self.operator_take_height_delta >= blocks
			&& self.emergency_recovery_height_delta > self.operator_take_height_delta)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BondPolicy {
    pub protected_value_sats: u64,
    pub watcher_reward_sats: u64,
    pub graph_vbytes: u64,
    pub fee_rate_sat_per_vbyte: u64,
}

impl BondPolicy {
    pub fn required_bond_sats(self) -> Option<u64> {
        self.graph_vbytes
            .checked_mul(self.fee_rate_sat_per_vbyte)
            .and_then(|fees| fees.checked_add(self.protected_value_sats))
            .and_then(|total| total.checked_add(self.watcher_reward_sats))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
struct EnforcementEvidence {
    exact_statement_valid: bool,
    real_boundless_receipt_verified: bool,
    bitvm_verifier_trace_verified: bool,
    all_transactions_core_accepted: bool,
    all_transactions_standard: bool,
    fresh_permissionless_watcher_exercised: bool,
    challenge_window_elapsed: bool,
    invalid_claim_challenged: bool,
    disprove_confirmed: bool,
    all_watchers_offline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementDecision {
    OperatorTake,
    OperatorSlashed,
    FailClosed,
    OfflineWatcherAssumptionFailure,
}

// Deliberately private: booleans model the future state machine in tests, but
// callers must never mint authorization by constructing an all-true struct.
// A public decision API requires opaque evidence types created by actual proof,
// Bitcoin Core, confirmation, and watcher verifiers.
#[cfg(test)]
fn decide(evidence: EnforcementEvidence) -> EnforcementDecision {
    if !evidence.exact_statement_valid {
        if evidence.all_watchers_offline && evidence.challenge_window_elapsed {
            return EnforcementDecision::OfflineWatcherAssumptionFailure;
        }
        if evidence.invalid_claim_challenged && evidence.disprove_confirmed {
            return EnforcementDecision::OperatorSlashed;
        }
        return EnforcementDecision::FailClosed;
    }

    let every_take_gate = evidence.real_boundless_receipt_verified
        && evidence.bitvm_verifier_trace_verified
        && evidence.all_transactions_core_accepted
        && evidence.all_transactions_standard
        && evidence.fresh_permissionless_watcher_exercised
        && evidence.challenge_window_elapsed
        && !evidence.all_watchers_offline;
    if every_take_gate {
        EnforcementDecision::OperatorTake
    } else {
        EnforcementDecision::FailClosed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete() -> EnforcementEvidence {
        EnforcementEvidence {
            exact_statement_valid: true,
            real_boundless_receipt_verified: true,
            bitvm_verifier_trace_verified: true,
            all_transactions_core_accepted: true,
            all_transactions_standard: true,
            fresh_permissionless_watcher_exercised: true,
            challenge_window_elapsed: true,
            invalid_claim_challenged: false,
            disprove_confirmed: false,
            all_watchers_offline: false,
        }
    }

    #[test]
    fn timing_policies_cover_every_response_and_reorg_margin() {
        assert!(TimingPolicy::REGTEST.validate());
        assert!(TimingPolicy::SIGNET.validate());
    }

    #[test]
    fn bond_includes_value_reward_and_full_graph_fee_reserve() {
        let policy = BondPolicy {
            protected_value_sats: 10_330,
            watcher_reward_sats: 10_000,
            graph_vbytes: 200_000,
            fee_rate_sat_per_vbyte: 2,
        };
        assert_eq!(policy.required_bond_sats(), Some(420_330));
    }

    #[test]
    fn every_operator_take_gate_is_mandatory() {
        assert_eq!(decide(complete()), EnforcementDecision::OperatorTake);
        for index in 0..6 {
            let mut missing = complete();
            match index {
                0 => missing.real_boundless_receipt_verified = false,
                1 => missing.bitvm_verifier_trace_verified = false,
                2 => missing.all_transactions_core_accepted = false,
                3 => missing.all_transactions_standard = false,
                4 => missing.fresh_permissionless_watcher_exercised = false,
                5 => missing.challenge_window_elapsed = false,
                _ => unreachable!(),
            }
            assert_eq!(decide(missing), EnforcementDecision::FailClosed);
        }
    }

    #[test]
    fn invalid_claim_slashes_only_after_a_confirmed_disprove() {
        let mut invalid = complete();
        invalid.exact_statement_valid = false;
        invalid.invalid_claim_challenged = true;
        invalid.disprove_confirmed = true;
        assert_eq!(decide(invalid), EnforcementDecision::OperatorSlashed);
        invalid.disprove_confirmed = false;
        assert_eq!(decide(invalid), EnforcementDecision::FailClosed);
    }

    #[test]
    fn all_watchers_offline_exposes_the_explicit_security_assumption() {
        let mut invalid = complete();
        invalid.exact_statement_valid = false;
        invalid.all_watchers_offline = true;
        assert_eq!(
            decide(invalid),
            EnforcementDecision::OfflineWatcherAssumptionFailure
        );
    }
}
