use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    RetryWait,
    Leased,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    NeedsReconciliation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectState {
    Prepared,
    Dispatching,
    Committed,
    DefinitelyFailed,
    OutcomeUnknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid state transition")]
pub struct InvalidTransition;
impl EffectState {
    pub fn unresolved(self) -> bool {
        matches!(self, Self::Dispatching | Self::OutcomeUnknown)
    }
    /// Unknown outcomes require explicit evidence or an eligible idempotent retry.
    pub fn transition(
        self,
        to: Self,
        evidenced_resolution: bool,
        eligible_retry: bool,
    ) -> Result<Self, InvalidTransition> {
        let allowed = matches!(
            (self, to),
            (Self::Prepared, Self::Dispatching)
                | (
                    Self::Dispatching,
                    Self::Committed | Self::DefinitelyFailed | Self::OutcomeUnknown
                )
        ) || (self == Self::OutcomeUnknown
            && ((evidenced_resolution && matches!(to, Self::Committed | Self::DefinitelyFailed))
                || (eligible_retry && to == Self::Dispatching)));
        if allowed {
            Ok(to)
        } else {
            Err(InvalidTransition)
        }
    }
}
impl RunState {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
    pub fn transition(
        self,
        to: Self,
        unresolved: bool,
        explicit_resume: bool,
    ) -> Result<Self, InvalidTransition> {
        if unresolved
            && matches!(
                to,
                Self::Succeeded | Self::Cancelled | Self::Queued | Self::RetryWait | Self::Failed
            )
        {
            return Err(InvalidTransition);
        }
        let allowed =
            matches!(
                (self, to),
                (Self::Queued, Self::Leased | Self::Cancelled | Self::Failed)
                    | (
                        Self::Leased,
                        Self::Running
                            | Self::Queued
                            | Self::RetryWait
                            | Self::Cancelled
                            | Self::Failed
                            | Self::NeedsReconciliation
                    )
                    | (
                        Self::Running,
                        Self::Succeeded
                            | Self::Failed
                            | Self::Cancelled
                            | Self::Queued
                            | Self::RetryWait
                            | Self::NeedsReconciliation
                    )
                    | (
                        Self::RetryWait,
                        Self::Queued | Self::Cancelled | Self::Failed | Self::NeedsReconciliation
                    )
                    | (Self::NeedsReconciliation, Self::Failed)
            ) || (self == Self::NeedsReconciliation && to == Self::Queued && explicit_resume);
        if allowed {
            Ok(to)
        } else {
            Err(InvalidTransition)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ambiguity_prevents_clean_cancellation_and_success() {
        for state in [RunState::Leased, RunState::Running] {
            for terminal in [
                RunState::Cancelled,
                RunState::Succeeded,
                RunState::Queued,
                RunState::Failed,
            ] {
                assert!(state.transition(terminal, true, false).is_err());
            }
            assert_eq!(
                state.transition(RunState::NeedsReconciliation, true, false),
                Ok(RunState::NeedsReconciliation)
            );
        }
    }
    #[test]
    fn unknown_never_implicitly_retries() {
        assert!(
            EffectState::OutcomeUnknown
                .transition(EffectState::Dispatching, false, false)
                .is_err()
        );
        assert!(
            EffectState::OutcomeUnknown
                .transition(EffectState::Committed, false, false)
                .is_err()
        );
        assert!(
            EffectState::Committed
                .transition(EffectState::Dispatching, false, true)
                .is_err()
        );
        assert!(
            EffectState::OutcomeUnknown
                .transition(EffectState::Committed, true, false)
                .is_ok()
        );
    }
    #[test]
    fn deferred_retry_is_nonterminal_and_requires_safe_promotion() {
        assert!(!RunState::RetryWait.terminal());
        assert_eq!(
            RunState::Running.transition(RunState::RetryWait, false, false),
            Ok(RunState::RetryWait)
        );
        assert_eq!(
            RunState::RetryWait.transition(RunState::Queued, false, false),
            Ok(RunState::Queued)
        );
        assert!(
            RunState::RetryWait
                .transition(RunState::Queued, true, false)
                .is_err()
        );
    }
}
