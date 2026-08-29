//! Provider-side relay boundary for one exact durable settlement transaction.

use std::error::Error;
use std::fmt;

use deadcat_rfq_provider::{RelayAttempt, RelayFailureClass, RelayObservation};

/// One completed status-first relay/reconciliation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayAttemptResult {
    observation: RelayObservation,
    last_failure: Option<RelayFailureClass>,
}

impl RelayAttemptResult {
    #[must_use]
    pub const fn observed(observation: RelayObservation) -> Self {
        Self {
            observation,
            last_failure: None,
        }
    }

    #[must_use]
    pub const fn policy_rejected(observation: RelayObservation) -> Self {
        Self {
            observation,
            last_failure: Some(RelayFailureClass::PolicyRejected),
        }
    }

    #[must_use]
    pub const fn observation(self) -> RelayObservation {
        self.observation
    }

    #[must_use]
    pub const fn last_failure(self) -> Option<RelayFailureClass> {
        self.last_failure
    }
}

/// A relay failure that should temporarily stop new settlement admission.
///
/// The concrete error is retained for operator logs but only the stable,
/// non-sensitive class is written to durable provider state.
#[derive(Debug)]
pub struct RelaySourceError<E> {
    class: RelayFailureClass,
    source: E,
}

impl<E> RelaySourceError<E> {
    #[must_use]
    pub const fn new(class: RelayFailureClass, source: E) -> Self {
        Self { class, source }
    }

    #[must_use]
    pub const fn class(&self) -> RelayFailureClass {
        self.class
    }
}

impl<E: fmt::Display> fmt::Display for RelaySourceError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "provider relay {:?}: {}",
            self.class, self.source
        )
    }
}

impl<E: Error + 'static> Error for RelaySourceError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Chain/mempool adapter allowed to inspect and relay only the transaction
/// bytes exposed only after the durable outbox has issued a fenced
/// [`RelayAttempt`].
pub trait ProviderRelaySource {
    type Error: Error + Send + Sync + 'static;

    fn relay_once(
        &self,
        attempt: &RelayAttempt,
    ) -> Result<RelayAttemptResult, RelaySourceError<Self::Error>>;
}
