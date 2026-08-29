use std::collections::BTreeSet;

use deadcat_rfq_client::{
    ExecutionJournal, ExecutionJournalError, ExecutionJournalKey, JournaledExecution,
    MAX_EXECUTION_JOURNAL_PAGE_SIZE,
};
use deadcat_rfq_rpc::SettlementLayoutDto;
use deadcat_rfq_wallet::TakerWalletIdentity;
use elements::{OutPoint, pset::PartiallySignedTransaction};
use thiserror::Error;

/// Complete startup view of wallet inputs that cannot be selected again.
#[derive(Clone, Debug)]
pub struct FundingRecoverySnapshot {
    exclusions: BTreeSet<OutPoint>,
    pending: Vec<JournaledExecution>,
}

impl FundingRecoverySnapshot {
    #[must_use]
    pub fn exclusions(&self) -> &BTreeSet<OutPoint> {
        &self.exclusions
    }

    #[must_use]
    pub fn pending(&self) -> &[JournaledExecution] {
        &self.pending
    }

    #[must_use]
    pub fn into_parts(self) -> (BTreeSet<OutPoint>, Vec<JournaledExecution>) {
        (self.exclusions, self.pending)
    }
}

/// Page and validate the complete journal before wallet funding becomes ready.
///
/// Every record must belong to the configured wallet owner, chain genesis, and
/// policy asset. A shared or accidentally swapped journal therefore fails
/// closed before any of its outpoints can influence this wallet's funding.
///
/// Every state except an authenticated pre-commit `Released` observation keeps
/// the taker inputs excluded. In particular, `Signed` is provider-terminal but
/// not wallet-terminal: the valid transaction may still be broadcast later.
pub fn load_funding_recovery<J: ExecutionJournal>(
    journal: &J,
    identity: TakerWalletIdentity,
) -> Result<FundingRecoverySnapshot, FundingRecoveryError> {
    let mut after = None;
    let mut exclusions = BTreeSet::new();
    let mut pending = Vec::new();
    loop {
        let page = journal.list_after(after, MAX_EXECUTION_JOURNAL_PAGE_SIZE)?;
        if page.is_empty() {
            break;
        }
        for execution in page {
            let key = execution.key();
            if after.is_some_and(|previous| key <= previous) {
                return Err(FundingRecoveryError::JournalOrder);
            }
            after = Some(key);
            validate_execution_identity(&execution, identity)?;
            if !execution.observation().requires_taker_funding_exclusion() {
                continue;
            }
            for outpoint in execution_taker_input_outpoints(&execution)? {
                if !exclusions.insert(outpoint) {
                    return Err(FundingRecoveryError::DuplicateTakerInput(outpoint));
                }
            }
            pending.push(execution);
        }
    }
    Ok(FundingRecoverySnapshot {
        exclusions,
        pending,
    })
}

pub(crate) fn validate_execution_identity(
    execution: &JournaledExecution,
    identity: TakerWalletIdentity,
) -> Result<(), FundingRecoveryError> {
    let binding = execution.attempt().binding();
    let key = execution.key();
    if binding.client_endpoint().to_bytes() != identity.owner() {
        return Err(FundingRecoveryError::JournalClientEndpointMismatch { key });
    }
    if binding.chain().genesis_hash != identity.genesis_hash() {
        return Err(FundingRecoveryError::JournalGenesisHashMismatch { key });
    }
    if binding.policy_asset() != identity.policy_asset() {
        return Err(FundingRecoveryError::JournalPolicyAssetMismatch { key });
    }
    Ok(())
}

pub(crate) fn execution_taker_input_outpoints(
    execution: &JournaledExecution,
) -> Result<BTreeSet<OutPoint>, FundingRecoveryError> {
    let pset = execution
        .attempt()
        .pset()
        .to_pset()
        .map_err(|error| FundingRecoveryError::InvalidPset(error.to_string()))?;
    taker_input_outpoints(&pset, execution.attempt().layout())
}

fn taker_input_outpoints(
    pset: &PartiallySignedTransaction,
    layout: &SettlementLayoutDto,
) -> Result<BTreeSet<OutPoint>, FundingRecoveryError> {
    let mut provider_indices = BTreeSet::new();
    for placement in &layout.provider_inputs {
        let index = usize::from(placement.transaction_index);
        if index >= pset.inputs().len() || !provider_indices.insert(index) {
            return Err(FundingRecoveryError::InvalidProviderInputPartition);
        }
    }
    let mut outpoints = BTreeSet::new();
    for (index, input) in pset.inputs().iter().enumerate() {
        if !provider_indices.contains(&index) {
            if !outpoints.insert(OutPoint::new(
                input.previous_txid,
                input.previous_output_index,
            )) {
                return Err(FundingRecoveryError::DuplicateInputWithinExecution);
            }
        }
    }
    if outpoints.is_empty() {
        return Err(FundingRecoveryError::MissingTakerInput);
    }
    Ok(outpoints)
}

#[derive(Debug, Error)]
pub enum FundingRecoveryError {
    #[error(transparent)]
    Journal(#[from] ExecutionJournalError),
    #[error("execution journal pagination is not strictly ordered")]
    JournalOrder,
    #[error("execution journal record {key:?} belongs to a different taker client endpoint")]
    JournalClientEndpointMismatch { key: ExecutionJournalKey },
    #[error("execution journal record {key:?} belongs to a different chain genesis hash")]
    JournalGenesisHashMismatch { key: ExecutionJournalKey },
    #[error("execution journal record {key:?} belongs to a different policy asset")]
    JournalPolicyAssetMismatch { key: ExecutionJournalKey },
    #[error("execution journal record contains an invalid settlement PSET: {0}")]
    InvalidPset(String),
    #[error("execution journal record has an invalid provider-input partition")]
    InvalidProviderInputPartition,
    #[error("execution journal record has no taker wallet input")]
    MissingTakerInput,
    #[error("execution journal record repeats a taker input outpoint")]
    DuplicateInputWithinExecution,
    #[error("taker input {0} appears in more than one non-released execution")]
    DuplicateTakerInput(OutPoint),
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_client::ExecutionJournalObservation;
    use deadcat_rfq_rpc::{
        FixedBytes32, InputPlacementDto, RelayObservationDto, RelayStatusDto, ReleaseReasonDto,
        ReservationStateDto, ReservationStatusDto, SettlementPset,
    };
    use elements::{Txid, hashes::Hash as _, pset::Input as PsetInput};

    use super::*;

    fn outpoint(marker: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
    }

    fn pset_with_inputs(inputs: impl IntoIterator<Item = OutPoint>) -> PartiallySignedTransaction {
        let mut pset = PartiallySignedTransaction::new_v2();
        for input in inputs {
            pset.add_input(PsetInput::from_prevout(input));
        }
        pset
    }

    fn layout_with_provider_inputs(provider_indices: &[u16]) -> SettlementLayoutDto {
        SettlementLayoutDto {
            taker_payment_input: 0,
            provider_inputs: provider_indices
                .iter()
                .enumerate()
                .map(|(quote_input_id, transaction_index)| InputPlacementDto {
                    quote_input_id: u16::try_from(quote_input_id).expect("small fixture"),
                    transaction_index: *transaction_index,
                })
                .collect(),
            quote_outputs: Vec::new(),
        }
    }

    fn status(state: ReservationStateDto) -> ReservationStatusDto {
        ReservationStatusDto {
            reservation_id: FixedBytes32::new([0x10; 32]),
            quote_commitment: FixedBytes32::new([0x11; 32]),
            created_at_millis: 100,
            accept_before_millis: 200,
            state,
        }
    }

    #[test]
    fn partition_excludes_provider_inputs_and_returns_every_taker_input() {
        let first_taker = outpoint(0x21, 0);
        let first_provider = outpoint(0x22, 1);
        let second_taker = outpoint(0x23, 2);
        let second_provider = outpoint(0x24, 3);
        let pset = pset_with_inputs([first_taker, first_provider, second_taker, second_provider]);

        let actual = taker_input_outpoints(&pset, &layout_with_provider_inputs(&[1, 3]))
            .expect("valid provider/taker partition");

        assert_eq!(actual, BTreeSet::from([first_taker, second_taker]));
    }

    #[test]
    fn duplicate_taker_outpoint_fails_closed() {
        let repeated = outpoint(0x31, 0);
        let pset = pset_with_inputs([repeated, outpoint(0x32, 0), repeated]);

        assert!(matches!(
            taker_input_outpoints(&pset, &layout_with_provider_inputs(&[1])),
            Err(FundingRecoveryError::DuplicateInputWithinExecution)
        ));
    }

    #[test]
    fn malformed_provider_partition_fails_closed() {
        let pset = pset_with_inputs([outpoint(0x41, 0), outpoint(0x42, 0)]);

        assert!(matches!(
            taker_input_outpoints(&pset, &layout_with_provider_inputs(&[1, 1])),
            Err(FundingRecoveryError::InvalidProviderInputPartition)
        ));
        assert!(matches!(
            taker_input_outpoints(&pset, &layout_with_provider_inputs(&[2])),
            Err(FundingRecoveryError::InvalidProviderInputPartition)
        ));
    }

    #[test]
    fn all_provider_inputs_fail_closed_instead_of_returning_empty_exclusions() {
        let pset = pset_with_inputs([outpoint(0x51, 0), outpoint(0x52, 0)]);

        assert!(matches!(
            taker_input_outpoints(&pset, &layout_with_provider_inputs(&[0, 1])),
            Err(FundingRecoveryError::MissingTakerInput)
        ));
    }

    #[test]
    fn only_released_observations_allow_funding_reuse() {
        let reserved = ExecutionJournalObservation::Reserved(status(ReservationStateDto::Reserved));
        let released =
            ExecutionJournalObservation::Released(status(ReservationStateDto::Released {
                reason: ReleaseReasonDto::ClientCancelled,
                at_millis: 150,
            }));
        let committed =
            ExecutionJournalObservation::Committed(status(ReservationStateDto::Committed {
                signing_commitment: FixedBytes32::new([0x12; 32]),
                committed_at_millis: 150,
            }));
        let signed_pset = SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
            .expect("empty fixture PSET");
        let transaction = signed_pset
            .to_pset()
            .expect("fixture PSET")
            .extract_tx()
            .expect("fixture transaction");
        let signed = ExecutionJournalObservation::Signed(status(ReservationStateDto::Signed {
            signing_commitment: FixedBytes32::new([0x12; 32]),
            artifact_digest: FixedBytes32::new([0x13; 32]),
            committed_at_millis: 150,
            signed_at_millis: 160,
            relay: RelayStatusDto {
                txid: transaction.txid(),
                wtxid: transaction.wtxid(),
                revision: 0,
                observation: RelayObservationDto::Unobserved,
                last_observed_at_millis: None,
                next_attempt_at_millis: Some(160),
                last_failure: None,
                last_failure_at_millis: None,
                attempt_count: 0,
                reorg_count: 0,
            },
            signed_pset,
        }));

        assert!(ExecutionJournalObservation::Armed.requires_taker_funding_exclusion());
        assert!(reserved.requires_taker_funding_exclusion());
        assert!(!released.requires_taker_funding_exclusion());
        assert!(committed.requires_taker_funding_exclusion());
        assert!(signed.requires_taker_funding_exclusion());
    }
}
