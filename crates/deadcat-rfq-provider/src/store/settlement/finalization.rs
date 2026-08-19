//! Exact provider signing, PSET finalization, and signed-artifact persistence.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use elements::encode::{deserialize, serialize};
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::Secp256k1;
use elements::{OutPoint, SchnorrSighashType, Transaction, TxOut};
use thiserror::Error;

use super::{canonical_pset, input_outpoint, verify_taproot_signature};
use crate::model::{Clock, MAX_SETTLEMENT_BYTES, RecoveryAction, SigningJob, TransactionFee};
use crate::wallet::{P2TR_SIGHASH_ALL_SIGNATURE_BYTES, ProviderSigner, SigningResponse};

use super::super::{
    CommitOutcome, ExactSigningState, ProviderError, ReservationBook, SignedOutcome,
    VerifiedSignedPset,
};

/// Transport-free coordinator for one exact durable provider signing job.
///
/// The coordinator never calls the signer until the supplied job has been
/// matched byte-for-byte against this provider book. It holds no database lock
/// while wallet or HSM work runs, exposes no locally signed candidate before a
/// successful durable write, and returns the already-stored winner when a
/// concurrent valid signature encoding wins the persistence race.
pub struct ProviderSigningCoordinator<'a, S: ProviderSigner + ?Sized> {
    book: &'a ReservationBook,
    signer: &'a S,
}

impl<'a, S: ProviderSigner + ?Sized> ProviderSigningCoordinator<'a, S> {
    #[must_use]
    pub const fn new(book: &'a ReservationBook, signer: &'a S) -> Self {
        Self { book, signer }
    }

    /// Complete a freshly committed or idempotently replayed validation
    /// outcome. An already-signed outcome is rechecked against this book and
    /// returned without invoking the signer.
    pub fn complete<C: Clock>(
        &self,
        outcome: CommitOutcome,
        clock: &C,
    ) -> Result<SignedOutcome, SigningFinalizationError> {
        match outcome {
            CommitOutcome::NewlyCommitted(job) | CommitOutcome::AlreadyCommitted(job) => {
                self.finalize(&job, clock)
            }
            CommitOutcome::AlreadySigned(artifact) => {
                Ok(self.book.replay_signed_artifact(&artifact)?)
            }
        }
    }

    /// Resume one exact action returned by [`ReservationBook::recovery_actions`].
    pub fn recover<C: Clock>(
        &self,
        action: RecoveryAction,
        clock: &C,
    ) -> Result<SignedOutcome, SigningFinalizationError> {
        match action {
            RecoveryAction::SignCommittedExact(job) => self.finalize(&job, clock),
            RecoveryAction::ReplaySignedExact(artifact) => {
                Ok(self.book.replay_signed_artifact(&artifact)?)
            }
        }
    }

    /// Sign and durably finalize one unforgeable job obtained from a commit or
    /// recovery action.
    ///
    /// No live chain query occurs here. The exact committed PSET contains the
    /// sighash prevouts that were authoritatively checked before commitment;
    /// those inputs may legitimately appear spent during crash recovery.
    pub fn finalize<C: Clock>(
        &self,
        expected_job: &SigningJob,
        clock: &C,
    ) -> Result<SignedOutcome, SigningFinalizationError> {
        let durable_job = match self.book.signing_state_for(expected_job)? {
            ExactSigningState::Pending(job) => job,
            ExactSigningState::Signed(artifact) => {
                return Ok(self.book.replay_signed_artifact(&artifact)?);
            }
        };
        let prepared = PreparedSigningPset::new(&durable_job)?;
        let response = match self.signer.sign(&durable_job) {
            Ok(response) => response,
            Err(error) => {
                // A concurrent worker may have completed the same exact job
                // while this signer failed. Never replace its durable success
                // with a local failure.
                if let ExactSigningState::Signed(artifact) =
                    self.book.signing_state_for(&durable_job)?
                {
                    return Ok(self.book.replay_signed_artifact(&artifact)?);
                }
                return Err(SigningFinalizationError::Signer(Box::new(error)));
            }
        };
        let candidate = match prepared.finalize(&durable_job, &response, self.book.identity()) {
            Ok(candidate) => candidate,
            Err(error) => {
                // As with a signer error, discard a malformed local response
                // if another worker has already stored the exact job's valid
                // winner. Nothing derived from the losing response escapes.
                if let ExactSigningState::Signed(artifact) =
                    self.book.signing_state_for(&durable_job)?
                {
                    return Ok(self.book.replay_signed_artifact(&artifact)?);
                }
                return Err(error);
            }
        };
        Ok(self
            .book
            .record_finalized_pset(&durable_job, candidate, clock)?)
    }
}

struct PreparedSigningPset {
    original_bytes: Vec<u8>,
    pset: PartiallySignedTransaction,
    transaction: Transaction,
    prevouts: Vec<TxOut>,
    target_indexes: Vec<usize>,
}

impl PreparedSigningPset {
    fn new(job: &SigningJob) -> Result<Self, SigningFinalizationError> {
        let original_bytes = canonical_pset(job.pre_sign_payload())
            .map_err(|error| SigningFinalizationError::InvalidCommittedPset(error.to_string()))?;
        let pset = deserialize::<PartiallySignedTransaction>(&original_bytes)
            .map_err(|error| SigningFinalizationError::InvalidCommittedPset(error.to_string()))?;
        let transaction = pset
            .extract_tx()
            .map_err(|error| SigningFinalizationError::InvalidCommittedPset(error.to_string()))?;
        let mut indexes = BTreeMap::new();
        let mut prevouts = Vec::with_capacity(pset.inputs().len());
        for (index, input) in pset.inputs().iter().enumerate() {
            let outpoint = input_outpoint(input);
            if indexes.insert(outpoint, index).is_some() {
                return Err(SigningFinalizationError::DuplicateInput(outpoint));
            }
            prevouts.push(input.witness_utxo.clone().ok_or(
                SigningFinalizationError::InvalidCommittedInput {
                    index,
                    reason: "missing witness UTXO",
                },
            )?);
        }

        let secp = Secp256k1::new();
        let mut target_outpoints = BTreeSet::new();
        let mut target_indexes = Vec::with_capacity(job.targets().len());
        for target in job.targets() {
            if !target_outpoints.insert(target.outpoint()) {
                return Err(SigningFinalizationError::DuplicateTarget(target.outpoint()));
            }
            let index = indexes.get(&target.outpoint()).copied().ok_or(
                SigningFinalizationError::MissingTargetInput(target.outpoint()),
            )?;
            let input = &pset.inputs()[index];
            let prevout = &prevouts[index];
            if input.tap_internal_key != Some(target.internal_key())
                || input.tap_merkle_root.is_some()
                || input.sighash_type != Some(SchnorrSighashType::All.into())
                || input.tap_key_sig.is_some()
                || input.final_script_witness.is_some()
                || prevout.script_pubkey
                    != elements::Script::new_v1_p2tr(&secp, target.internal_key(), None)
            {
                return Err(SigningFinalizationError::InvalidCommittedInput {
                    index,
                    reason: "provider target is not an unsigned tree-less P2TR SIGHASH_ALL input",
                });
            }
            target_indexes.push(index);
        }

        Ok(Self {
            original_bytes,
            pset,
            transaction,
            prevouts,
            target_indexes,
        })
    }

    fn finalize(
        self,
        job: &SigningJob,
        response: &SigningResponse,
        identity: crate::model::ProviderIdentity,
    ) -> Result<VerifiedSignedPset, SigningFinalizationError> {
        if response.commitment() != job.commitment() {
            return Err(SigningFinalizationError::ResponseCommitmentMismatch);
        }
        if response.signatures().len() != job.targets().len() {
            return Err(SigningFinalizationError::ResponseShape(
                "signature count does not match the durable target count",
            ));
        }

        let mut verified = Vec::with_capacity(job.targets().len());
        for (position, ((target, signature), index)) in job
            .targets()
            .iter()
            .zip(response.signatures())
            .zip(&self.target_indexes)
            .enumerate()
        {
            if signature.outpoint() != target.outpoint() {
                return Err(SigningFinalizationError::ResponseShape(
                    "signature order or outpoint does not match the durable target",
                ));
            }
            let signature_value = signature.signature();
            if signature_value.hash_ty != SchnorrSighashType::All
                || signature.serialized().len() != P2TR_SIGHASH_ALL_SIGNATURE_BYTES
                || signature.serialized()[P2TR_SIGHASH_ALL_SIGNATURE_BYTES - 1]
                    != SchnorrSighashType::All as u8
            {
                return Err(SigningFinalizationError::ResponseShape(
                    "provider signature is not an explicit 65-byte SIGHASH_ALL signature",
                ));
            }
            verify_taproot_signature(
                &self.transaction,
                &self.prevouts,
                *index,
                signature_value,
                target.internal_key(),
                identity.genesis_hash(),
            )
            .map_err(|error| SigningFinalizationError::InvalidProviderSignature {
                position,
                outpoint: target.outpoint(),
                detail: error.to_string(),
            })?;
            verified.push((*index, signature_value));
        }

        let mut finalized = self.pset;
        for (index, signature) in &verified {
            let input = &mut finalized.inputs_mut()[*index];
            input.tap_key_sig = Some(*signature);
            input.final_script_witness = Some(vec![signature.to_vec()]);
        }
        finalized
            .sanity_check()
            .map_err(|error| SigningFinalizationError::InvalidFinalizedPset(error.to_string()))?;
        let signed_bytes = serialize(&finalized);
        if signed_bytes.len() > MAX_SETTLEMENT_BYTES {
            return Err(SigningFinalizationError::FinalizedPayloadTooLarge {
                maximum: MAX_SETTLEMENT_BYTES,
                actual: signed_bytes.len(),
            });
        }
        let reparsed = deserialize::<PartiallySignedTransaction>(&signed_bytes)
            .map_err(|error| SigningFinalizationError::InvalidFinalizedPset(error.to_string()))?;
        if serialize(&reparsed) != signed_bytes {
            return Err(SigningFinalizationError::NonCanonicalFinalizedPset);
        }

        let mut normalized = reparsed.clone();
        for (index, _) in &verified {
            let input = &mut normalized.inputs_mut()[*index];
            input.tap_key_sig = None;
            input.final_script_witness = None;
        }
        if serialize(&normalized) != self.original_bytes {
            return Err(SigningFinalizationError::UnexpectedPsetMutation);
        }

        let finalized_transaction = reparsed
            .extract_tx()
            .map_err(|error| SigningFinalizationError::InvalidFinalizedPset(error.to_string()))?;
        verify_every_final_signature(
            &reparsed,
            &finalized_transaction,
            &self.prevouts,
            identity.genesis_hash(),
        )?;
        finalized_transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &self.prevouts)
            .map_err(|error| SigningFinalizationError::ConfidentialProofs(error.to_string()))?;
        let actual_fee = TransactionFee::new(
            job.fee().policy_asset(),
            finalized_transaction.fee_in(job.fee().policy_asset()),
            u64::try_from(finalized_transaction.weight())
                .map_err(|_| SigningFinalizationError::TransactionSizeOverflow)?,
            u64::try_from(finalized_transaction.vsize())
                .map_err(|_| SigningFinalizationError::TransactionSizeOverflow)?,
            u64::try_from(finalized_transaction.discount_vsize())
                .map_err(|_| SigningFinalizationError::TransactionSizeOverflow)?,
        )
        .map_err(|error| SigningFinalizationError::InvalidFeeFacts(error.to_string()))?;
        if actual_fee != job.fee() {
            return Err(SigningFinalizationError::FeeFactsMismatch {
                expected: job.fee(),
                actual: Box::new(actual_fee),
            });
        }

        Ok(VerifiedSignedPset(signed_bytes))
    }
}

fn verify_every_final_signature(
    pset: &PartiallySignedTransaction,
    transaction: &Transaction,
    prevouts: &[TxOut],
    genesis_hash: elements::BlockHash,
) -> Result<(), SigningFinalizationError> {
    let secp = Secp256k1::new();
    for (index, (input, prevout)) in pset.inputs().iter().zip(prevouts).enumerate() {
        let internal_key =
            input
                .tap_internal_key
                .ok_or(SigningFinalizationError::InvalidFinalizedInput {
                    index,
                    reason: "missing Taproot internal key",
                })?;
        let signature =
            input
                .tap_key_sig
                .ok_or(SigningFinalizationError::InvalidFinalizedInput {
                    index,
                    reason: "missing Taproot key-path signature",
                })?;
        if input.sighash_type != Some(SchnorrSighashType::All.into())
            || signature.hash_ty != SchnorrSighashType::All
            || input.final_script_witness.as_ref() != Some(&vec![signature.to_vec()])
            || prevout.script_pubkey != elements::Script::new_v1_p2tr(&secp, internal_key, None)
        {
            return Err(SigningFinalizationError::InvalidFinalizedInput {
                index,
                reason: "input is not one exact finalized tree-less P2TR SIGHASH_ALL spend",
            });
        }
        verify_taproot_signature(
            transaction,
            prevouts,
            index,
            signature,
            internal_key,
            genesis_hash,
        )
        .map_err(|error| SigningFinalizationError::InvalidFinalSignature {
            index,
            detail: error.to_string(),
        })?;
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum SigningFinalizationError {
    #[error("provider state rejected signing or finalization: {0}")]
    Provider(#[from] ProviderError),
    #[error("provider signer failed: {0}")]
    Signer(#[source] Box<dyn Error + Send + Sync>),
    #[error("invalid committed PSET: {0}")]
    InvalidCommittedPset(String),
    #[error("committed PSET contains duplicate input {0:?}")]
    DuplicateInput(OutPoint),
    #[error("durable signing job contains duplicate target {0:?}")]
    DuplicateTarget(OutPoint),
    #[error("committed PSET does not contain provider target {0:?}")]
    MissingTargetInput(OutPoint),
    #[error("invalid committed input {index}: {reason}")]
    InvalidCommittedInput { index: usize, reason: &'static str },
    #[error("signer response is bound to a different signing commitment")]
    ResponseCommitmentMismatch,
    #[error("invalid signer response: {0}")]
    ResponseShape(&'static str),
    #[error("invalid provider signature {position} for {outpoint:?}: {detail}")]
    InvalidProviderSignature {
        position: usize,
        outpoint: OutPoint,
        detail: String,
    },
    #[error("invalid finalized PSET: {0}")]
    InvalidFinalizedPset(String),
    #[error("finalized PSET does not have one canonical encoding")]
    NonCanonicalFinalizedPset,
    #[error("finalized PSET changed data other than the provider signature fields")]
    UnexpectedPsetMutation,
    #[error("signed settlement has {actual} bytes; maximum is {maximum}")]
    FinalizedPayloadTooLarge { maximum: usize, actual: usize },
    #[error("invalid finalized input {index}: {reason}")]
    InvalidFinalizedInput { index: usize, reason: &'static str },
    #[error("invalid finalized signature at input {index}: {detail}")]
    InvalidFinalSignature { index: usize, detail: String },
    #[error("finalized confidential proof or balance verification failed: {0}")]
    ConfidentialProofs(String),
    #[error("finalized transaction size does not fit the provider fee model")]
    TransactionSizeOverflow,
    #[error("invalid finalized fee facts: {0}")]
    InvalidFeeFacts(String),
    #[error("finalized fee facts changed: expected {expected:?}, got {actual:?}")]
    FeeFactsMismatch {
        expected: TransactionFee,
        actual: Box<TransactionFee>,
    },
}

#[cfg(test)]
mod tests;
