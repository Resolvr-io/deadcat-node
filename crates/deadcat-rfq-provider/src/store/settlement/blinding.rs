//! Provider-side non-last blinding of an exact reserved RFQ contribution.
//!
//! This stage runs before the taker balances the transaction's blinding
//! factors or signs. It resolves the durable firm quote and a fresh in-memory
//! wallet snapshot, validates the quote's exact placement in the submitted
//! unblinded PSET, and gives `elements` only the confidential openings for the
//! reserved provider inputs. Openings and generated output blinders never
//! leave this module.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;

use elements::OutPoint;
use elements::encode::{deserialize, serialize};
use elements::pset::{Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::rand::{CryptoRng, RngCore};
use thiserror::Error;

use super::{
    AuthoritativePrevout, SettlementContextState, SettlementLayout, SettlementValidationError,
    SettlementValidationLimits, canonical_pset, validate_common_input, validate_global,
    validate_layout, validate_provider_input, validate_quoted_output,
};
use crate::inventory::{InventoryCoordinator, InventoryCoordinatorError};
use crate::model::{Clock, MAX_SETTLEMENT_BYTES, ReservationAccess, ReservationId};
use crate::quote::QuoteBlinderRole;
use crate::store::ProviderError;
use crate::wallet::InventorySource;

/// Canonically encoded PSET after exactly the provider-owned outputs were
/// blinded as the non-last participant.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderBlindedPset(Vec<u8>);

impl ProviderBlindedPset {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for ProviderBlindedPset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderBlindedPset")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Transport-free coordinator for the provider's collaborative-blinding turn.
pub struct ProviderBlindingCoordinator<'a, S> {
    inventory: &'a InventoryCoordinator<S>,
    limits: SettlementValidationLimits,
}

impl<'a, S> ProviderBlindingCoordinator<'a, S>
where
    S: InventorySource,
{
    #[must_use]
    pub fn new(inventory: &'a InventoryCoordinator<S>) -> Self {
        Self {
            inventory,
            limits: SettlementValidationLimits::default(),
        }
    }

    #[must_use]
    pub const fn with_limits(mut self, limits: SettlementValidationLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Validate and blind one unblinded PSET for a still-live reservation.
    ///
    /// The operation mutates a private clone. Any validation or blinding
    /// failure discards that clone, so callers never observe a partially
    /// blinded PSET. A later final-settlement validation remains responsible
    /// for authoritative taker prevouts, final balancing proofs, signatures,
    /// fees, and provider-output recovery.
    ///
    /// Successful retries before commitment intentionally use fresh randomness
    /// and may return different, equally valid blinded bytes. Callers must not
    /// claim byte-level idempotency for this reversible stage. Once one
    /// taker-signed PSET is durably committed, the signing path accepts and
    /// replays only that exact payload.
    pub fn blind<C, R>(
        &self,
        access: ReservationAccess,
        layout: &SettlementLayout,
        submitted_pset: &[u8],
        clock: &C,
        rng: &mut R,
    ) -> Result<ProviderBlindedPset, ProviderBlindingError<S::Error>>
    where
        C: Clock,
        R: RngCore + CryptoRng,
    {
        let canonical = canonical_pset(submitted_pset)?;
        let original = deserialize::<PartiallySignedTransaction>(&canonical)
            .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;
        validate_global(&original, self.limits)?;

        let book = self.inventory.reservation_book();
        let context = book.settlement_context(access)?;
        if !matches!(context.state, SettlementContextState::Reserved) {
            return Err(ProviderBlindingError::PointOfNoReturn(
                access.reservation_id(),
            ));
        }
        let now = clock.now();
        if now >= context.quote.accept_before() {
            return Err(ProviderError::ReservationDeadlineElapsed {
                accept_before: context.quote.accept_before(),
                now,
            }
            .into());
        }
        validate_layout(&context.quote, layout, &original)?;

        let current = self.inventory.current(&now)?;
        let mut openings = HashMap::new();
        let targets = context
            .provider_targets
            .iter()
            .map(|target| (target.outpoint(), *target))
            .collect::<BTreeMap<_, _>>();
        let provider_indexes = layout
            .provider_inputs
            .iter()
            .map(|placement| placement.transaction_index)
            .collect::<BTreeSet<_>>();

        for placement in &layout.provider_inputs {
            let quoted = context
                .quote
                .contribution()
                .inputs()
                .iter()
                .find(|input| input.id() == placement.quote_input)
                .ok_or(SettlementValidationError::LayoutInputMismatch)?;
            let target = targets.get(&quoted.outpoint()).ok_or(
                SettlementValidationError::InvalidProviderInput {
                    index: placement.transaction_index,
                    reason: "durable provider target is missing",
                },
            )?;
            if quoted.inventory_binding() != target.inventory_binding() {
                return Err(SettlementValidationError::InvalidProviderInput {
                    index: placement.transaction_index,
                    reason: "quoted inventory binding disagrees with durable provider target",
                }
                .into());
            }
            let owned = current.output(quoted.outpoint()).ok_or(
                ProviderBlindingError::ProviderInputAbsent(quoted.outpoint()),
            )?;
            if owned.binding() != quoted.inventory_binding()
                || owned.txout() != quoted.witness_utxo()
            {
                return Err(ProviderBlindingError::ProviderInputBinding(
                    quoted.outpoint(),
                ));
            }
            let authoritative = AuthoritativePrevout::new(owned.outpoint(), owned.txout().clone());
            validate_common_input(
                &original.inputs()[placement.transaction_index],
                &authoritative,
                placement.transaction_index,
            )?;
            validate_provider_input(
                &original.inputs()[placement.transaction_index],
                &authoritative,
                quoted.witness_utxo(),
                *target,
                placement.transaction_index,
            )?;
            openings.insert(
                placement.transaction_index,
                owned.confidential_input_opening().txout_secrets(),
            );
        }

        let provider_outputs =
            validate_unblinded_outputs(&original, &context.quote, layout, &provider_indexes)?;
        let mut blinded = original.clone();
        // `elements` returns the generated ABF/VBF values even though this
        // protocol never needs them. Drop the vector immediately; the upstream
        // scalar wrappers are Copy and do not currently offer zeroizing drops.
        drop(
            blinded
                .blind_non_last(rng, &Secp256k1::new(), &openings)
                .map_err(|error| ProviderBlindingError::PsetBlinding(error.to_string()))?,
        );
        let encoded = serialize(&blinded);
        if encoded.len() > MAX_SETTLEMENT_BYTES {
            return Err(ProviderBlindingError::PayloadTooLarge {
                maximum: MAX_SETTLEMENT_BYTES,
                actual: encoded.len(),
            });
        }
        let canonical_blinded = canonical_pset(&encoded)?;
        let reparsed = deserialize::<PartiallySignedTransaction>(&canonical_blinded)
            .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;
        validate_blinding_mutation_scope(&original, &reparsed, &provider_outputs)?;
        Ok(ProviderBlindedPset(canonical_blinded))
    }
}

fn validate_unblinded_outputs<E>(
    pset: &PartiallySignedTransaction,
    quote: &crate::quote::FirmQuote,
    layout: &SettlementLayout,
    provider_indexes: &BTreeSet<usize>,
) -> Result<BTreeSet<usize>, ProviderBlindingError<E>>
where
    E: Error + Send + Sync + 'static,
{
    let mut provider_outputs = BTreeSet::new();
    for placement in &layout.quote_outputs {
        let quoted = quote
            .contribution()
            .outputs()
            .iter()
            .find(|output| output.id() == placement.quote_output)
            .ok_or(SettlementValidationError::LayoutOutputMismatch)?;
        let output = &pset.outputs()[placement.transaction_index];
        validate_quoted_output(output, quoted, layout, placement.transaction_index)?;
        if matches!(quoted.blinder(), QuoteBlinderRole::ProviderInput(_)) {
            provider_outputs.insert(placement.transaction_index);
        }
    }

    for (output_index, output) in pset.outputs().iter().enumerate() {
        require_unblinded_output(output, output_index)?;
        let blinder = output
            .blinder_index
            .and_then(|index| usize::try_from(index).ok());
        if blinder.is_some_and(|input_index| provider_indexes.contains(&input_index))
            && !provider_outputs.contains(&output_index)
        {
            return Err(ProviderBlindingError::UnquotedProviderBlindedOutput(
                output_index,
            ));
        }
    }
    if provider_outputs.is_empty() {
        return Err(ProviderBlindingError::NoProviderBlindedOutputs);
    }
    Ok(provider_outputs)
}

fn require_unblinded_output<E: Error + Send + Sync + 'static>(
    output: &PsetOutput,
    index: usize,
) -> Result<(), ProviderBlindingError<E>> {
    if output.asset_comm.is_some()
        || output.amount_comm.is_some()
        || output.ecdh_pubkey.is_some()
        || output.value_rangeproof.is_some()
        || output.asset_surjection_proof.is_some()
        || output.blind_value_proof.is_some()
        || output.blind_asset_proof.is_some()
    {
        return Err(ProviderBlindingError::OutputAlreadyBlinded(index));
    }
    Ok(())
}

fn validate_blinding_mutation_scope<E: Error + Send + Sync + 'static>(
    original: &PartiallySignedTransaction,
    blinded: &PartiallySignedTransaction,
    provider_outputs: &BTreeSet<usize>,
) -> Result<(), ProviderBlindingError<E>> {
    if blinded.global.scalars.len() != 1 {
        return Err(ProviderBlindingError::UnexpectedMutation);
    }
    let mut normalized = blinded.clone();
    normalized.global.scalars = original.global.scalars.clone();
    for index in provider_outputs {
        let output = &blinded.outputs()[*index];
        if output.asset_comm.is_none()
            || output.amount_comm.is_none()
            || output.ecdh_pubkey.is_none()
            || output.value_rangeproof.is_none()
            || output.asset_surjection_proof.is_none()
            || output.blind_value_proof.is_none()
            || output.blind_asset_proof.is_none()
        {
            return Err(ProviderBlindingError::IncompleteProviderOutput(*index));
        }
        let normalized_output = &mut normalized.outputs_mut()[*index];
        let original_output = &original.outputs()[*index];
        normalized_output.asset_comm = original_output.asset_comm;
        normalized_output.amount_comm = original_output.amount_comm;
        normalized_output.ecdh_pubkey = original_output.ecdh_pubkey;
        normalized_output.value_rangeproof = original_output.value_rangeproof.clone();
        normalized_output.asset_surjection_proof = original_output.asset_surjection_proof.clone();
        normalized_output.blind_value_proof = original_output.blind_value_proof.clone();
        normalized_output.blind_asset_proof = original_output.blind_asset_proof.clone();
    }
    if &normalized != original {
        return Err(ProviderBlindingError::UnexpectedMutation);
    }
    Ok(())
}

/// Failures before or during the provider's non-last blinding turn.
#[derive(Debug, Error)]
pub enum ProviderBlindingError<SourceError>
where
    SourceError: Error + Send + Sync + 'static,
{
    #[error(transparent)]
    Provider(#[from] ProviderError),
    #[error(transparent)]
    Settlement(#[from] SettlementValidationError),
    #[error("fresh wallet inventory is unavailable: {0}")]
    Inventory(#[from] InventoryCoordinatorError<SourceError>),
    #[error("reservation {0:?} already crossed the provider signing point")]
    PointOfNoReturn(ReservationId),
    #[error("reserved provider input {0:?} is absent from fresh wallet inventory")]
    ProviderInputAbsent(OutPoint),
    #[error("reserved provider input {0:?} disagrees with its durable quote binding")]
    ProviderInputBinding(OutPoint),
    #[error("unquoted output {0} assigns its blinding role to a provider input")]
    UnquotedProviderBlindedOutput(usize),
    #[error("the durable quote has no output assigned to provider blinding")]
    NoProviderBlindedOutputs,
    #[error("output {0} is already partially or fully blinded")]
    OutputAlreadyBlinded(usize),
    #[error("provider output {0} was not completely blinded")]
    IncompleteProviderOutput(usize),
    #[error("PSET non-last blinding failed: {0}")]
    PsetBlinding(String),
    #[error("provider-blinded PSET has {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { maximum: usize, actual: usize },
    #[error(
        "provider blinding changed a PSET field outside its permitted output proofs and scalar"
    )]
    UnexpectedMutation,
}

#[cfg(test)]
#[path = "blinding/tests.rs"]
mod tests;
