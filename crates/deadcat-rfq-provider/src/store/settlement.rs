//! Provider-side authorization of a complete Liquid settlement.
//!
//! This is the last fallible validation boundary before provider inventory is
//! durably committed and a wallet or HSM may sign it. It deliberately derives
//! its authority from the persisted firm quote, authoritative unspent
//! prevouts, and wallet-owned output recovery—not from client manifests.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::{Message, Secp256k1};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    AssetId, BlindAssetProofs as _, BlindValueProofs as _, BlockHash, LockTime, OutPoint,
    SchnorrSig, SchnorrSighashType, Sequence, Transaction, TxOut,
};
use thiserror::Error;

use super::{
    CommitOutcome, ProviderError, ReservationBook, SettlementContext, SettlementContextState,
};
use crate::model::{
    Clock, MAX_SETTLEMENT_BYTES, ProviderIdentity, QuoteCommitment, ReservationAccess,
    ReservationId, TransactionFee, WalletKeyLocator,
};
use crate::quote::{
    DestinationRecovery, FirmQuote, QuoteBlinderRole, QuoteInputId, QuoteOutputId, QuoteOutputRole,
    QuotedOutput,
};
use crate::wallet::{P2TR_SIGHASH_ALL_SIGNATURE_BYTES, ProviderOutputRecovery};

/// Default whole-transaction input bound, aligned with the client composer.
pub const DEFAULT_MAX_SETTLEMENT_INPUTS: usize = 32;
/// Default whole-transaction output bound, aligned with the client composer.
pub const DEFAULT_MAX_SETTLEMENT_OUTPUTS: usize = 32;

/// One chain-authoritative output that is unspent in the source's coherent
/// snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativePrevout {
    outpoint: OutPoint,
    txout: TxOut,
}

impl AuthoritativePrevout {
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: TxOut) -> Self {
        Self { outpoint, txout }
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.txout
    }
}

/// Trusted chain/mempool view used immediately before commitment.
///
/// Implementations must return one entry per requested outpoint, in request
/// order, including each complete consensus [`TxOut`] and its rangeproof
/// witness, and must fail if any output is missing or spent. The adapter should
/// minimize skew across the batch; a later outspend can still race this read
/// and make the transaction unrelayable, but cannot authorize a different
/// provider spend.
pub trait SettlementChainSource {
    type Error: Error + Send + Sync + 'static;

    /// Genesis hash of the Liquid chain backing this source.
    fn genesis_hash(&self) -> BlockHash;

    fn unspent_prevouts(
        &self,
        outpoints: &[OutPoint],
    ) -> Result<Vec<AuthoritativePrevout>, Self::Error>;
}

/// Global placement of one quote-local provider input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementInputPlacement {
    quote_input: QuoteInputId,
    transaction_index: usize,
}

impl SettlementInputPlacement {
    #[must_use]
    pub const fn new(quote_input: QuoteInputId, transaction_index: usize) -> Self {
        Self {
            quote_input,
            transaction_index,
        }
    }

    #[must_use]
    pub const fn quote_input(self) -> QuoteInputId {
        self.quote_input
    }

    #[must_use]
    pub const fn transaction_index(self) -> usize {
        self.transaction_index
    }
}

/// Global placement of one quote-local output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementOutputPlacement {
    quote_output: QuoteOutputId,
    transaction_index: usize,
}

impl SettlementOutputPlacement {
    #[must_use]
    pub const fn new(quote_output: QuoteOutputId, transaction_index: usize) -> Self {
        Self {
            quote_output,
            transaction_index,
        }
    }

    #[must_use]
    pub const fn quote_output(self) -> QuoteOutputId {
        self.quote_output
    }

    #[must_use]
    pub const fn transaction_index(self) -> usize {
        self.transaction_index
    }
}

/// Injective quote-local to whole-transaction placement supplied with a final
/// PSET.
///
/// The mapping is only a locator. Every referenced object is rechecked against
/// the durable quote, and no two quote roles may alias one transaction object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementLayout {
    taker_payment_input: usize,
    provider_inputs: Vec<SettlementInputPlacement>,
    quote_outputs: Vec<SettlementOutputPlacement>,
}

impl SettlementLayout {
    pub fn new(
        taker_payment_input: usize,
        mut provider_inputs: Vec<SettlementInputPlacement>,
        mut quote_outputs: Vec<SettlementOutputPlacement>,
    ) -> Result<Self, SettlementLayoutError> {
        if provider_inputs.is_empty() {
            return Err(SettlementLayoutError::NoProviderInputs);
        }
        if quote_outputs.is_empty() {
            return Err(SettlementLayoutError::NoQuoteOutputs);
        }
        provider_inputs.sort_by_key(|placement| placement.quote_input);
        quote_outputs.sort_by_key(|placement| placement.quote_output);
        if let Some(duplicate) = provider_inputs
            .windows(2)
            .find(|pair| pair[0].quote_input == pair[1].quote_input)
        {
            return Err(SettlementLayoutError::DuplicateQuoteInput(
                duplicate[0].quote_input,
            ));
        }
        if let Some(duplicate) = quote_outputs
            .windows(2)
            .find(|pair| pair[0].quote_output == pair[1].quote_output)
        {
            return Err(SettlementLayoutError::DuplicateQuoteOutput(
                duplicate[0].quote_output,
            ));
        }
        let mut input_indexes = BTreeSet::new();
        input_indexes.insert(taker_payment_input);
        for placement in &provider_inputs {
            if !input_indexes.insert(placement.transaction_index) {
                return Err(SettlementLayoutError::AliasedInput(
                    placement.transaction_index,
                ));
            }
        }
        let mut output_indexes = BTreeSet::new();
        for placement in &quote_outputs {
            if !output_indexes.insert(placement.transaction_index) {
                return Err(SettlementLayoutError::AliasedOutput(
                    placement.transaction_index,
                ));
            }
        }
        Ok(Self {
            taker_payment_input,
            provider_inputs,
            quote_outputs,
        })
    }

    #[must_use]
    pub const fn taker_payment_input(&self) -> usize {
        self.taker_payment_input
    }

    #[must_use]
    pub fn provider_inputs(&self) -> &[SettlementInputPlacement] {
        &self.provider_inputs
    }

    #[must_use]
    pub fn quote_outputs(&self) -> &[SettlementOutputPlacement] {
        &self.quote_outputs
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SettlementLayoutError {
    #[error("settlement layout has no provider inputs")]
    NoProviderInputs,
    #[error("settlement layout has no quote outputs")]
    NoQuoteOutputs,
    #[error("settlement layout repeats quote input {0:?}")]
    DuplicateQuoteInput(QuoteInputId),
    #[error("settlement layout repeats quote output {0:?}")]
    DuplicateQuoteOutput(QuoteOutputId),
    #[error("settlement layout aliases transaction input {0}")]
    AliasedInput(usize),
    #[error("settlement layout aliases transaction output {0}")]
    AliasedOutput(usize),
}

/// Bounded resource profile enforced before proof or signature verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SettlementValidationLimits {
    maximum_inputs: usize,
    maximum_outputs: usize,
}

impl SettlementValidationLimits {
    pub fn new(
        maximum_inputs: usize,
        maximum_outputs: usize,
    ) -> Result<Self, SettlementLimitsError> {
        if maximum_inputs == 0 {
            return Err(SettlementLimitsError::ZeroMaximumInputs);
        }
        if maximum_outputs == 0 {
            return Err(SettlementLimitsError::ZeroMaximumOutputs);
        }
        Ok(Self {
            maximum_inputs,
            maximum_outputs,
        })
    }

    #[must_use]
    pub const fn maximum_inputs(self) -> usize {
        self.maximum_inputs
    }

    #[must_use]
    pub const fn maximum_outputs(self) -> usize {
        self.maximum_outputs
    }
}

impl Default for SettlementValidationLimits {
    fn default() -> Self {
        Self {
            maximum_inputs: DEFAULT_MAX_SETTLEMENT_INPUTS,
            maximum_outputs: DEFAULT_MAX_SETTLEMENT_OUTPUTS,
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum SettlementLimitsError {
    #[error("maximum settlement input count must be nonzero")]
    ZeroMaximumInputs,
    #[error("maximum settlement output count must be nonzero")]
    ZeroMaximumOutputs,
}

/// Non-forgeable authorization to cross the durable provider signing point.
///
/// This type is intentionally not cloneable or serializable. Dropping it has
/// no effect; consuming it atomically rechecks the quote binding, deadline,
/// fee policy, and durable allocations before returning a signing job.
pub struct ValidatedSigningIntent {
    provider: ProviderIdentity,
    access: ReservationAccess,
    quote_commitment: QuoteCommitment,
    canonical_pset: Vec<u8>,
    fee: TransactionFee,
}

impl ValidatedSigningIntent {
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.access.reservation_id()
    }

    #[must_use]
    pub fn canonical_pset(&self) -> &[u8] {
        &self.canonical_pset
    }

    #[must_use]
    pub const fn fee(&self) -> TransactionFee {
        self.fee
    }

    pub fn commit<C: Clock>(
        self,
        book: &ReservationBook,
        clock: &C,
    ) -> Result<CommitOutcome, ProviderError> {
        book.commit_validated_before_sign(
            self.provider,
            self.access,
            self.quote_commitment,
            self.canonical_pset,
            self.fee,
            clock,
        )
    }
}

impl fmt::Debug for ValidatedSigningIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedSigningIntent")
            .field("provider", &self.provider)
            .field("reservation_id", &self.access.reservation_id())
            .field("quote_commitment", &self.quote_commitment)
            .field("canonical_pset_bytes", &self.canonical_pset.len())
            .field("fee", &self.fee)
            .finish()
    }
}

/// Complete provider-side final-PSET validator for the initial RFQ profile.
///
/// Every non-provider input must already be a finalized tree-less P2TR
/// key-path `SIGHASH_ALL` spend. This permits ordinary taker funding and
/// already-signed wallet contributions, but intentionally does not yet execute
/// Simplicity covenant witnesses or coordinate a second interactive RFQ
/// signer. Supporting those venues requires an authenticated script/venue
/// verifier rather than treating an arbitrary nonempty witness as valid.
pub struct ProviderSettlementValidator<'a, C, R> {
    book: &'a ReservationBook,
    chain: &'a C,
    output_recovery: &'a R,
    limits: SettlementValidationLimits,
}

impl<'a, C, R> ProviderSettlementValidator<'a, C, R>
where
    C: SettlementChainSource,
    R: ProviderOutputRecovery,
{
    #[must_use]
    pub fn new(book: &'a ReservationBook, chain: &'a C, output_recovery: &'a R) -> Self {
        Self {
            book,
            chain,
            output_recovery,
            limits: SettlementValidationLimits::default(),
        }
    }

    #[must_use]
    pub const fn with_limits(mut self, limits: SettlementValidationLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Validate and canonicalize one complete taker-signed PSET.
    ///
    /// Exact retries of a committed or signed payload are recognized from
    /// durable state before live chain/wallet calls, because those inputs may
    /// already have been spent by the exact settlement. Replay compares only
    /// the canonical payload; the supplied layout is not consulted because it
    /// cannot authorize a new signing intent after commitment.
    pub fn validate(
        &self,
        access: ReservationAccess,
        layout: &SettlementLayout,
        submitted_pset: &[u8],
    ) -> Result<ValidatedSigningIntent, SettlementValidationError> {
        let canonical_pset = canonical_pset(submitted_pset)?;
        let context = self.book.settlement_context(access)?;
        match &context.state {
            SettlementContextState::Committed(job) | SettlementContextState::Signed(job) => {
                if job.pre_sign_payload() != canonical_pset {
                    return Err(
                        ProviderError::DifferentSigningIntent(access.reservation_id()).into(),
                    );
                }
                return Ok(ValidatedSigningIntent {
                    provider: context.provider,
                    access,
                    quote_commitment: context.quote.commitment(),
                    canonical_pset,
                    fee: job.fee(),
                });
            }
            SettlementContextState::Reserved => {}
        }
        let pset = deserialize::<PartiallySignedTransaction>(&canonical_pset)
            .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;
        self.validate_reserved(&context, layout, canonical_pset, &pset)
    }

    fn validate_reserved(
        &self,
        context: &SettlementContext,
        layout: &SettlementLayout,
        canonical_pset: Vec<u8>,
        pset: &PartiallySignedTransaction,
    ) -> Result<ValidatedSigningIntent, SettlementValidationError> {
        validate_global(pset, self.limits)?;
        validate_layout(&context.quote, layout, pset)?;
        let chain_genesis = self.chain.genesis_hash();
        if chain_genesis != context.provider.genesis_hash() {
            return Err(SettlementValidationError::WrongChain {
                expected: context.provider.genesis_hash(),
                actual: chain_genesis,
            });
        }

        let outpoints = pset.inputs().iter().map(input_outpoint).collect::<Vec<_>>();
        let authoritative = self
            .chain
            .unspent_prevouts(&outpoints)
            .map_err(|error| SettlementValidationError::ChainSource(Box::new(error)))?;
        if authoritative.len() != outpoints.len() {
            return Err(SettlementValidationError::AuthoritativePrevoutCount {
                expected: outpoints.len(),
                actual: authoritative.len(),
            });
        }
        for (index, (expected, actual)) in outpoints.iter().zip(&authoritative).enumerate() {
            if actual.outpoint() != *expected {
                return Err(SettlementValidationError::AuthoritativePrevoutMismatch(
                    index,
                ));
            }
        }
        let prevouts = authoritative
            .iter()
            .map(|prevout| prevout.txout.clone())
            .collect::<Vec<_>>();
        let transaction = pset
            .extract_tx()
            .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;

        let provider_by_id = layout
            .provider_inputs
            .iter()
            .map(|placement| (placement.quote_input, placement.transaction_index))
            .collect::<BTreeMap<_, _>>();
        let provider_indexes = provider_by_id.values().copied().collect::<BTreeSet<_>>();
        let targets_by_outpoint = context
            .provider_targets
            .iter()
            .map(|target| (target.outpoint(), *target))
            .collect::<BTreeMap<_, _>>();

        for (index, input) in pset.inputs().iter().enumerate() {
            validate_common_input(input, &authoritative[index], index)?;
            if provider_indexes.contains(&index) {
                let quoted = context
                    .quote
                    .contribution()
                    .inputs()
                    .iter()
                    .find(|quoted| provider_by_id.get(&quoted.id()) == Some(&index))
                    .ok_or(SettlementValidationError::InvalidProviderInput {
                        index,
                        reason: "layout does not resolve to a quoted input",
                    })?;
                let target = targets_by_outpoint.get(&quoted.outpoint()).ok_or(
                    SettlementValidationError::InvalidProviderInput {
                        index,
                        reason: "durable signing target is missing",
                    },
                )?;
                if quoted.inventory_binding() != target.inventory_binding() {
                    return Err(SettlementValidationError::InvalidProviderInput {
                        index,
                        reason: "quoted inventory binding disagrees with durable signing target",
                    });
                }
                validate_provider_input(
                    input,
                    &authoritative[index],
                    quoted.witness_utxo(),
                    *target,
                    index,
                )?;
            } else {
                validate_taker_input(
                    input,
                    &transaction,
                    &prevouts,
                    context.provider.genesis_hash(),
                    index,
                )?;
            }
        }

        let fee_amount =
            validate_outputs(pset, &transaction, context, layout, self.output_recovery)?;
        transaction
            .verify_tx_amt_proofs(&Secp256k1::new(), &prevouts)
            .map_err(|error| SettlementValidationError::ConfidentialProofs(error.to_string()))?;

        let mut projected = transaction;
        for index in provider_indexes {
            projected.input[index].witness.script_witness =
                vec![vec![0_u8; P2TR_SIGHASH_ALL_SIGNATURE_BYTES]];
        }
        let fee = TransactionFee::new(
            context.provider.policy_asset(),
            fee_amount,
            u64::try_from(projected.weight())
                .map_err(|_| SettlementValidationError::TransactionSizeOverflow)?,
            u64::try_from(projected.vsize())
                .map_err(|_| SettlementValidationError::TransactionSizeOverflow)?,
            u64::try_from(projected.discount_vsize())
                .map_err(|_| SettlementValidationError::TransactionSizeOverflow)?,
        )
        .map_err(|error| SettlementValidationError::InvalidFeeFacts(error.to_string()))?;
        context.quote.fee_policy().validate(fee)?;

        Ok(ValidatedSigningIntent {
            provider: context.provider,
            access: context.access,
            quote_commitment: context.quote.commitment(),
            canonical_pset,
            fee,
        })
    }
}

fn canonical_pset(bytes: &[u8]) -> Result<Vec<u8>, SettlementValidationError> {
    if bytes.is_empty() {
        return Err(SettlementValidationError::EmptyPayload);
    }
    if bytes.len() > MAX_SETTLEMENT_BYTES {
        return Err(SettlementValidationError::PayloadTooLarge {
            maximum: MAX_SETTLEMENT_BYTES,
            actual: bytes.len(),
        });
    }
    let pset = deserialize::<PartiallySignedTransaction>(bytes)
        .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;
    pset.sanity_check()
        .map_err(|error| SettlementValidationError::InvalidPset(error.to_string()))?;
    let canonical = serialize(&pset);
    if canonical != bytes {
        return Err(SettlementValidationError::NonCanonicalPset);
    }
    Ok(canonical)
}

fn validate_global(
    pset: &PartiallySignedTransaction,
    limits: SettlementValidationLimits,
) -> Result<(), SettlementValidationError> {
    if pset.inputs().is_empty() || pset.inputs().len() > limits.maximum_inputs {
        return Err(SettlementValidationError::InputCount {
            maximum: limits.maximum_inputs,
            actual: pset.inputs().len(),
        });
    }
    if pset.outputs().is_empty() || pset.outputs().len() > limits.maximum_outputs {
        return Err(SettlementValidationError::OutputCount {
            maximum: limits.maximum_outputs,
            actual: pset.outputs().len(),
        });
    }
    if pset.global.version != 2 || pset.global.tx_data.version != 2 {
        return Err(SettlementValidationError::InvalidGlobal(
            "PSET and transaction versions must both be 2",
        ));
    }
    if !pset.global.xpub.is_empty()
        || !pset.global.scalars.is_empty()
        || !pset.global.proprietary.is_empty()
        || !pset.global.unknown.is_empty()
    {
        return Err(SettlementValidationError::InvalidGlobal(
            "unexpected global wallet, blinding, proprietary, or unknown metadata",
        ));
    }
    if pset.global.tx_data.tx_modifiable.unwrap_or(0) != 0
        || pset.global.elements_tx_modifiable_flag.unwrap_or(0) != 0
    {
        return Err(SettlementValidationError::InvalidGlobal(
            "transaction remains modifiable",
        ));
    }
    if pset
        .global
        .tx_data
        .fallback_locktime
        .is_some_and(|locktime| locktime != LockTime::ZERO)
    {
        return Err(SettlementValidationError::InvalidGlobal(
            "nonzero locktime is unsupported",
        ));
    }
    let mut outpoints = BTreeSet::new();
    for (index, input) in pset.inputs().iter().enumerate() {
        let outpoint = input_outpoint(input);
        if outpoint.is_null() || input.previous_output_index & 0xc000_0000 != 0 {
            return Err(SettlementValidationError::InvalidInput {
                index,
                reason: "null, issuance, or pegin outpoint",
            });
        }
        if !outpoints.insert(outpoint) {
            return Err(SettlementValidationError::DuplicateInput(outpoint));
        }
    }
    Ok(())
}

fn validate_layout(
    quote: &FirmQuote,
    layout: &SettlementLayout,
    pset: &PartiallySignedTransaction,
) -> Result<(), SettlementValidationError> {
    if layout.taker_payment_input >= pset.inputs().len() {
        return Err(SettlementValidationError::LayoutIndexOutOfRange);
    }
    let expected_inputs = quote
        .contribution()
        .inputs()
        .iter()
        .map(|input| input.id())
        .collect::<BTreeSet<_>>();
    let actual_inputs = layout
        .provider_inputs
        .iter()
        .map(|placement| placement.quote_input)
        .collect::<BTreeSet<_>>();
    if expected_inputs != actual_inputs
        || layout
            .provider_inputs
            .iter()
            .any(|placement| placement.transaction_index >= pset.inputs().len())
    {
        return Err(SettlementValidationError::LayoutInputMismatch);
    }
    let expected_outputs = quote
        .contribution()
        .outputs()
        .iter()
        .map(|output| output.id())
        .collect::<BTreeSet<_>>();
    let actual_outputs = layout
        .quote_outputs
        .iter()
        .map(|placement| placement.quote_output)
        .collect::<BTreeSet<_>>();
    if expected_outputs != actual_outputs
        || layout
            .quote_outputs
            .iter()
            .any(|placement| placement.transaction_index >= pset.outputs().len())
    {
        return Err(SettlementValidationError::LayoutOutputMismatch);
    }
    for placement in &layout.provider_inputs {
        let quoted = quote
            .contribution()
            .inputs()
            .iter()
            .find(|input| input.id() == placement.quote_input)
            .ok_or(SettlementValidationError::LayoutInputMismatch)?;
        if input_outpoint(&pset.inputs()[placement.transaction_index]) != quoted.outpoint() {
            return Err(SettlementValidationError::LayoutInputMismatch);
        }
    }
    Ok(())
}

fn validate_common_input(
    input: &PsetInput,
    authoritative: &AuthoritativePrevout,
    index: usize,
) -> Result<(), SettlementValidationError> {
    let Some(witness_utxo) = input.witness_utxo.as_ref() else {
        return Err(SettlementValidationError::InvalidInput {
            index,
            reason: "missing witness UTXO",
        });
    };
    if !same_prevout_body(witness_utxo, authoritative.txout())
        || input.in_utxo_rangeproof != authoritative.txout().witness.rangeproof
    {
        return Err(SettlementValidationError::InvalidInput {
            index,
            reason: "PSET witness UTXO disagrees with authoritative prevout",
        });
    }
    if input.non_witness_utxo.is_some()
        || !input.partial_sigs.is_empty()
        || !input.bip32_derivation.is_empty()
        || !input.ripemd160_preimages.is_empty()
        || !input.sha256_preimages.is_empty()
        || !input.hash160_preimages.is_empty()
        || !input.hash256_preimages.is_empty()
        || input.redeem_script.is_some()
        || input.witness_script.is_some()
        || input.final_script_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || !input.tap_scripts.is_empty()
        || !input.tap_key_origins.is_empty()
        || input.tap_merkle_root.is_some()
        || input.amount.is_some()
        || input.blind_value_proof.is_some()
        || input.asset.is_some()
        || input.blind_asset_proof.is_some()
        || !input.proprietary.is_empty()
        || !input.unknown.is_empty()
    {
        return Err(SettlementValidationError::InvalidInput {
            index,
            reason: "unsupported signing or wallet metadata",
        });
    }
    if input
        .sequence
        .is_some_and(|sequence| sequence != Sequence::MAX)
        || input.required_time_locktime.is_some()
        || input.required_height_locktime.is_some()
    {
        return Err(SettlementValidationError::InvalidInput {
            index,
            reason: "non-final sequence or input locktime requirement",
        });
    }
    if has_issuance_or_pegin_metadata(input) {
        return Err(SettlementValidationError::InvalidInput {
            index,
            reason: "issuance or pegin metadata is unsupported",
        });
    }
    Ok(())
}

fn validate_provider_input(
    input: &PsetInput,
    authoritative: &AuthoritativePrevout,
    quoted_prevout: &TxOut,
    target: crate::model::SigningTarget,
    index: usize,
) -> Result<(), SettlementValidationError> {
    if authoritative.txout() != quoted_prevout || authoritative.outpoint() != target.outpoint() {
        return Err(SettlementValidationError::InvalidProviderInput {
            index,
            reason: "authoritative prevout disagrees with durable quote",
        });
    }
    if authoritative.txout().script_pubkey
        != elements::Script::new_v1_p2tr(&Secp256k1::new(), target.internal_key(), None)
        || input.tap_internal_key != Some(target.internal_key())
        || input.sighash_type != Some(SchnorrSighashType::All.into())
        || input.tap_key_sig.is_some()
        || input.final_script_witness.is_some()
    {
        return Err(SettlementValidationError::InvalidProviderInput {
            index,
            reason: "provider input is not unsigned tree-less P2TR SIGHASH_ALL",
        });
    }
    Ok(())
}

fn validate_taker_input(
    input: &PsetInput,
    transaction: &Transaction,
    prevouts: &[TxOut],
    genesis_hash: elements::BlockHash,
    index: usize,
) -> Result<(), SettlementValidationError> {
    let prevout = &prevouts[index];
    let internal_key =
        input
            .tap_internal_key
            .ok_or(SettlementValidationError::InvalidTakerInput {
                index,
                reason: "missing Taproot internal key",
            })?;
    if prevout.script_pubkey != elements::Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None)
        || input.sighash_type != Some(SchnorrSighashType::All.into())
    {
        return Err(SettlementValidationError::InvalidTakerInput {
            index,
            reason: "input is not tree-less P2TR with explicit SIGHASH_ALL",
        });
    }
    let signature = input
        .tap_key_sig
        .ok_or(SettlementValidationError::InvalidTakerInput {
            index,
            reason: "missing finalized Taproot signature",
        })?;
    if signature.hash_ty != SchnorrSighashType::All
        || input.final_script_witness.as_ref() != Some(&vec![signature.to_vec()])
    {
        return Err(SettlementValidationError::InvalidTakerInput {
            index,
            reason: "final witness is not the exact explicit-ALL key-path signature",
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
}

fn verify_taproot_signature(
    transaction: &Transaction,
    prevouts: &[TxOut],
    index: usize,
    signature: SchnorrSig,
    internal_key: elements::secp256k1_zkp::XOnlyPublicKey,
    genesis_hash: elements::BlockHash,
) -> Result<(), SettlementValidationError> {
    let sighash = SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            index,
            &Prevouts::All(prevouts),
            SchnorrSighashType::All,
            genesis_hash,
        )
        .map_err(|error| SettlementValidationError::InvalidSignature {
            index,
            detail: error.to_string(),
        })?;
    let message = Message::from_digest(sighash.to_byte_array());
    let (output_key, _) = internal_key.tap_tweak(&Secp256k1::new(), None);
    Secp256k1::new()
        .verify_schnorr(&signature.sig, &message, output_key.as_inner())
        .map_err(|error| SettlementValidationError::InvalidSignature {
            index,
            detail: error.to_string(),
        })
}

fn validate_outputs<R: ProviderOutputRecovery>(
    pset: &PartiallySignedTransaction,
    transaction: &Transaction,
    context: &SettlementContext,
    layout: &SettlementLayout,
    output_recovery: &R,
) -> Result<u64, SettlementValidationError> {
    let mut fee = None;
    for (index, output) in pset.outputs().iter().enumerate() {
        if output.script_pubkey.is_empty() {
            if fee.is_some() {
                return Err(SettlementValidationError::InvalidFeeOutput(
                    "multiple fee outputs",
                ));
            }
            fee = Some(validate_fee_output(
                output,
                context.provider.policy_asset(),
            )?);
        } else {
            validate_confidential_output(output, index, pset.inputs().len())?;
        }
    }
    let fee = fee.ok_or(SettlementValidationError::InvalidFeeOutput(
        "missing fee output",
    ))?;

    for placement in &layout.quote_outputs {
        let quoted = context
            .quote
            .contribution()
            .outputs()
            .iter()
            .find(|output| output.id() == placement.quote_output)
            .ok_or(SettlementValidationError::LayoutOutputMismatch)?;
        let output = &pset.outputs()[placement.transaction_index];
        validate_quoted_output(output, quoted, layout, placement.transaction_index)?;
        match quoted.role() {
            QuoteOutputRole::ProviderPayment => validate_provider_recovery(
                output_recovery,
                context.provider_receive_recovery,
                &transaction.output[placement.transaction_index],
                quoted,
            )?,
            QuoteOutputRole::ProviderChange => {
                let recovery = context.provider_change_recovery.ok_or(
                    SettlementValidationError::InvalidQuotedOutput {
                        index: placement.transaction_index,
                        reason: "provider change recovery metadata is missing",
                    },
                )?;
                validate_provider_recovery(
                    output_recovery,
                    recovery,
                    &transaction.output[placement.transaction_index],
                    quoted,
                )?;
            }
            QuoteOutputRole::TakerReceive => {}
        }
    }
    Ok(fee)
}

fn validate_fee_output(
    output: &PsetOutput,
    policy_asset: AssetId,
) -> Result<u64, SettlementValidationError> {
    let amount = output
        .amount
        .ok_or(SettlementValidationError::InvalidFeeOutput(
            "fee amount is missing",
        ))?;
    if amount == 0
        || output.asset != Some(policy_asset)
        || output.asset_comm.is_some()
        || output.amount_comm.is_some()
        || output.blinding_key.is_some()
        || output.ecdh_pubkey.is_some()
        || output.blinder_index.is_some()
        || output.value_rangeproof.is_some()
        || output.asset_surjection_proof.is_some()
        || output.blind_value_proof.is_some()
        || output.blind_asset_proof.is_some()
        || has_output_wallet_metadata(output)
    {
        return Err(SettlementValidationError::InvalidFeeOutput(
            "fee output is not one exact explicit policy-asset fee",
        ));
    }
    Ok(amount)
}

fn validate_confidential_output(
    output: &PsetOutput,
    index: usize,
    input_count: usize,
) -> Result<(), SettlementValidationError> {
    if output.script_pubkey.is_provably_unspendable()
        || output.blinding_key.is_none()
        || output.ecdh_pubkey.is_none()
        || output.asset.is_none()
        || output.amount.is_none()
        || output.asset_comm.is_none()
        || output.amount_comm.is_none()
        || output.value_rangeproof.is_none()
        || output.asset_surjection_proof.is_none()
        || output.blind_asset_proof.is_none()
        || output.blind_value_proof.is_none()
        || output
            .blinder_index
            .is_none_or(|blinder| usize::try_from(blinder).map_or(true, |i| i >= input_count))
        || has_output_wallet_metadata(output)
    {
        return Err(SettlementValidationError::InvalidOutput {
            index,
            reason: "ordinary output is not a fully disclosed confidential output",
        });
    }
    let asset = output.asset.expect("presence checked");
    let amount = output.amount.expect("presence checked");
    let asset_commitment = output.asset_comm.expect("presence checked");
    let value_commitment = output.amount_comm.expect("presence checked");
    if !output
        .blind_asset_proof
        .as_deref()
        .expect("presence checked")
        .blind_asset_proof_verify(&Secp256k1::new(), asset, asset_commitment)
        || !output
            .blind_value_proof
            .as_deref()
            .expect("presence checked")
            .blind_value_proof_verify(
                &Secp256k1::new(),
                amount,
                asset_commitment,
                value_commitment,
            )
    {
        return Err(SettlementValidationError::InvalidOutput {
            index,
            reason: "disclosed asset or amount does not match its commitment",
        });
    }
    Ok(())
}

fn validate_quoted_output(
    output: &PsetOutput,
    quoted: &QuotedOutput,
    layout: &SettlementLayout,
    index: usize,
) -> Result<(), SettlementValidationError> {
    let expected_blinder = match quoted.blinder() {
        QuoteBlinderRole::TakerPaymentInput => layout.taker_payment_input,
        QuoteBlinderRole::ProviderInput(id) => layout
            .provider_inputs
            .iter()
            .find(|placement| placement.quote_input == id)
            .map(|placement| placement.transaction_index)
            .ok_or(SettlementValidationError::LayoutInputMismatch)?,
    };
    let expected_blinder = u32::try_from(expected_blinder)
        .map_err(|_| SettlementValidationError::LayoutIndexOutOfRange)?;
    if output.script_pubkey != *quoted.destination().script_pubkey()
        || output.blinding_key
            != Some(BitcoinPublicKey::new(
                quoted.destination().blinding_public_key(),
            ))
        || output.asset != Some(quoted.asset())
        || output.amount != Some(quoted.amount())
        || output.blinder_index != Some(expected_blinder)
    {
        return Err(SettlementValidationError::InvalidQuotedOutput {
            index,
            reason: "output disagrees with durable quote economics, destination, or blinder role",
        });
    }
    Ok(())
}

fn validate_provider_recovery<R: ProviderOutputRecovery>(
    output_recovery: &R,
    recovery: DestinationRecovery,
    txout: &TxOut,
    quoted: &QuotedOutput,
) -> Result<(), SettlementValidationError> {
    let locator = WalletKeyLocator::new(recovery.wallet_locator)
        .map_err(|error| SettlementValidationError::InvalidRecoveryMetadata(error.to_string()))?;
    output_recovery
        .validate_confidential_output(
            locator,
            elements::secp256k1_zkp::XOnlyPublicKey::from_slice(&recovery.internal_key).map_err(
                |error| SettlementValidationError::InvalidRecoveryMetadata(error.to_string()),
            )?,
            txout,
            quoted.asset(),
            quoted.amount(),
        )
        .map_err(|error| SettlementValidationError::OutputRecovery {
            role: quoted.role(),
            source: Box::new(error),
        })
}

fn has_output_wallet_metadata(output: &PsetOutput) -> bool {
    output.redeem_script.is_some()
        || output.witness_script.is_some()
        || !output.bip32_derivation.is_empty()
        || output.tap_internal_key.is_some()
        || output.tap_tree.is_some()
        || !output.tap_key_origins.is_empty()
        || !output.proprietary.is_empty()
        || !output.unknown.is_empty()
}

fn has_issuance_or_pegin_metadata(input: &PsetInput) -> bool {
    input.issuance_value_amount.is_some()
        || input.issuance_value_comm.is_some()
        || input.issuance_inflation_keys.is_some()
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_value_rangeproof.is_some()
        || input.issuance_keys_rangeproof.is_some()
        || input.issuance_blinding_nonce.is_some()
        || input.issuance_asset_entropy.is_some()
        || input.in_issuance_blind_value_proof.is_some()
        || input.in_issuance_blind_inflation_keys_proof.is_some()
        || input.blinded_issuance.is_some()
        || input.pegin_tx.is_some()
        || input.pegin_txout_proof.is_some()
        || input.pegin_genesis_hash.is_some()
        || input.pegin_claim_script.is_some()
        || input.pegin_value.is_some()
        || input.pegin_witness.is_some()
}

fn input_outpoint(input: &PsetInput) -> OutPoint {
    OutPoint::new(input.previous_txid, input.previous_output_index)
}

fn same_prevout_body(actual: &TxOut, expected: &TxOut) -> bool {
    actual.asset == expected.asset
        && actual.value == expected.value
        && actual.nonce == expected.nonce
        && actual.script_pubkey == expected.script_pubkey
}

#[derive(Debug, Error)]
pub enum SettlementValidationError {
    #[error("settlement payload must not be empty")]
    EmptyPayload,
    #[error("settlement payload has {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { maximum: usize, actual: usize },
    #[error("invalid PSET: {0}")]
    InvalidPset(String),
    #[error("PSET is not in the canonical encoding committed by the provider")]
    NonCanonicalPset,
    #[error("provider state rejected settlement validation: {0}")]
    Provider(#[from] ProviderError),
    #[error("settlement has {actual} inputs; accepted range is 1..={maximum}")]
    InputCount { maximum: usize, actual: usize },
    #[error("settlement has {actual} outputs; accepted range is 1..={maximum}")]
    OutputCount { maximum: usize, actual: usize },
    #[error("invalid global settlement policy: {0}")]
    InvalidGlobal(&'static str),
    #[error("duplicate settlement input {0:?}")]
    DuplicateInput(OutPoint),
    #[error("settlement layout contains an out-of-range index")]
    LayoutIndexOutOfRange,
    #[error("settlement provider-input layout does not match the durable quote")]
    LayoutInputMismatch,
    #[error("settlement output layout does not match the durable quote")]
    LayoutOutputMismatch,
    #[error("authoritative chain source failed: {0}")]
    ChainSource(#[source] Box<dyn Error + Send + Sync>),
    #[error("chain source returned {actual} prevouts; expected {expected}")]
    AuthoritativePrevoutCount { expected: usize, actual: usize },
    #[error("chain source returned the wrong outpoint at input {0}")]
    AuthoritativePrevoutMismatch(usize),
    #[error("chain source is on {actual}, expected provider chain {expected}")]
    WrongChain {
        expected: BlockHash,
        actual: BlockHash,
    },
    #[error("invalid input {index}: {reason}")]
    InvalidInput { index: usize, reason: &'static str },
    #[error("invalid provider input {index}: {reason}")]
    InvalidProviderInput { index: usize, reason: &'static str },
    #[error("invalid taker input {index}: {reason}")]
    InvalidTakerInput { index: usize, reason: &'static str },
    #[error("invalid signature at input {index}: {detail}")]
    InvalidSignature { index: usize, detail: String },
    #[error("invalid output {index}: {reason}")]
    InvalidOutput { index: usize, reason: &'static str },
    #[error("invalid quoted output {index}: {reason}")]
    InvalidQuotedOutput { index: usize, reason: &'static str },
    #[error("invalid fee output: {0}")]
    InvalidFeeOutput(&'static str),
    #[error("provider cannot recover {role:?} output: {source}")]
    OutputRecovery {
        role: QuoteOutputRole,
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    #[error("invalid provider output recovery metadata: {0}")]
    InvalidRecoveryMetadata(String),
    #[error("confidential transaction proof or balance verification failed: {0}")]
    ConfidentialProofs(String),
    #[error("transaction size does not fit the provider fee model")]
    TransactionSizeOverflow,
    #[error("invalid derived fee facts: {0}")]
    InvalidFeeFacts(String),
    #[error("fee policy rejected the final transaction: {0}")]
    FeePolicy(#[from] crate::model::FeePolicyViolation),
}

#[cfg(test)]
mod tests;
