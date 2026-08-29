//! Keyless taker authorization for one collaboratively blinded RFQ settlement.
//!
//! The authorization flow in this module owns no wallet secrets. It freezes the
//! exact locally composed route before provider blinding, obtains one coherent
//! and authoritative current-state snapshot, and gives a caller-owned wallet a
//! narrowly scoped job. The wallet may only complete the remaining blinding
//! turn and sign the wallet inputs; the authorization boundary independently
//! validates the complete result before it becomes an executable settlement.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use async_trait::async_trait;
use deadcat_client::composition::{CompositionLayout, UnblindedStructureManifest};
use deadcat_client::venue::{ComposedRoute, RouteAuthorization};
use deadcat_liquid_settlement::{
    CanonicalPset, CanonicalPsetError, verify_confidential_proofs_and_balance,
    verify_output_disclosure, verify_treeless_p2tr_explicit_all,
};
use deadcat_rfq_rpc::{
    BlinderRoleDto, FeeSizeMetricDto, FirmQuoteValidationError, MAX_SETTLEMENT_BYTES,
    MAX_SETTLEMENT_INPUTS, MAX_SETTLEMENT_OUTPUTS, QuoteOutputRoleDto, SettlementLayoutDto,
    SettlementPset, VerifiedFirmQuote,
};
use deadcat_types::{ChainAnchor, ChainIdentity, ContractId};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode::serialize;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use elements::{AssetId, LockTime, OutPoint, SchnorrSighashType, Script, Sequence, TxOut};
use thiserror::Error;

use crate::{
    ExecutionBinding, ProviderBlindedPset, RfqLegBinding, RfqVenueError, TakerAuthorizedSettlement,
    TradingMarket,
};

/// One authoritative, unspent input prevout returned in transaction order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthoritativeTakerPrevout {
    outpoint: OutPoint,
    txout: TxOut,
}

impl AuthoritativeTakerPrevout {
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

/// Coherent current state used for one authorization decision.
///
/// `market`, `observed_at_millis`, and `prevouts` must come from one logical
/// snapshot. The source must fail rather than return this value unless every
/// requested prevout is currently unspent and the quote's snapshot anchor is
/// still in the canonical ancestry of `market.observed_at()`.
#[derive(Clone, Debug)]
pub struct TakerSettlementSnapshot {
    observed_at_millis: u64,
    market: TradingMarket,
    prevouts: Vec<AuthoritativeTakerPrevout>,
}

impl TakerSettlementSnapshot {
    #[must_use]
    pub const fn new(
        observed_at_millis: u64,
        market: TradingMarket,
        prevouts: Vec<AuthoritativeTakerPrevout>,
    ) -> Self {
        Self {
            observed_at_millis,
            market,
            prevouts,
        }
    }

    #[must_use]
    pub const fn observed_at_millis(&self) -> u64 {
        self.observed_at_millis
    }

    #[must_use]
    pub const fn market(&self) -> &TradingMarket {
        &self.market
    }

    #[must_use]
    pub fn prevouts(&self) -> &[AuthoritativeTakerPrevout] {
        &self.prevouts
    }
}

/// Exact owned query derived by local provider-response preflight.
///
/// The request is created only after the authenticated provider PSET has passed
/// binding, layout, canonical encoding, mutation-scope, disclosure, and fee
/// checks. Owning the ordered outpoints lets a blocking Core adapter move the
/// complete bounded operation onto an explicit blocking-task boundary.
pub struct TakerSettlementSnapshotRequest {
    chain: ChainIdentity,
    market: ContractId,
    quote_anchor: ChainAnchor,
    outpoints: Vec<OutPoint>,
}

impl TakerSettlementSnapshotRequest {
    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn market(&self) -> ContractId {
        self.market
    }

    #[must_use]
    pub const fn quote_anchor(&self) -> ChainAnchor {
        self.quote_anchor
    }

    #[must_use]
    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }
}

/// Asynchronous authoritative chain, market, and clock boundary for taker
/// authorization.
#[async_trait]
pub trait TakerSettlementSource: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    /// Return one coherent snapshot for the exact ordered outpoint list.
    ///
    /// The source must authenticate `chain`, re-materialize `market`, verify
    /// that `quote_anchor` remains in its canonical ancestry, and reject any
    /// missing or spent outpoint. Returned prevouts must preserve request order
    /// and include complete rangeproof witnesses.
    async fn settlement_snapshot(
        &self,
        request: TakerSettlementSnapshotRequest,
    ) -> Result<TakerSettlementSnapshot, Self::Error>;
}

/// Why the authorization boundary expects the caller wallet to own an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnedOutputKind {
    WalletContribution,
    RfqReceive,
}

/// Exact cleartext opening expected for one caller-owned output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedOutputExpectation {
    index: usize,
    kind: OwnedOutputKind,
    asset: AssetId,
    amount: u64,
    script_pubkey: Script,
}

impl OwnedOutputExpectation {
    #[must_use]
    pub const fn index(&self) -> usize {
        self.index
    }

    #[must_use]
    pub const fn kind(&self) -> OwnedOutputKind {
        self.kind
    }

    #[must_use]
    pub const fn asset(&self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }
}

/// Wallet-facing output-opening validation request.
#[derive(Clone, Copy, Debug)]
pub struct OwnedOutputValidation<'a> {
    expectation: &'a OwnedOutputExpectation,
    txout: &'a TxOut,
}

impl<'a> OwnedOutputValidation<'a> {
    #[must_use]
    pub const fn expectation(&self) -> &'a OwnedOutputExpectation {
        self.expectation
    }

    #[must_use]
    pub const fn txout(&self) -> &'a TxOut {
        self.txout
    }
}

/// Non-forgeable wallet job issued only after provider-delta and current-state
/// validation succeeds.
///
/// This type deliberately has no public constructor and is not cloneable. A
/// wallet backend may consume it to perform only the single balancing
/// `blind_last` turn. Signing is a separate capability issued after validation.
pub struct TakerWalletBlindingJob {
    pset: PartiallySignedTransaction,
    chain: ChainIdentity,
    route: RouteAuthorization,
    layout: CompositionLayout,
    prevouts: Vec<AuthoritativeTakerPrevout>,
    wallet_input_indices: Vec<usize>,
    wallet_output_indices: Vec<usize>,
    provider_input_indices: Vec<usize>,
    owned_outputs: Vec<OwnedOutputExpectation>,
}

impl TakerWalletBlindingJob {
    #[must_use]
    pub const fn pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn route(&self) -> &RouteAuthorization {
        &self.route
    }

    #[must_use]
    pub const fn layout(&self) -> &CompositionLayout {
        &self.layout
    }

    #[must_use]
    pub fn prevouts(&self) -> &[AuthoritativeTakerPrevout] {
        &self.prevouts
    }

    #[must_use]
    pub fn wallet_input_indices(&self) -> &[usize] {
        &self.wallet_input_indices
    }

    #[must_use]
    pub fn wallet_output_indices(&self) -> &[usize] {
        &self.wallet_output_indices
    }

    #[must_use]
    pub fn provider_input_indices(&self) -> &[usize] {
        &self.provider_input_indices
    }

    #[must_use]
    pub fn owned_outputs(&self) -> &[OwnedOutputExpectation] {
        &self.owned_outputs
    }

    #[must_use]
    pub fn into_pset(self) -> PartiallySignedTransaction {
        self.pset
    }
}

/// Non-forgeable signing job issued only after balancing blinding, complete
/// proof/balance verification, output recovery, and fee policy validation.
pub struct TakerWalletSigningJob {
    pset: PartiallySignedTransaction,
    chain: ChainIdentity,
    prevouts: Vec<AuthoritativeTakerPrevout>,
    wallet_input_indices: Vec<usize>,
}

impl TakerWalletSigningJob {
    #[must_use]
    pub const fn pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub fn prevouts(&self) -> &[AuthoritativeTakerPrevout] {
        &self.prevouts
    }

    #[must_use]
    pub fn wallet_input_indices(&self) -> &[usize] {
        &self.wallet_input_indices
    }

    #[must_use]
    pub fn into_pset(self) -> PartiallySignedTransaction {
        self.pset
    }
}

/// Caller-owned wallet capability used only after all pre-sign checks pass.
pub trait TakerWalletFinalizer {
    type Error: Error + Send + Sync + 'static;

    /// Complete only the balancing blinding turn. The returned PSET remains
    /// unsigned and is revalidated before any signing job can be produced.
    fn blind_last(
        &self,
        job: TakerWalletBlindingJob,
    ) -> Result<PartiallySignedTransaction, Self::Error>;

    /// Sign every wallet input after the coordinator has authorized the fully
    /// blinded transaction and fee policy.
    fn sign(&self, job: TakerWalletSigningJob) -> Result<PartiallySignedTransaction, Self::Error>;

    /// Prove that the wallet can recover the exact confidential opening.
    fn validate_owned_output(&self, output: OwnedOutputValidation<'_>) -> Result<(), Self::Error>;
}

/// Immutable authorization plan derived from one exact locally composed route.
#[derive(Clone, Debug)]
pub struct TakerSettlementPlan {
    binding: ExecutionBinding,
    settlement_layout: SettlementLayoutDto,
    original: CanonicalPset,
    manifest: UnblindedStructureManifest,
    route: RouteAuthorization,
    composition_layout: CompositionLayout,
    quote: VerifiedFirmQuote,
    market: TradingMarket,
    wallet_inputs: BTreeSet<usize>,
    provider_inputs: BTreeSet<usize>,
    wallet_outputs: BTreeSet<usize>,
    provider_outputs: BTreeSet<usize>,
    owned_outputs: Vec<OwnedOutputExpectation>,
}

impl TakerSettlementPlan {
    /// Freeze the exact production launch profile: one authenticated RFQ leg
    /// plus ordinary wallet-owned tree-less P2TR explicit-ALL inputs.
    pub fn new(
        route: &ComposedRoute,
        rfq: &RfqLegBinding,
    ) -> Result<Self, TakerSettlementPlanError> {
        let settlement = rfq.resolve(route)?;
        Self::build(
            route,
            ExecutionBinding::from_settlement(&settlement),
            settlement.layout().clone(),
            rfq.verified_quote().clone(),
            rfq.market(),
            rfq.leg_id(),
        )
    }

    fn build(
        route: &ComposedRoute,
        binding: ExecutionBinding,
        settlement_layout: SettlementLayoutDto,
        quote: VerifiedFirmQuote,
        market: &TradingMarket,
        rfq_leg_id: deadcat_client::venue::LegId,
    ) -> Result<Self, TakerSettlementPlanError> {
        if route.authorization().legs().len() != 1
            || route.authorization().legs()[0].id() != rfq_leg_id
        {
            return Err(TakerSettlementPlanError::LaunchProfile(
                "exactly one RFQ leg is required",
            ));
        }

        let quote_value = quote.quote();
        quote_value.validate_structure()?;
        settlement_layout.validate_for_quote(quote_value)?;
        validate_binding(&binding, &quote)?;
        if market.chain() != binding.chain()
            || market.policy_asset() != binding.policy_asset()
            || market.contract_id() != quote_value.request.context.market
            || !market.supports_pair(
                quote_value.execution.input.asset,
                quote_value.execution.output.asset,
            )
        {
            return Err(TakerSettlementPlanError::MarketMismatch);
        }

        let transaction = route.transaction();
        transaction
            .manifest()
            .validate(transaction.pset())
            .map_err(|error| TakerSettlementPlanError::Manifest(error.to_string()))?;
        let original = CanonicalPset::decode(&serialize(transaction.pset()), MAX_SETTLEMENT_BYTES)?;
        validate_launch_global(original.pset())?;
        validate_settlement_shape(original.pset())?;

        let wallet_placement = transaction
            .layout()
            .placement(route.layout().wallet())
            .ok_or(TakerSettlementPlanError::LaunchProfile(
                "wallet contribution is missing from composition",
            ))?;
        let wallet_inputs = contiguous_indices(
            wallet_placement.input_base(),
            wallet_placement.input_count(),
        )?;
        if wallet_inputs.is_empty() {
            return Err(TakerSettlementPlanError::LaunchProfile(
                "wallet contribution must contain at least one input",
            ));
        }
        let provider_inputs = settlement_layout
            .provider_inputs
            .iter()
            .map(|placement| usize::from(placement.transaction_index))
            .collect::<BTreeSet<_>>();
        validate_partition(
            original.pset().inputs().len(),
            &wallet_inputs,
            &provider_inputs,
            "input",
        )?;
        if !wallet_inputs.contains(&usize::from(settlement_layout.taker_payment_input)) {
            return Err(TakerSettlementPlanError::LaunchProfile(
                "the RFQ payer input is not wallet-owned",
            ));
        }

        let wallet_contribution_outputs = contiguous_indices(
            wallet_placement.output_base(),
            wallet_placement.output_count(),
        )?;
        let quote_outputs = settlement_layout
            .quote_outputs
            .iter()
            .map(|placement| usize::from(placement.transaction_index))
            .collect::<BTreeSet<_>>();
        let fee_output = transaction.layout().fee_output_index();
        validate_output_partition(
            original.pset().outputs().len(),
            &wallet_contribution_outputs,
            &quote_outputs,
            fee_output,
        )?;

        let provider_input_by_id = settlement_layout
            .provider_inputs
            .iter()
            .map(|placement| {
                (
                    placement.quote_input_id,
                    usize::from(placement.transaction_index),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let quote_output_by_id = settlement_layout
            .quote_outputs
            .iter()
            .map(|placement| {
                (
                    placement.quote_output_id,
                    usize::from(placement.transaction_index),
                )
            })
            .collect::<BTreeMap<_, _>>();

        validate_original_inputs(
            original.pset(),
            quote_value,
            &provider_input_by_id,
            &wallet_inputs,
        )?;

        let mut wallet_outputs = wallet_contribution_outputs.clone();
        let mut provider_outputs = BTreeSet::new();
        let mut owned_outputs = Vec::new();
        for index in &wallet_contribution_outputs {
            let output = &original.pset().outputs()[*index];
            let blinder = output_blinder(output, *index)?;
            if !wallet_inputs.contains(&blinder) {
                return Err(TakerSettlementPlanError::LaunchProfile(
                    "wallet output delegates blinding outside wallet inputs",
                ));
            }
            owned_outputs.push(owned_expectation(
                *index,
                OwnedOutputKind::WalletContribution,
                output,
            )?);
        }

        for quoted in &quote_value.outputs {
            let index = *quote_output_by_id
                .get(&quoted.id)
                .ok_or(TakerSettlementPlanError::QuoteLayout)?;
            let output = &original.pset().outputs()[index];
            validate_quote_output(
                output,
                quoted,
                index,
                &provider_input_by_id,
                usize::from(settlement_layout.taker_payment_input),
            )?;
            match quoted.blinder {
                BlinderRoleDto::TakerPaymentInput => {
                    wallet_outputs.insert(index);
                }
                BlinderRoleDto::ProviderInput { .. } => {
                    provider_outputs.insert(index);
                }
            }
            if quoted.role == QuoteOutputRoleDto::TakerReceive {
                owned_outputs.push(owned_expectation(
                    index,
                    OwnedOutputKind::RfqReceive,
                    output,
                )?);
            }
        }
        if provider_outputs.is_empty() {
            return Err(TakerSettlementPlanError::LaunchProfile(
                "RFQ must assign at least one output to provider blinding",
            ));
        }
        for (index, output) in original.pset().outputs().iter().enumerate() {
            if index == fee_output {
                validate_fee_output(output, binding.policy_asset())?;
            } else {
                validate_unblinded_output(output, index)?;
            }
        }

        Ok(Self {
            binding,
            settlement_layout,
            original,
            manifest: transaction.manifest().clone(),
            route: route.authorization().clone(),
            composition_layout: transaction.layout().clone(),
            quote,
            market: market.clone(),
            wallet_inputs,
            provider_inputs,
            wallet_outputs,
            provider_outputs,
            owned_outputs,
        })
    }

    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn settlement_layout(&self) -> &SettlementLayoutDto {
        &self.settlement_layout
    }

    #[must_use]
    pub fn original_pset(&self) -> &PartiallySignedTransaction {
        self.original.pset()
    }

    #[must_use]
    pub const fn route(&self) -> &RouteAuthorization {
        &self.route
    }

    #[must_use]
    pub const fn composition_layout(&self) -> &CompositionLayout {
        &self.composition_layout
    }

    #[must_use]
    pub const fn quote(&self) -> &VerifiedFirmQuote {
        &self.quote
    }

    #[must_use]
    pub const fn market(&self) -> &TradingMarket {
        &self.market
    }

    #[must_use]
    pub fn owned_outputs(&self) -> &[OwnedOutputExpectation] {
        &self.owned_outputs
    }
}

/// Locally validated provider response awaiting one authoritative snapshot.
///
/// Construction performs every check that needs only the frozen route and the
/// authenticated provider response. It yields the exact owned source request
/// but holds no source or wallet reference across that asynchronous boundary.
/// [`Self::observe`] consumes this capability while obtaining the exact source
/// snapshot, so callers cannot advance to wallet authorization without crossing
/// the authoritative source boundary.
pub struct PreparedTakerAuthorization {
    plan: TakerSettlementPlan,
    provider: CanonicalPset,
    request: TakerSettlementSnapshotRequest,
}

impl PreparedTakerAuthorization {
    pub(crate) fn new(
        plan: TakerSettlementPlan,
        response: &ProviderBlindedPset,
    ) -> Result<Self, TakerAuthorizationError> {
        if response.binding() != &plan.binding || response.layout() != &plan.settlement_layout {
            return Err(TakerAuthorizationError::BindingMismatch);
        }
        response.layout().validate_for_quote(plan.quote.quote())?;

        let provider = CanonicalPset::decode(response.pset().as_bytes(), MAX_SETTLEMENT_BYTES)?;
        plan.manifest
            .validate(provider.pset())
            .map_err(|error| TakerAuthorizationError::Manifest(error.to_string()))?;
        validate_provider_mutation(&plan, provider.pset())?;

        for index in &plan.provider_outputs {
            verify_output_disclosure(&provider.pset().outputs()[*index]).map_err(|error| {
                TakerAuthorizationError::OutputDisclosure {
                    index: *index,
                    detail: error.to_string(),
                }
            })?;
        }

        // Fee policy is signing authorization, not a post-sign diagnostic.
        // Project fixed-size explicit-ALL witnesses before any chain read or
        // wallet capability is requested, then recheck concrete wallet results
        // below.
        validate_fee_policy(&plan, provider.pset())?;

        let outpoints = provider
            .pset()
            .inputs()
            .iter()
            .map(input_outpoint)
            .collect::<Vec<_>>();
        let quote_value = plan.quote.quote();
        let quote_anchor = ChainAnchor {
            height: quote_value.snapshot.block_height,
            hash: quote_value.snapshot.block_hash,
        };
        Ok(Self {
            request: TakerSettlementSnapshotRequest {
                chain: plan.binding.chain(),
                market: plan.market.contract_id(),
                quote_anchor,
                outpoints,
            },
            plan,
            provider,
        })
    }

    #[must_use]
    pub const fn plan(&self) -> &TakerSettlementPlan {
        &self.plan
    }

    /// Obtain the exact authoritative snapshot derived during local preflight.
    ///
    /// This consumes the preflight capability. Success returns a second opaque
    /// capability whose synchronous [`ObservedTakerAuthorization::authorize`]
    /// method is the only standardized path to a signed settlement.
    pub async fn observe<S>(
        self,
        source: &S,
    ) -> Result<ObservedTakerAuthorization, TakerAuthorizationError>
    where
        S: TakerSettlementSource + ?Sized,
    {
        let snapshot = source
            .settlement_snapshot(self.request)
            .await
            .map_err(|error| TakerAuthorizationError::Source(Box::new(error)))?;
        Ok(ObservedTakerAuthorization {
            plan: self.plan,
            provider: self.provider,
            snapshot,
        })
    }
}

/// Locally preflighted provider response paired with authoritative current
/// state.
///
/// This type has no public constructor. It is produced only when
/// [`PreparedTakerAuthorization::observe`] successfully crosses the configured
/// source boundary, and it deliberately owns no wallet reference.
pub struct ObservedTakerAuthorization {
    plan: TakerSettlementPlan,
    provider: CanonicalPset,
    snapshot: TakerSettlementSnapshot,
}

impl ObservedTakerAuthorization {
    /// Finish authorization from one coherent authoritative snapshot.
    ///
    /// This method is deliberately synchronous: after the current-state read
    /// completes there is no cancellation point before wallet-owned output
    /// validation, balancing blinding, full proof/balance checks, and signing.
    pub fn authorize<W>(
        self,
        wallet: &W,
    ) -> Result<TakerAuthorizedSettlement, TakerAuthorizationError>
    where
        W: TakerWalletFinalizer + ?Sized,
    {
        let Self {
            plan,
            provider,
            snapshot,
        } = self;
        let outpoints = provider
            .pset()
            .inputs()
            .iter()
            .map(input_outpoint)
            .collect::<Vec<_>>();
        let quote = plan.quote.quote();
        let quote_anchor = ChainAnchor {
            height: quote.snapshot.block_height,
            hash: quote.snapshot.block_hash,
        };
        validate_snapshot(&plan, &snapshot, &outpoints, quote_anchor)?;

        let prevouts = snapshot
            .prevouts()
            .iter()
            .map(|prevout| prevout.txout().clone())
            .collect::<Vec<_>>();
        validate_quoted_provider_prevouts(&plan, snapshot.prevouts())?;
        validate_all_inputs(
            provider.pset(),
            snapshot.prevouts(),
            &plan.provider_inputs,
            false,
            plan.binding.chain().genesis_hash,
        )?;

        let provider_transaction = provider
            .pset()
            .extract_tx()
            .map_err(|error| TakerAuthorizationError::InvalidPset(error.to_string()))?;
        for expectation in plan.owned_outputs.iter().filter(|expectation| {
            expectation.kind == OwnedOutputKind::RfqReceive
                && plan.provider_outputs.contains(&expectation.index)
        }) {
            wallet
                .validate_owned_output(OwnedOutputValidation {
                    expectation,
                    txout: &provider_transaction.output[expectation.index],
                })
                .map_err(|error| TakerAuthorizationError::Wallet(Box::new(error)))?;
        }

        let job = TakerWalletBlindingJob {
            pset: provider.pset().clone(),
            chain: plan.binding.chain(),
            route: plan.route.clone(),
            layout: plan.composition_layout.clone(),
            prevouts: snapshot.prevouts().to_vec(),
            wallet_input_indices: plan.wallet_inputs.iter().copied().collect(),
            wallet_output_indices: plan.wallet_outputs.iter().copied().collect(),
            provider_input_indices: plan.provider_inputs.iter().copied().collect(),
            owned_outputs: plan.owned_outputs.clone(),
        };
        let wallet_blinded = wallet
            .blind_last(job)
            .map_err(|error| TakerAuthorizationError::Wallet(Box::new(error)))?;
        let wallet_blinded =
            CanonicalPset::decode(&serialize(&wallet_blinded), MAX_SETTLEMENT_BYTES)?;
        plan.manifest
            .validate(wallet_blinded.pset())
            .map_err(|error| TakerAuthorizationError::Manifest(error.to_string()))?;
        validate_wallet_blinding_mutation(&plan, provider.pset(), wallet_blinded.pset())?;
        validate_all_inputs(
            wallet_blinded.pset(),
            snapshot.prevouts(),
            &plan.provider_inputs,
            false,
            plan.binding.chain().genesis_hash,
        )?;

        for (index, output) in wallet_blinded.pset().outputs().iter().enumerate() {
            if index == plan.composition_layout.fee_output_index() {
                validate_fee_output(output, plan.binding.policy_asset())?;
            } else {
                validate_confidential_output(output, index, wallet_blinded.pset().inputs().len())?;
            }
        }
        let transaction = wallet_blinded
            .pset()
            .extract_tx()
            .map_err(|error| TakerAuthorizationError::InvalidPset(error.to_string()))?;
        verify_confidential_proofs_and_balance(&transaction, &prevouts)
            .map_err(|error| TakerAuthorizationError::Confidential(error.detail().to_owned()))?;
        for expectation in &plan.owned_outputs {
            wallet
                .validate_owned_output(OwnedOutputValidation {
                    expectation,
                    txout: &transaction.output[expectation.index],
                })
                .map_err(|error| TakerAuthorizationError::Wallet(Box::new(error)))?;
        }
        validate_fee_policy(&plan, wallet_blinded.pset())?;

        let signing_job = TakerWalletSigningJob {
            pset: wallet_blinded.pset().clone(),
            chain: plan.binding.chain(),
            prevouts: snapshot.prevouts().to_vec(),
            wallet_input_indices: plan.wallet_inputs.iter().copied().collect(),
        };
        let signed = wallet
            .sign(signing_job)
            .map_err(|error| TakerAuthorizationError::Wallet(Box::new(error)))?;
        let signed = CanonicalPset::decode(&serialize(&signed), MAX_SETTLEMENT_BYTES)?;
        plan.manifest
            .validate(signed.pset())
            .map_err(|error| TakerAuthorizationError::Manifest(error.to_string()))?;
        validate_wallet_signing_mutation(&plan, wallet_blinded.pset(), signed.pset())?;
        validate_all_inputs(
            signed.pset(),
            snapshot.prevouts(),
            &plan.provider_inputs,
            true,
            plan.binding.chain().genesis_hash,
        )?;
        validate_fee_policy(&plan, signed.pset())?;

        let pset = SettlementPset::from_bytes(signed.into_bytes())
            .map_err(|error| TakerAuthorizationError::InvalidPset(error.to_string()))?;
        Ok(TakerAuthorizedSettlement::from_preflight(
            plan.binding,
            plan.settlement_layout,
            pset,
        ))
    }
}

fn validate_quoted_provider_prevouts(
    plan: &TakerSettlementPlan,
    authoritative: &[AuthoritativeTakerPrevout],
) -> Result<(), TakerAuthorizationError> {
    for placement in &plan.settlement_layout.provider_inputs {
        let index = usize::from(placement.transaction_index);
        let quoted = plan
            .quote
            .quote()
            .inputs
            .iter()
            .find(|quoted| quoted.id == placement.quote_input_id)
            .ok_or(TakerAuthorizationError::InvalidInput {
                index,
                reason: "provider layout does not resolve the authenticated quote",
            })?;
        let quoted_prevout = quoted.witness_utxo.to_txout()?;
        if authoritative[index].outpoint != quoted.outpoint
            || authoritative[index].txout != quoted_prevout
        {
            return Err(TakerAuthorizationError::InvalidInput {
                index,
                reason: "authoritative provider prevout differs from authenticated quote",
            });
        }
    }
    Ok(())
}

fn validate_binding(
    binding: &ExecutionBinding,
    verified: &VerifiedFirmQuote,
) -> Result<(), TakerSettlementPlanError> {
    let quote = verified.quote();
    let attestation = verified.signed().attestation;
    if binding.provider_endpoint() != quote.provider_endpoint
        || binding.provider_endpoint() != attestation.provider_endpoint
        || binding.client_endpoint() != attestation.client_endpoint
        || binding.chain().network != quote.network
        || binding.chain().genesis_hash != quote.genesis_hash
        || binding.policy_asset() != quote.policy_asset
        || binding.reservation_id() != quote.reservation_id
        || binding.quote_commitment() != quote.quote_commitment
        || binding.created_at_millis() != quote.created_at_millis
        || binding.accept_before_millis() != quote.accept_before_millis
    {
        return Err(TakerSettlementPlanError::BindingMismatch);
    }
    Ok(())
}

fn contiguous_indices(
    base: usize,
    count: usize,
) -> Result<BTreeSet<usize>, TakerSettlementPlanError> {
    let end = base
        .checked_add(count)
        .ok_or(TakerSettlementPlanError::IndexOverflow)?;
    Ok((base..end).collect())
}

fn validate_partition(
    length: usize,
    first: &BTreeSet<usize>,
    second: &BTreeSet<usize>,
    kind: &'static str,
) -> Result<(), TakerSettlementPlanError> {
    if !first.is_disjoint(second)
        || first.union(second).copied().collect::<BTreeSet<_>>() != (0..length).collect()
    {
        return Err(TakerSettlementPlanError::Partition(kind));
    }
    Ok(())
}

fn validate_output_partition(
    length: usize,
    wallet: &BTreeSet<usize>,
    quote: &BTreeSet<usize>,
    fee: usize,
) -> Result<(), TakerSettlementPlanError> {
    if fee >= length || wallet.contains(&fee) || quote.contains(&fee) || !wallet.is_disjoint(quote)
    {
        return Err(TakerSettlementPlanError::Partition("output"));
    }
    let mut union = wallet.union(quote).copied().collect::<BTreeSet<_>>();
    union.insert(fee);
    if union != (0..length).collect() {
        return Err(TakerSettlementPlanError::Partition("output"));
    }
    Ok(())
}

fn validate_launch_global(
    pset: &PartiallySignedTransaction,
) -> Result<(), TakerSettlementPlanError> {
    if pset.global.version != 2
        || pset.global.tx_data.version != 2
        || pset.global.tx_data.tx_modifiable.unwrap_or(0) != 0
        || pset.global.elements_tx_modifiable_flag.unwrap_or(0) != 0
        || !pset.global.scalars.is_empty()
        || pset
            .global
            .tx_data
            .fallback_locktime
            .is_some_and(|locktime| locktime != LockTime::ZERO)
    {
        return Err(TakerSettlementPlanError::LaunchProfile(
            "only immutable version-2 zero-locktime settlement PSETs are supported",
        ));
    }
    Ok(())
}

fn validate_settlement_shape(
    pset: &PartiallySignedTransaction,
) -> Result<(), TakerSettlementPlanError> {
    if pset.inputs().len() > MAX_SETTLEMENT_INPUTS || pset.outputs().len() > MAX_SETTLEMENT_OUTPUTS
    {
        return Err(TakerSettlementPlanError::LaunchProfile(
            "whole transaction exceeds RFQ settlement input/output bounds",
        ));
    }
    Ok(())
}

fn validate_original_inputs(
    pset: &PartiallySignedTransaction,
    quote: &deadcat_rfq_rpc::FirmQuoteDto,
    provider_by_id: &BTreeMap<u16, usize>,
    wallet_inputs: &BTreeSet<usize>,
) -> Result<(), TakerSettlementPlanError> {
    let provider_by_index = provider_by_id
        .iter()
        .map(|(id, index)| (*index, *id))
        .collect::<BTreeMap<_, _>>();
    for (index, input) in pset.inputs().iter().enumerate() {
        validate_input_metadata(input, index, false)
            .map_err(|error| TakerSettlementPlanError::Input(error.to_string()))?;
        if wallet_inputs.contains(&index) {
            validate_treeless_p2tr_declaration(input, index)
                .map_err(|error| TakerSettlementPlanError::Input(error.to_string()))?;
            continue;
        }
        let quote_id = provider_by_index
            .get(&index)
            .ok_or(TakerSettlementPlanError::QuoteLayout)?;
        let quoted = quote
            .inputs
            .iter()
            .find(|quoted| quoted.id == *quote_id)
            .ok_or(TakerSettlementPlanError::QuoteLayout)?;
        let quoted_prevout = quoted.witness_utxo.to_txout()?;
        let witness = input
            .witness_utxo
            .as_ref()
            .ok_or(TakerSettlementPlanError::Input(
                "missing witness UTXO".to_owned(),
            ))?;
        let internal_key = XOnlyPublicKey::from_slice(&quoted.internal_key.to_bytes())
            .map_err(|_| TakerSettlementPlanError::Input("invalid internal key".to_owned()))?;
        if input_outpoint(input) != quoted.outpoint
            || !same_prevout_body(witness, &quoted_prevout)
            || input.in_utxo_rangeproof != quoted_prevout.witness.rangeproof
            || input.tap_internal_key != Some(internal_key)
        {
            return Err(TakerSettlementPlanError::Input(format!(
                "provider input {index} disagrees with authenticated quote"
            )));
        }
        validate_treeless_p2tr_declaration(input, index)
            .map_err(|error| TakerSettlementPlanError::Input(error.to_string()))?;
    }
    Ok(())
}

fn validate_quote_output(
    output: &PsetOutput,
    quoted: &deadcat_rfq_rpc::QuoteOutputDto,
    index: usize,
    provider_by_id: &BTreeMap<u16, usize>,
    taker_payment_input: usize,
) -> Result<(), TakerSettlementPlanError> {
    let blinding_key = PublicKey::from_slice(&quoted.destination.blinding_public_key.to_bytes())
        .map(BitcoinPublicKey::new)
        .map_err(|_| TakerSettlementPlanError::QuoteLayout)?;
    let expected_blinder = match quoted.blinder {
        BlinderRoleDto::TakerPaymentInput => taker_payment_input,
        BlinderRoleDto::ProviderInput { quote_input_id } => *provider_by_id
            .get(&quote_input_id)
            .ok_or(TakerSettlementPlanError::QuoteLayout)?,
    };
    if output.asset != Some(quoted.asset)
        || output.amount != Some(quoted.amount)
        || output.script_pubkey.as_bytes() != quoted.destination.script_pubkey
        || output.blinding_key != Some(blinding_key)
        || output_blinder(output, index)? != expected_blinder
    {
        return Err(TakerSettlementPlanError::QuoteLayout);
    }
    Ok(())
}

fn owned_expectation(
    index: usize,
    kind: OwnedOutputKind,
    output: &PsetOutput,
) -> Result<OwnedOutputExpectation, TakerSettlementPlanError> {
    Ok(OwnedOutputExpectation {
        index,
        kind,
        asset: output.asset.ok_or(TakerSettlementPlanError::QuoteLayout)?,
        amount: output.amount.ok_or(TakerSettlementPlanError::QuoteLayout)?,
        script_pubkey: output.script_pubkey.clone(),
    })
}

fn output_blinder(output: &PsetOutput, index: usize) -> Result<usize, TakerSettlementPlanError> {
    output
        .blinder_index
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| TakerSettlementPlanError::Input(format!("output {index} has no blinder")))
}

fn validate_snapshot(
    plan: &TakerSettlementPlan,
    snapshot: &TakerSettlementSnapshot,
    outpoints: &[OutPoint],
    quote_anchor: ChainAnchor,
) -> Result<(), TakerAuthorizationError> {
    let now = snapshot.observed_at_millis;
    if now < plan.binding.created_at_millis() || now >= plan.binding.accept_before_millis() {
        return Err(TakerAuthorizationError::QuoteNotLive {
            now,
            created_at: plan.binding.created_at_millis(),
            accept_before: plan.binding.accept_before_millis(),
        });
    }
    if !snapshot.market.is_continuation_of(&plan.market)
        || snapshot.market.observed_at().height < quote_anchor.height
        || (snapshot.market.observed_at().height == quote_anchor.height
            && snapshot.market.observed_at().hash != quote_anchor.hash)
    {
        return Err(TakerAuthorizationError::MarketContinuity);
    }
    if snapshot.prevouts.len() != outpoints.len() {
        return Err(TakerAuthorizationError::PrevoutCount {
            expected: outpoints.len(),
            actual: snapshot.prevouts.len(),
        });
    }
    for (index, (expected, actual)) in outpoints.iter().zip(&snapshot.prevouts).enumerate() {
        if expected != &actual.outpoint {
            return Err(TakerAuthorizationError::PrevoutOrder { index });
        }
    }
    Ok(())
}

fn validate_provider_mutation(
    plan: &TakerSettlementPlan,
    provider: &PartiallySignedTransaction,
) -> Result<(), TakerAuthorizationError> {
    if provider.global.scalars.len() != 1 {
        return Err(TakerAuthorizationError::ProviderMutation(
            "provider blinding must leave exactly one scalar",
        ));
    }
    let mut normalized = provider.clone();
    normalized.global.scalars = plan.original.pset().global.scalars.clone();
    for index in &plan.provider_outputs {
        if !blinding_is_complete(&provider.outputs()[*index]) {
            return Err(TakerAuthorizationError::ProviderOutputIncomplete(*index));
        }
        restore_blinding_fields(
            &mut normalized.outputs_mut()[*index],
            &plan.original.pset().outputs()[*index],
        );
    }
    if &normalized != plan.original.pset() {
        return Err(TakerAuthorizationError::ProviderMutation(
            "provider changed a field outside its assigned output proofs and scalar",
        ));
    }
    Ok(())
}

fn validate_wallet_blinding_mutation(
    plan: &TakerSettlementPlan,
    provider: &PartiallySignedTransaction,
    wallet_blinded: &PartiallySignedTransaction,
) -> Result<(), TakerAuthorizationError> {
    if !wallet_blinded.global.scalars.is_empty() {
        return Err(TakerAuthorizationError::WalletMutation(
            "balancing blinding scalars were not consumed",
        ));
    }
    let mut normalized = wallet_blinded.clone();
    normalized.global.scalars = provider.global.scalars.clone();
    for index in &plan.wallet_outputs {
        if !blinding_is_complete(&wallet_blinded.outputs()[*index]) {
            return Err(TakerAuthorizationError::WalletOutputIncomplete(*index));
        }
        restore_blinding_fields(
            &mut normalized.outputs_mut()[*index],
            &provider.outputs()[*index],
        );
    }
    if &normalized != provider {
        return Err(TakerAuthorizationError::WalletMutation(
            "wallet changed a field outside assigned output proofs or wallet signatures",
        ));
    }
    Ok(())
}

fn validate_wallet_signing_mutation(
    plan: &TakerSettlementPlan,
    wallet_blinded: &PartiallySignedTransaction,
    signed: &PartiallySignedTransaction,
) -> Result<(), TakerAuthorizationError> {
    let mut normalized = signed.clone();
    for index in &plan.wallet_inputs {
        let input = &mut normalized.inputs_mut()[*index];
        input.tap_key_sig = wallet_blinded.inputs()[*index].tap_key_sig;
        input.final_script_witness = wallet_blinded.inputs()[*index].final_script_witness.clone();
    }
    if &normalized != wallet_blinded {
        return Err(TakerAuthorizationError::WalletMutation(
            "wallet changed a field outside its assigned signatures",
        ));
    }
    Ok(())
}

fn validate_all_inputs(
    pset: &PartiallySignedTransaction,
    authoritative: &[AuthoritativeTakerPrevout],
    provider_inputs: &BTreeSet<usize>,
    wallet_signed: bool,
    genesis_hash: elements::BlockHash,
) -> Result<(), TakerAuthorizationError> {
    let transaction = pset
        .extract_tx()
        .map_err(|error| TakerAuthorizationError::InvalidPset(error.to_string()))?;
    let prevouts = authoritative
        .iter()
        .map(|prevout| prevout.txout.clone())
        .collect::<Vec<_>>();
    for (index, input) in pset.inputs().iter().enumerate() {
        validate_authoritative_input(input, &authoritative[index], index)?;
        validate_input_metadata(
            input,
            index,
            wallet_signed && !provider_inputs.contains(&index),
        )?;
        let internal_key = validate_treeless_p2tr_declaration(input, index)?;
        if provider_inputs.contains(&index) {
            if input.tap_key_sig.is_some() || input.final_script_witness.is_some() {
                return Err(TakerAuthorizationError::InvalidInput {
                    index,
                    reason: "provider input was signed by the taker wallet",
                });
            }
        } else if wallet_signed {
            let signature = input
                .tap_key_sig
                .ok_or(TakerAuthorizationError::InvalidInput {
                    index,
                    reason: "wallet input lacks a Taproot key-path signature",
                })?;
            if signature.hash_ty != SchnorrSighashType::All
                || input.final_script_witness.as_ref() != Some(&vec![signature.to_vec()])
            {
                return Err(TakerAuthorizationError::InvalidInput {
                    index,
                    reason: "wallet final witness is not the exact explicit-ALL signature",
                });
            }
            verify_treeless_p2tr_explicit_all(
                &transaction,
                &prevouts,
                index,
                signature,
                internal_key,
                genesis_hash,
            )
            .map_err(|error| TakerAuthorizationError::InvalidSignature {
                index,
                detail: error.detail().to_owned(),
            })?;
        } else if input.tap_key_sig.is_some() || input.final_script_witness.is_some() {
            return Err(TakerAuthorizationError::InvalidInput {
                index,
                reason: "input was signed before wallet authorization",
            });
        }
    }
    Ok(())
}

fn validate_authoritative_input(
    input: &PsetInput,
    authoritative: &AuthoritativeTakerPrevout,
    index: usize,
) -> Result<(), TakerAuthorizationError> {
    if input_outpoint(input) != authoritative.outpoint {
        return Err(TakerAuthorizationError::PrevoutOrder { index });
    }
    let witness = input
        .witness_utxo
        .as_ref()
        .ok_or(TakerAuthorizationError::InvalidInput {
            index,
            reason: "missing witness UTXO",
        })?;
    if !same_prevout_body(witness, &authoritative.txout)
        || input.in_utxo_rangeproof != authoritative.txout.witness.rangeproof
    {
        return Err(TakerAuthorizationError::InvalidInput {
            index,
            reason: "PSET witness UTXO disagrees with authoritative prevout",
        });
    }
    Ok(())
}

fn validate_input_metadata(
    input: &PsetInput,
    index: usize,
    signed: bool,
) -> Result<(), TakerAuthorizationError> {
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
        || input
            .sequence
            .is_some_and(|sequence| sequence != Sequence::MAX)
        || input.required_time_locktime.is_some()
        || input.required_height_locktime.is_some()
        || has_issuance_or_pegin_metadata(input)
        || (!signed && (input.tap_key_sig.is_some() || input.final_script_witness.is_some()))
    {
        return Err(TakerAuthorizationError::InvalidInput {
            index,
            reason: "unsupported signing, wallet, issuance, pegin, or locktime metadata",
        });
    }
    Ok(())
}

fn validate_treeless_p2tr_declaration(
    input: &PsetInput,
    index: usize,
) -> Result<XOnlyPublicKey, TakerAuthorizationError> {
    let key = input
        .tap_internal_key
        .ok_or(TakerAuthorizationError::InvalidInput {
            index,
            reason: "missing Taproot internal key",
        })?;
    let witness = input
        .witness_utxo
        .as_ref()
        .ok_or(TakerAuthorizationError::InvalidInput {
            index,
            reason: "missing witness UTXO",
        })?;
    if input.sighash_type != Some(SchnorrSighashType::All.into())
        || witness.script_pubkey != Script::new_v1_p2tr(&Secp256k1::new(), key, None)
    {
        return Err(TakerAuthorizationError::InvalidInput {
            index,
            reason: "input is not tree-less P2TR with explicit SIGHASH_ALL",
        });
    }
    Ok(key)
}

fn validate_unblinded_output(
    output: &PsetOutput,
    index: usize,
) -> Result<(), TakerSettlementPlanError> {
    if output.script_pubkey.is_empty()
        || output.script_pubkey.is_provably_unspendable()
        || output.blinding_key.is_none()
        || output.asset.is_none()
        || output.amount.is_none()
        || !blinding_is_absent(output)
        || has_output_wallet_metadata(output)
    {
        return Err(TakerSettlementPlanError::Output(index));
    }
    Ok(())
}

fn validate_confidential_output(
    output: &PsetOutput,
    index: usize,
    input_count: usize,
) -> Result<(), TakerAuthorizationError> {
    if output.script_pubkey.is_empty()
        || output.script_pubkey.is_provably_unspendable()
        || output.blinding_key.is_none()
        || !blinding_is_complete(output)
        || output
            .blinder_index
            .and_then(|value| usize::try_from(value).ok())
            .is_none_or(|blinder| blinder >= input_count)
        || has_output_wallet_metadata(output)
    {
        return Err(TakerAuthorizationError::InvalidOutput {
            index,
            reason: "ordinary output is not a fully disclosed confidential output",
        });
    }
    verify_output_disclosure(output).map_err(|error| TakerAuthorizationError::OutputDisclosure {
        index,
        detail: error.to_string(),
    })
}

fn validate_fee_output(
    output: &PsetOutput,
    policy_asset: AssetId,
) -> Result<(), TakerSettlementPlanError> {
    if output.script_pubkey.is_empty()
        && output.amount.is_some_and(|amount| amount != 0)
        && output.asset == Some(policy_asset)
        && output.blinding_key.is_none()
        && output.blinder_index.is_none()
        && blinding_is_absent(output)
        && !has_output_wallet_metadata(output)
    {
        Ok(())
    } else {
        Err(TakerSettlementPlanError::FeeOutput)
    }
}

fn validate_fee_policy(
    plan: &TakerSettlementPlan,
    candidate: &PartiallySignedTransaction,
) -> Result<(), TakerAuthorizationError> {
    let placeholder = fee_placeholder_signature()?;
    let mut projected = candidate.clone();
    for index in plan.wallet_inputs.union(&plan.provider_inputs) {
        let input = &mut projected.inputs_mut()[*index];
        if input.tap_key_sig.is_none() {
            input.tap_key_sig = Some(placeholder);
        }
        if input.final_script_witness.is_none() {
            let signature = input.tap_key_sig.unwrap_or(placeholder);
            input.final_script_witness = Some(vec![signature.to_vec()]);
        }
    }
    let encoded = serialize(&projected);
    if encoded.len() > MAX_SETTLEMENT_BYTES {
        return Err(TakerAuthorizationError::FinalPayloadTooLarge {
            maximum: MAX_SETTLEMENT_BYTES,
            actual: encoded.len(),
        });
    }
    let transaction = projected
        .extract_tx()
        .map_err(|error| TakerAuthorizationError::InvalidPset(error.to_string()))?;
    let policy = plan.quote.quote().fee_policy;
    let weight = u64::try_from(transaction.weight())
        .map_err(|_| TakerAuthorizationError::FeePolicy("transaction weight overflow"))?;
    if weight > policy.maximum_transaction_weight {
        return Err(TakerAuthorizationError::FeePolicy(
            "projected transaction exceeds provider maximum weight",
        ));
    }
    let fee = transaction.fee_in(policy.policy_asset);
    if fee < policy.minimum_absolute_fee {
        return Err(TakerAuthorizationError::FeePolicy(
            "network fee is below provider minimum absolute fee",
        ));
    }
    let size = match policy.size_metric {
        FeeSizeMetricDto::RegularVbytes => transaction.vsize(),
        FeeSizeMetricDto::DiscountVbytes => transaction.discount_vsize(),
    };
    let required = u128::from(policy.minimum_sats_per_kvb)
        .checked_mul(
            u128::try_from(size)
                .map_err(|_| TakerAuthorizationError::FeePolicy("transaction size overflow"))?,
        )
        .and_then(|product| product.checked_add(999))
        .map(|value| value / 1_000)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(TakerAuthorizationError::FeePolicy(
            "required fee calculation overflow",
        ))?;
    if fee < required {
        return Err(TakerAuthorizationError::FeePolicy(
            "network fee is below provider minimum feerate",
        ));
    }
    Ok(())
}

fn fee_placeholder_signature() -> Result<elements::SchnorrSig, TakerAuthorizationError> {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&[0x42; 32]).map_err(|_| {
        TakerAuthorizationError::FeePolicy("internal signature projection key is invalid")
    })?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    Ok(elements::SchnorrSig {
        sig: secp.sign_schnorr(&Message::from_digest([0x24; 32]), &keypair),
        hash_ty: SchnorrSighashType::All,
    })
}

fn blinding_is_absent(output: &PsetOutput) -> bool {
    output.asset_comm.is_none()
        && output.amount_comm.is_none()
        && output.ecdh_pubkey.is_none()
        && output.value_rangeproof.is_none()
        && output.asset_surjection_proof.is_none()
        && output.blind_value_proof.is_none()
        && output.blind_asset_proof.is_none()
}

fn blinding_is_complete(output: &PsetOutput) -> bool {
    output.asset.is_some()
        && output.amount.is_some()
        && output.asset_comm.is_some()
        && output.amount_comm.is_some()
        && output.ecdh_pubkey.is_some()
        && output.value_rangeproof.is_some()
        && output.asset_surjection_proof.is_some()
        && output.blind_value_proof.is_some()
        && output.blind_asset_proof.is_some()
}

fn restore_blinding_fields(target: &mut PsetOutput, source: &PsetOutput) {
    target.asset_comm = source.asset_comm;
    target.amount_comm = source.amount_comm;
    target.ecdh_pubkey = source.ecdh_pubkey;
    target.value_rangeproof = source.value_rangeproof.clone();
    target.asset_surjection_proof = source.asset_surjection_proof.clone();
    target.blind_value_proof = source.blind_value_proof.clone();
    target.blind_asset_proof = source.blind_asset_proof.clone();
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
pub enum TakerSettlementPlanError {
    #[error("RFQ route binding failed: {0}")]
    Rfq(#[from] RfqVenueError),
    #[error("authenticated quote or layout is invalid: {0}")]
    Quote(#[from] FirmQuoteValidationError),
    #[error("route manifest validation failed: {0}")]
    Manifest(String),
    #[error(transparent)]
    Canonical(#[from] CanonicalPsetError),
    #[error("the reservation binding does not match the authenticated quote")]
    BindingMismatch,
    #[error("the supplied market does not authorize this quote")]
    MarketMismatch,
    #[error("unsupported launch settlement profile: {0}")]
    LaunchProfile(&'static str),
    #[error("{0} ownership does not form an exact transaction partition")]
    Partition(&'static str),
    #[error("composition index arithmetic overflow")]
    IndexOverflow,
    #[error("settlement layout does not resolve the authenticated quote")]
    QuoteLayout,
    #[error("invalid launch input: {0}")]
    Input(String),
    #[error("invalid unblinded launch output {0}")]
    Output(usize),
    #[error("invalid explicit policy-asset fee output")]
    FeeOutput,
}

#[derive(Debug, Error)]
pub enum TakerAuthorizationError {
    #[error("the provider response binding or layout differs from this plan")]
    BindingMismatch,
    #[error("settlement layout is invalid: {0}")]
    Layout(#[from] FirmQuoteValidationError),
    #[error(transparent)]
    Canonical(#[from] CanonicalPsetError),
    #[error("invalid PSET: {0}")]
    InvalidPset(String),
    #[error("route manifest validation failed: {0}")]
    Manifest(String),
    #[error("authoritative state source failed: {0}")]
    Source(#[source] Box<dyn Error + Send + Sync>),
    #[error("caller wallet failed: {0}")]
    Wallet(#[source] Box<dyn Error + Send + Sync>),
    #[error("provider mutation is unauthorized: {0}")]
    ProviderMutation(&'static str),
    #[error("provider output {0} is not completely blinded")]
    ProviderOutputIncomplete(usize),
    #[error("wallet mutation is unauthorized: {0}")]
    WalletMutation(&'static str),
    #[error("wallet output {0} is not completely blinded")]
    WalletOutputIncomplete(usize),
    #[error("quote is not live at {now}; valid interval is [{created_at}, {accept_before})")]
    QuoteNotLive {
        now: u64,
        created_at: u64,
        accept_before: u64,
    },
    #[error("fresh market state does not continue the planned market and quote anchor")]
    MarketContinuity,
    #[error("authoritative source returned {actual} prevouts; expected {expected}")]
    PrevoutCount { expected: usize, actual: usize },
    #[error("authoritative source returned the wrong outpoint at input {index}")]
    PrevoutOrder { index: usize },
    #[error("invalid input {index}: {reason}")]
    InvalidInput { index: usize, reason: &'static str },
    #[error("invalid signature at input {index}: {detail}")]
    InvalidSignature { index: usize, detail: String },
    #[error("invalid output {index}: {reason}")]
    InvalidOutput { index: usize, reason: &'static str },
    #[error("output disclosure proof failed at {index}: {detail}")]
    OutputDisclosure { index: usize, detail: String },
    #[error("confidential transaction verification failed: {0}")]
    Confidential(String),
    #[error("provider fee policy rejected settlement: {0}")]
    FeePolicy(&'static str),
    #[error("projected finalized PSET has {actual} bytes; maximum is {maximum}")]
    FinalPayloadTooLarge { maximum: usize, actual: usize },
    #[error("invalid explicit policy-asset fee output")]
    FeeOutput,
}

impl From<TakerSettlementPlanError> for TakerAuthorizationError {
    fn from(error: TakerSettlementPlanError) -> Self {
        match error {
            TakerSettlementPlanError::FeeOutput => Self::FeeOutput,
            other => Self::InvalidPset(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;
