//! Provisional client-local venue normalization.
//!
//! A venue-specific adapter authenticates its quote, reservation, or chain
//! evidence and proposes one selected fill. A client-created per-leg request
//! then binds that proposal to exact payment and recipient outputs before it
//! becomes a [`PreparedLeg`]. Aggregate validation returns an owning
//! [`ValidatedRoute`], which is the only route type that can compose those exact
//! legs and the already-authorized network fee.
//!
//! These types are deliberately transport-free and do not derive
//! serialization: untrusted wire data must never deserialize directly into a
//! client-authorized leg. This initial binding supports ordinary confidential
//! payment/receipt outputs. Future AMM or DLOB adapters will need typed
//! covenant-specific bindings rather than raw PSET maps.
//!
//! Leg input amounts are the user's gross trade-asset debit, including any
//! same-asset venue fee. Leg output amounts are the user's net receipt. The
//! Liquid network fee is authorized and accounted separately.
//!
//! A prepared leg or validated route authorizes only these normalized trade
//! claims and their named ordinary outputs. It does not validate wallet change,
//! ancillary-output net effects, per-asset transaction balance, proofs, or
//! sighash policy. Every participant must still authorize the complete blinded
//! transaction before signing.

use std::collections::{BTreeMap, BTreeSet};

use deadcat_types::{ChainIdentity, ContractId};
use elements::bitcoin::PublicKey;
use elements::{AssetId, OutPoint, Script};
use thiserror::Error;

use crate::composition::{
    BlinderRef, ComposedTransaction, CompositionError, CompositionLimits, ContributionHandle,
    InputSpec, NetworkFee, OutputId, OutputSpec, TransactionComposer, TransactionContribution,
};

/// Exact amount of one Liquid asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AssetAmount {
    asset: AssetId,
    amount: u64,
}

/// Exact confidential destination authorized by the user for every route leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfidentialRecipient {
    script_pubkey: Script,
    blinding_key: PublicKey,
}

impl ConfidentialRecipient {
    pub fn new(script_pubkey: Script, blinding_key: PublicKey) -> Result<Self, ExecutionError> {
        if script_pubkey.is_empty() || script_pubkey.is_provably_unspendable() {
            return Err(ExecutionError::InvalidRecipientScript);
        }
        Ok(Self {
            script_pubkey,
            blinding_key,
        })
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn blinding_key(&self) -> PublicKey {
        self.blinding_key
    }
}

impl AssetAmount {
    pub fn new(asset: AssetId, amount: u64) -> Result<Self, ExecutionError> {
        if amount == 0 {
            return Err(ExecutionError::ZeroAmount);
        }
        Ok(Self { asset, amount })
    }

    #[must_use]
    pub const fn asset(self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(self) -> u64 {
        self.amount
    }
}

/// Exact chain, market, and policy-asset context shared by every route leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VenueContext {
    pub chain: ChainIdentity,
    pub market: ContractId,
    pub policy_asset: AssetId,
}

/// User-authorized trade amount semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionKind {
    ExactIn {
        input: AssetAmount,
        output_asset: AssetId,
        minimum_output: u64,
    },
    ExactOut {
        input_asset: AssetId,
        maximum_input: u64,
        output: AssetAmount,
    },
}

impl ExecutionKind {
    fn pair(self) -> (AssetId, AssetId) {
        match self {
            Self::ExactIn {
                input,
                output_asset,
                ..
            } => (input.asset, output_asset),
            Self::ExactOut {
                input_asset,
                output,
                ..
            } => (input_asset, output.asset),
        }
    }
}

/// Venue-neutral request and the user's hard fee bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionRequest {
    context: VenueContext,
    kind: ExecutionKind,
    recipient: ConfidentialRecipient,
    venue_fee_limits: BTreeMap<AssetId, u64>,
    max_network_fee: u64,
}

impl ExecutionRequest {
    pub fn exact_in(
        context: VenueContext,
        input: AssetAmount,
        output_asset: AssetId,
        minimum_output: u64,
        recipient: ConfidentialRecipient,
        venue_fee_limits: BTreeMap<AssetId, u64>,
        max_network_fee: u64,
    ) -> Result<Self, ExecutionError> {
        validate_pair_and_amounts(input.asset, input.amount, output_asset, minimum_output)?;
        validate_request_limits(
            input.asset,
            input.amount,
            &venue_fee_limits,
            max_network_fee,
        )?;
        Ok(Self {
            context,
            kind: ExecutionKind::ExactIn {
                input,
                output_asset,
                minimum_output,
            },
            recipient,
            venue_fee_limits,
            max_network_fee,
        })
    }

    pub fn exact_out(
        context: VenueContext,
        input_asset: AssetId,
        maximum_input: u64,
        output: AssetAmount,
        recipient: ConfidentialRecipient,
        venue_fee_limits: BTreeMap<AssetId, u64>,
        max_network_fee: u64,
    ) -> Result<Self, ExecutionError> {
        validate_pair_and_amounts(input_asset, maximum_input, output.asset, output.amount)?;
        validate_request_limits(
            input_asset,
            maximum_input,
            &venue_fee_limits,
            max_network_fee,
        )?;
        Ok(Self {
            context,
            kind: ExecutionKind::ExactOut {
                input_asset,
                maximum_input,
                output,
            },
            recipient,
            venue_fee_limits,
            max_network_fee,
        })
    }

    #[must_use]
    pub const fn context(&self) -> VenueContext {
        self.context
    }

    #[must_use]
    pub const fn kind(&self) -> ExecutionKind {
        self.kind
    }

    #[must_use]
    pub const fn recipient(&self) -> &ConfidentialRecipient {
        &self.recipient
    }

    #[must_use]
    pub const fn max_network_fee(&self) -> u64 {
        self.max_network_fee
    }

    /// Allocate an exact-input portion to one venue adapter.
    pub fn exact_in_leg(
        &self,
        id: LegId,
        input_amount: u64,
        payer_blinder: OutPoint,
    ) -> Result<LegPreparationRequest, ExecutionError> {
        let ExecutionKind::ExactIn {
            input,
            output_asset,
            ..
        } = self.kind
        else {
            return Err(ExecutionError::WrongLegRequestKind);
        };
        Ok(LegPreparationRequest {
            id,
            context: self.context,
            kind: LegExecutionKind::ExactIn {
                input: AssetAmount::new(input.asset, input_amount)?,
                output_asset,
            },
            recipient: self.recipient.clone(),
            payer_blinder,
        })
    }

    /// Allocate an exact-output portion to one venue adapter.
    pub fn exact_out_leg(
        &self,
        id: LegId,
        output_amount: u64,
        payer_blinder: OutPoint,
    ) -> Result<LegPreparationRequest, ExecutionError> {
        let ExecutionKind::ExactOut {
            input_asset,
            output,
            ..
        } = self.kind
        else {
            return Err(ExecutionError::WrongLegRequestKind);
        };
        Ok(LegPreparationRequest {
            id,
            context: self.context,
            kind: LegExecutionKind::ExactOut {
                input_asset,
                output: AssetAmount::new(output.asset, output_amount)?,
            },
            recipient: self.recipient.clone(),
            payer_blinder,
        })
    }

    /// Validate checked aggregate economics and retain ownership of the exact
    /// legs and fee that will be composed.
    pub fn validate_route(
        self,
        legs: Vec<PreparedLeg>,
        network_fee: NetworkFee,
    ) -> Result<ValidatedRoute, ExecutionError> {
        if legs.is_empty() {
            return Err(ExecutionError::NoLegs);
        }
        if network_fee.policy_asset() != self.context.policy_asset {
            return Err(ExecutionError::WrongPolicyAsset);
        }
        if network_fee.amount() > self.max_network_fee {
            return Err(ExecutionError::NetworkFeeExceeded {
                maximum: self.max_network_fee,
                actual: network_fee.amount(),
            });
        }

        let expected_pair = self.kind.pair();
        let mut leg_ids = BTreeSet::new();
        let mut total_input = 0_u64;
        let mut total_output = 0_u64;
        let mut fees = BTreeMap::<AssetId, u64>::new();
        for leg in &legs {
            if !leg_ids.insert(leg.id()) {
                return Err(ExecutionError::DuplicateLegId(leg.id()));
            }
            if leg.request.context != self.context || leg.request.recipient != self.recipient {
                return Err(ExecutionError::ContextMismatch);
            }
            if !matches!(
                (self.kind, leg.request.kind),
                (
                    ExecutionKind::ExactIn { .. },
                    LegExecutionKind::ExactIn { .. }
                ) | (
                    ExecutionKind::ExactOut { .. },
                    LegExecutionKind::ExactOut { .. }
                )
            ) {
                return Err(ExecutionError::WrongLegRequestKind);
            }
            if leg.request.kind.pair() != expected_pair
                || (leg.execution.input.asset, leg.execution.output.asset) != expected_pair
            {
                return Err(ExecutionError::AssetDirectionMismatch);
            }
            total_input = total_input
                .checked_add(leg.execution.input.amount)
                .ok_or(ExecutionError::AmountOverflow)?;
            total_output = total_output
                .checked_add(leg.execution.output.amount)
                .ok_or(ExecutionError::AmountOverflow)?;
            for (&asset, &amount) in &leg.venue_fees {
                let total = fees.entry(asset).or_default();
                *total = total
                    .checked_add(amount)
                    .ok_or(ExecutionError::AmountOverflow)?;
            }
        }

        for (&asset, &actual) in &fees {
            let maximum = self.venue_fee_limits.get(&asset).copied().unwrap_or(0);
            if actual > maximum {
                return Err(ExecutionError::VenueFeeExceeded {
                    asset,
                    maximum,
                    actual,
                });
            }
        }

        match self.kind {
            ExecutionKind::ExactIn {
                input,
                minimum_output,
                ..
            } => {
                if total_input != input.amount {
                    return Err(ExecutionError::ExactInputMismatch {
                        expected: input.amount,
                        actual: total_input,
                    });
                }
                if total_output < minimum_output {
                    return Err(ExecutionError::MinimumOutputNotMet {
                        minimum: minimum_output,
                        actual: total_output,
                    });
                }
            }
            ExecutionKind::ExactOut {
                maximum_input,
                output,
                ..
            } => {
                if total_output != output.amount {
                    return Err(ExecutionError::ExactOutputMismatch {
                        expected: output.amount,
                        actual: total_output,
                    });
                }
                if total_input > maximum_input {
                    return Err(ExecutionError::MaximumInputExceeded {
                        maximum: maximum_input,
                        actual: total_input,
                    });
                }
            }
        }

        let summary = RouteSummary {
            execution: ExactExecution {
                input: AssetAmount {
                    asset: expected_pair.0,
                    amount: total_input,
                },
                output: AssetAmount {
                    asset: expected_pair.1,
                    amount: total_output,
                },
            },
            venue_fees: fees,
            network_fee,
        };
        Ok(ValidatedRoute {
            request: self,
            legs,
            summary,
        })
    }
}

/// Exact gross input and net output for one prepared leg or complete route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactExecution {
    input: AssetAmount,
    output: AssetAmount,
}

impl ExactExecution {
    pub fn new(input: AssetAmount, output: AssetAmount) -> Result<Self, ExecutionError> {
        validate_pair_and_amounts(input.asset, input.amount, output.asset, output.amount)?;
        Ok(Self { input, output })
    }

    #[must_use]
    pub const fn input(self) -> AssetAmount {
        self.input
    }

    #[must_use]
    pub const fn output(self) -> AssetAmount {
        self.output
    }
}

/// Route-local identifier for one independently prepared venue leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegId(u64);

impl LegId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Per-leg allocation created by the client/router before adapter preparation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegPreparationRequest {
    id: LegId,
    context: VenueContext,
    kind: LegExecutionKind,
    recipient: ConfidentialRecipient,
    payer_blinder: OutPoint,
}

impl LegPreparationRequest {
    #[must_use]
    pub const fn id(&self) -> LegId {
        self.id
    }

    #[must_use]
    pub const fn context(&self) -> VenueContext {
        self.context
    }

    #[must_use]
    pub const fn kind(&self) -> LegExecutionKind {
        self.kind
    }

    #[must_use]
    pub const fn recipient(&self) -> &ConfidentialRecipient {
        &self.recipient
    }

    #[must_use]
    pub const fn payer_blinder(&self) -> OutPoint {
        self.payer_blinder
    }

    /// Authorize one adapter proposal against this exact allocation and the
    /// user's exact recipient/blinding requirements.
    pub fn authorize(self, proposal: ProposedLeg) -> Result<PreparedLeg, ExecutionError> {
        validate_leg_execution(self.kind, proposal.execution)?;
        validate_initial_fees(proposal.execution, &proposal.venue_fees)?;
        if proposal.contribution.inputs().is_empty() || proposal.contribution.outputs().is_empty() {
            return Err(ExecutionError::EmptyContribution);
        }
        if proposal.payment_output == proposal.receive_output {
            return Err(ExecutionError::ReusedEconomicOutput);
        }

        let payment = unique_output(&proposal.contribution, proposal.payment_output)?;
        validate_claimed_confidential_output(
            payment,
            proposal.execution.input,
            None,
            BlinderRef::External(self.payer_blinder),
        )?;
        let receive = unique_output(&proposal.contribution, proposal.receive_output)?;
        validate_claimed_confidential_output(
            receive,
            proposal.execution.output,
            Some(&self.recipient),
            receive
                .blinder()
                .ok_or(ExecutionError::EconomicOutputNotConfidential)?,
        )?;
        let Some(BlinderRef::Local(receive_blinder)) = receive.blinder() else {
            return Err(ExecutionError::ReceiveOutputNotVenueBlinded);
        };
        if unique_input(&proposal.contribution, receive_blinder).is_err() {
            return Err(ExecutionError::ReceiveOutputNotVenueBlinded);
        }

        for output in proposal.contribution.outputs() {
            if let Some(BlinderRef::External(outpoint)) = output.blinder()
                && (output.id() != proposal.payment_output || outpoint != self.payer_blinder)
            {
                return Err(ExecutionError::UnauthorizedExternalBlinder);
            }
        }
        if proposal
            .contribution
            .inputs()
            .iter()
            .any(|input| input.outpoint() == self.payer_blinder)
        {
            return Err(ExecutionError::VenueClaimsPayerInput);
        }

        Ok(PreparedLeg {
            request: self,
            execution: proposal.execution,
            venue_fees: proposal.venue_fees,
            contribution: proposal.contribution,
            payment_output: proposal.payment_output,
            receive_output: proposal.receive_output,
        })
    }
}

/// Exact side allocated to one venue before it returns a quote/fill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegExecutionKind {
    ExactIn {
        input: AssetAmount,
        output_asset: AssetId,
    },
    ExactOut {
        input_asset: AssetId,
        output: AssetAmount,
    },
}

impl LegExecutionKind {
    fn pair(self) -> (AssetId, AssetId) {
        match self {
            Self::ExactIn {
                input,
                output_asset,
            } => (input.asset, output_asset),
            Self::ExactOut {
                input_asset,
                output,
            } => (input_asset, output.asset),
        }
    }
}

/// Adapter-produced fill proposal. It is not authorized until the originating
/// [`LegPreparationRequest`] consumes and validates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposedLeg {
    execution: ExactExecution,
    venue_fees: BTreeMap<AssetId, u64>,
    contribution: TransactionContribution,
    payment_output: OutputId,
    receive_output: OutputId,
}

impl ProposedLeg {
    pub fn new(
        execution: ExactExecution,
        venue_fees: BTreeMap<AssetId, u64>,
        contribution: TransactionContribution,
        payment_output: OutputId,
        receive_output: OutputId,
    ) -> Result<Self, ExecutionError> {
        if venue_fees.values().any(|amount| *amount == 0) {
            return Err(ExecutionError::ZeroFeeEntry);
        }
        Ok(Self {
            execution,
            venue_fees,
            contribution,
            payment_output,
            receive_output,
        })
    }
}

/// Exact venue execution authenticated and bound to physical output claims by
/// a client-created per-leg request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLeg {
    request: LegPreparationRequest,
    execution: ExactExecution,
    venue_fees: BTreeMap<AssetId, u64>,
    contribution: TransactionContribution,
    payment_output: OutputId,
    receive_output: OutputId,
}

impl PreparedLeg {
    #[must_use]
    pub const fn id(&self) -> LegId {
        self.request.id
    }

    #[must_use]
    pub const fn context(&self) -> VenueContext {
        self.request.context
    }

    #[must_use]
    pub const fn execution(&self) -> ExactExecution {
        self.execution
    }

    #[must_use]
    pub const fn contribution(&self) -> &TransactionContribution {
        &self.contribution
    }

    #[must_use]
    pub fn venue_fees(&self) -> &BTreeMap<AssetId, u64> {
        &self.venue_fees
    }

    #[must_use]
    pub const fn payment_output(&self) -> OutputId {
        self.payment_output
    }

    #[must_use]
    pub const fn receive_output(&self) -> OutputId {
        self.receive_output
    }
}

/// Pure local adapter boundary. Network I/O and evidence acquisition happen
/// before this method; the implementation authenticates and proposes a fill.
pub trait VenueAdapter {
    type Evidence;
    type Error;

    fn prepare(
        &self,
        request: &LegPreparationRequest,
        evidence: &Self::Evidence,
    ) -> Result<ProposedLeg, Self::Error>;
}

/// Normalized aggregate result for final wallet review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSummary {
    execution: ExactExecution,
    venue_fees: BTreeMap<AssetId, u64>,
    network_fee: NetworkFee,
}

impl RouteSummary {
    #[must_use]
    pub const fn execution(&self) -> ExactExecution {
        self.execution
    }

    #[must_use]
    pub fn venue_fees(&self) -> &BTreeMap<AssetId, u64> {
        &self.venue_fees
    }

    #[must_use]
    pub const fn network_fee(&self) -> NetworkFee {
        self.network_fee
    }
}

/// Aggregate-validated route that owns the exact legs and network fee that
/// will be composed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedRoute {
    request: ExecutionRequest,
    legs: Vec<PreparedLeg>,
    summary: RouteSummary,
}

impl ValidatedRoute {
    #[must_use]
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    #[must_use]
    pub fn legs(&self) -> &[PreparedLeg] {
        &self.legs
    }

    #[must_use]
    pub const fn summary(&self) -> &RouteSummary {
        &self.summary
    }

    /// Compose the exact owned legs after a wallet contribution. The same fee
    /// that passed aggregate validation is used; callers cannot substitute a
    /// different contribution or fee after validation.
    pub fn compose(
        self,
        limits: CompositionLimits,
        wallet: TransactionContribution,
    ) -> Result<ComposedRoute, RouteCompositionError> {
        let wallet_outpoints = wallet
            .inputs()
            .iter()
            .map(InputSpec::outpoint)
            .collect::<BTreeSet<_>>();
        for payer_leg in &self.legs {
            let payer_blinder = payer_leg.request.payer_blinder;
            if !wallet_outpoints.contains(&payer_blinder) {
                return Err(RouteCompositionError::PayerBlinderNotInWallet {
                    leg: payer_leg.id(),
                    outpoint: payer_blinder,
                });
            }
            if let Some(claiming_leg) = self.legs.iter().find(|candidate| {
                candidate
                    .contribution
                    .inputs()
                    .iter()
                    .any(|input| input.outpoint() == payer_blinder)
            }) {
                return Err(RouteCompositionError::PayerBlinderClaimedByVenue {
                    payer_leg: payer_leg.id(),
                    claiming_leg: claiming_leg.id(),
                    outpoint: payer_blinder,
                });
            }
        }
        let mut composer = TransactionComposer::new(limits, self.summary.network_fee);
        let wallet_handle = composer.push(wallet)?;
        let mut leg_handles = BTreeMap::new();
        for leg in &self.legs {
            let handle = composer.push(leg.contribution.clone())?;
            if leg_handles.insert(leg.id(), handle).is_some() {
                return Err(RouteCompositionError::DuplicateLegId(leg.id()));
            }
        }
        let transaction = composer.finish()?;
        Ok(ComposedRoute {
            transaction,
            authorization: RouteAuthorization {
                request: self.request,
                legs: self.legs,
                layout: RouteLayout {
                    wallet: wallet_handle,
                    legs: leg_handles,
                },
                summary: self.summary,
            },
        })
    }
}

/// Contribution handles allocated to the wallet and each selected venue leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteLayout {
    wallet: ContributionHandle,
    legs: BTreeMap<LegId, ContributionHandle>,
}

impl RouteLayout {
    #[must_use]
    pub const fn wallet(&self) -> ContributionHandle {
        self.wallet
    }

    #[must_use]
    pub fn leg(&self, id: LegId) -> Option<ContributionHandle> {
        self.legs.get(&id).copied()
    }
}

/// Route-level authorization retained for final signer-specific validation and
/// user review; it is not by itself authorization to sign the transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteAuthorization {
    request: ExecutionRequest,
    legs: Vec<PreparedLeg>,
    layout: RouteLayout,
    summary: RouteSummary,
}

impl RouteAuthorization {
    #[must_use]
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    #[must_use]
    pub fn legs(&self) -> &[PreparedLeg] {
        &self.legs
    }

    #[must_use]
    pub const fn layout(&self) -> &RouteLayout {
        &self.layout
    }

    #[must_use]
    pub const fn summary(&self) -> &RouteSummary {
        &self.summary
    }
}

/// Transaction assembled from validated legs, pending each participant's
/// signer-specific whole-transaction authorization.
#[derive(Clone, Debug)]
pub struct ComposedRoute {
    transaction: ComposedTransaction,
    authorization: RouteAuthorization,
}

impl ComposedRoute {
    #[must_use]
    pub const fn transaction(&self) -> &ComposedTransaction {
        &self.transaction
    }

    #[must_use]
    pub const fn layout(&self) -> &RouteLayout {
        self.authorization.layout()
    }

    #[must_use]
    pub const fn summary(&self) -> &RouteSummary {
        self.authorization.summary()
    }

    #[must_use]
    pub const fn authorization(&self) -> &RouteAuthorization {
        &self.authorization
    }

    #[must_use]
    pub fn into_parts(self) -> (ComposedTransaction, RouteAuthorization) {
        (self.transaction, self.authorization)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RouteCompositionError {
    #[error(transparent)]
    Composition(#[from] CompositionError),
    #[error("duplicate route leg id {0:?} reached composition")]
    DuplicateLegId(LegId),
    #[error("route leg {leg:?} assigns blinding to non-wallet input {outpoint}")]
    PayerBlinderNotInWallet { leg: LegId, outpoint: OutPoint },
    #[error(
        "route leg {payer_leg:?} assigns blinding to wallet input {outpoint}, but venue leg {claiming_leg:?} also claims that input"
    )]
    PayerBlinderClaimedByVenue {
        payer_leg: LegId,
        claiming_leg: LegId,
        outpoint: OutPoint,
    },
}

fn validate_pair_and_amounts(
    input_asset: AssetId,
    input_amount: u64,
    output_asset: AssetId,
    output_amount: u64,
) -> Result<(), ExecutionError> {
    if input_asset == output_asset {
        return Err(ExecutionError::SameAssetPair);
    }
    if input_amount == 0 || output_amount == 0 {
        return Err(ExecutionError::ZeroAmount);
    }
    Ok(())
}

fn validate_request_limits(
    input_asset: AssetId,
    maximum_input: u64,
    venue_fee_limits: &BTreeMap<AssetId, u64>,
    max_network_fee: u64,
) -> Result<(), ExecutionError> {
    if max_network_fee == 0 {
        return Err(ExecutionError::ZeroNetworkFeeLimit);
    }
    for (&asset, &amount) in venue_fee_limits {
        if amount == 0 {
            return Err(ExecutionError::ZeroFeeEntry);
        }
        if asset != input_asset {
            return Err(ExecutionError::UnsupportedFeeAsset(asset));
        }
        if amount > maximum_input {
            return Err(ExecutionError::VenueFeeExceedsGrossInput);
        }
    }
    Ok(())
}

fn validate_leg_execution(
    requested: LegExecutionKind,
    execution: ExactExecution,
) -> Result<(), ExecutionError> {
    if requested.pair() != (execution.input.asset, execution.output.asset) {
        return Err(ExecutionError::AssetDirectionMismatch);
    }
    match requested {
        LegExecutionKind::ExactIn { input, .. } if execution.input != input => {
            Err(ExecutionError::LegExactInputMismatch)
        }
        LegExecutionKind::ExactOut { output, .. } if execution.output != output => {
            Err(ExecutionError::LegExactOutputMismatch)
        }
        _ => Ok(()),
    }
}

fn validate_initial_fees(
    execution: ExactExecution,
    fees: &BTreeMap<AssetId, u64>,
) -> Result<(), ExecutionError> {
    for (&asset, &amount) in fees {
        if amount == 0 {
            return Err(ExecutionError::ZeroFeeEntry);
        }
        if asset != execution.input.asset {
            return Err(ExecutionError::UnsupportedFeeAsset(asset));
        }
        if amount > execution.input.amount {
            return Err(ExecutionError::VenueFeeExceedsGrossInput);
        }
    }
    Ok(())
}

fn unique_output(
    contribution: &TransactionContribution,
    id: OutputId,
) -> Result<&OutputSpec, ExecutionError> {
    let mut matches = contribution
        .outputs()
        .iter()
        .filter(|output| output.id() == id);
    let output = matches
        .next()
        .ok_or(ExecutionError::MissingEconomicOutput(id))?;
    if matches.next().is_some() {
        return Err(ExecutionError::AmbiguousEconomicOutput(id));
    }
    Ok(output)
}

fn unique_input(
    contribution: &TransactionContribution,
    id: crate::composition::InputId,
) -> Result<(), ExecutionError> {
    let count = contribution
        .inputs()
        .iter()
        .filter(|input| input.id() == id)
        .count();
    if count == 1 {
        Ok(())
    } else {
        Err(ExecutionError::ReceiveOutputNotVenueBlinded)
    }
}

fn validate_claimed_confidential_output(
    output: &OutputSpec,
    expected: AssetAmount,
    recipient: Option<&ConfidentialRecipient>,
    expected_blinder: BlinderRef,
) -> Result<(), ExecutionError> {
    if output.asset_amount() != Some((expected.asset, expected.amount)) {
        return Err(ExecutionError::EconomicOutputMismatch(output.id()));
    }
    let Some((script_pubkey, blinding_key)) = output.confidential_recipient() else {
        return Err(ExecutionError::EconomicOutputNotConfidential);
    };
    if output.blinder() != Some(expected_blinder) {
        return Err(ExecutionError::EconomicOutputBlinderMismatch(output.id()));
    }
    if let Some(recipient) = recipient
        && (script_pubkey != recipient.script_pubkey() || blinding_key != recipient.blinding_key())
    {
        return Err(ExecutionError::RecipientMismatch);
    }
    Ok(())
}

/// Venue normalization and aggregate-intent failures.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExecutionError {
    #[error("trade amounts must be positive")]
    ZeroAmount,
    #[error("zero-value venue fee entries must be omitted")]
    ZeroFeeEntry,
    #[error("the network-fee limit must be positive")]
    ZeroNetworkFeeLimit,
    #[error("the initial venue binding supports fees only in the trade input asset: {0}")]
    UnsupportedFeeAsset(AssetId),
    #[error("a venue fee cannot exceed the gross trade input")]
    VenueFeeExceedsGrossInput,
    #[error("the recipient script must be spendable and nonempty")]
    InvalidRecipientScript,
    #[error("input and output assets must differ")]
    SameAssetPair,
    #[error("at least one prepared leg is required")]
    NoLegs,
    #[error("duplicate prepared leg id {0:?}")]
    DuplicateLegId(LegId),
    #[error("the requested leg allocation uses the wrong exact-in/exact-out mode")]
    WrongLegRequestKind,
    #[error("a leg targets a different chain, market, or policy asset")]
    ContextMismatch,
    #[error("a leg uses the wrong asset direction")]
    AssetDirectionMismatch,
    #[error("checked route amount arithmetic overflowed")]
    AmountOverflow,
    #[error("the venue proposal does not use the exact allocated leg input")]
    LegExactInputMismatch,
    #[error("the venue proposal does not use the exact allocated leg output")]
    LegExactOutputMismatch,
    #[error("a prepared venue leg must contribute at least one input and output")]
    EmptyContribution,
    #[error("payment and receipt cannot claim the same output")]
    ReusedEconomicOutput,
    #[error("the contribution is missing economic output {0:?}")]
    MissingEconomicOutput(OutputId),
    #[error("economic output {0:?} is ambiguous within its contribution")]
    AmbiguousEconomicOutput(OutputId),
    #[error("economic output {0:?} does not match its declared asset and amount")]
    EconomicOutputMismatch(OutputId),
    #[error("economic payment and receipt outputs must be confidential")]
    EconomicOutputNotConfidential,
    #[error("economic output {0:?} uses the wrong blinding input")]
    EconomicOutputBlinderMismatch(OutputId),
    #[error("the receive output does not match the user-authorized destination")]
    RecipientMismatch,
    #[error("the receive output must be blinded by a local venue input")]
    ReceiveOutputNotVenueBlinded,
    #[error("only the claimed payment output may use the payer's external blinder")]
    UnauthorizedExternalBlinder,
    #[error("a venue contribution cannot claim the payer's wallet input")]
    VenueClaimsPayerInput,
    #[error("the network fee uses the wrong policy asset")]
    WrongPolicyAsset,
    #[error("network fee {actual} exceeds maximum {maximum}")]
    NetworkFeeExceeded { maximum: u64, actual: u64 },
    #[error("venue fee for {asset} is {actual}, exceeding maximum {maximum}")]
    VenueFeeExceeded {
        asset: AssetId,
        maximum: u64,
        actual: u64,
    },
    #[error("exact input is {actual}, expected {expected}")]
    ExactInputMismatch { expected: u64, actual: u64 },
    #[error("output is {actual}, below minimum {minimum}")]
    MinimumOutputNotMet { minimum: u64, actual: u64 },
    #[error("exact output is {actual}, expected {expected}")]
    ExactOutputMismatch { expected: u64, actual: u64 },
    #[error("input is {actual}, above maximum {maximum}")]
    MaximumInputExceeded { maximum: u64, actual: u64 },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
    use elements::bitcoin::PublicKey as BitcoinPublicKey;
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{BlockHash, OutPoint, Script, TxOut, TxOutWitness, Txid};

    use super::*;
    use crate::composition::{
        BlinderRef, CompositionLimits, InputId, InputSequence, InputSpec, LockTimeConstraint,
        OutputId, OutputSpec,
    };

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn test_context(byte: u8) -> VenueContext {
        VenueContext {
            chain: ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_byte_array([byte; 32]),
            },
            market: ContractId::new(OutPoint::new(
                Txid::from_byte_array([byte.wrapping_add(1); 32]),
                0,
            )),
            policy_asset: asset(1),
        }
    }

    fn amount(asset: AssetId, amount: u64) -> AssetAmount {
        AssetAmount::new(asset, amount).expect("amount")
    }

    fn script(byte: u8) -> Script {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend([byte; 20]);
        Script::from(bytes)
    }

    fn blinding_key(byte: u8) -> BitcoinPublicKey {
        BitcoinPublicKey::new(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).expect("secret"),
        ))
    }

    fn recipient() -> ConfidentialRecipient {
        ConfidentialRecipient::new(script(90), blinding_key(90)).expect("recipient")
    }

    fn payer_outpoint() -> OutPoint {
        OutPoint::new(Txid::from_byte_array([20; 32]), 0)
    }

    fn input_spec(id: u64, byte: u8, input_asset: AssetId, input_amount: u64) -> InputSpec {
        InputSpec::new(
            InputId::new(id),
            OutPoint::new(Txid::from_byte_array([byte; 32]), 0),
            TxOut {
                asset: Asset::Explicit(input_asset),
                value: Value::Explicit(input_amount),
                nonce: Nonce::Null,
                script_pubkey: script(byte),
                witness: TxOutWitness::default(),
            },
            InputSequence::Final,
        )
    }

    fn proposed_leg(
        id: u64,
        asset_in: AssetId,
        amount_in: u64,
        asset_out: AssetId,
        amount_out: u64,
        fees: BTreeMap<AssetId, u64>,
    ) -> ProposedLeg {
        ProposedLeg::new(
            ExactExecution::new(amount(asset_in, amount_in), amount(asset_out, amount_out))
                .expect("execution"),
            fees,
            TransactionContribution::new(
                vec![input_spec(1, 30 + id as u8, asset_out, amount_out)],
                vec![
                    OutputSpec::confidential(
                        OutputId::new(1),
                        asset_in,
                        amount_in,
                        script(70 + id as u8),
                        blinding_key(70 + id as u8),
                        BlinderRef::External(payer_outpoint()),
                    ),
                    OutputSpec::confidential(
                        OutputId::new(2),
                        asset_out,
                        amount_out,
                        recipient().script_pubkey().clone(),
                        recipient().blinding_key(),
                        BlinderRef::Local(InputId::new(1)),
                    ),
                ],
                LockTimeConstraint::Unconstrained,
            ),
            OutputId::new(1),
            OutputId::new(2),
        )
        .expect("proposal")
    }

    struct StaticAdapter(ProposedLeg);

    impl VenueAdapter for StaticAdapter {
        type Evidence = ();
        type Error = ExecutionError;

        fn prepare(
            &self,
            _request: &LegPreparationRequest,
            _evidence: &Self::Evidence,
        ) -> Result<ProposedLeg, Self::Error> {
            Ok(self.0.clone())
        }
    }

    fn exact_in_leg(
        request: &ExecutionRequest,
        id: u64,
        amount_in: u64,
        amount_out: u64,
        fees: BTreeMap<AssetId, u64>,
    ) -> PreparedLeg {
        let leg_request = request
            .exact_in_leg(LegId::new(id), amount_in, payer_outpoint())
            .expect("leg request");
        let (asset_in, asset_out) = request.kind().pair();
        let adapter = StaticAdapter(proposed_leg(
            id, asset_in, amount_in, asset_out, amount_out, fees,
        ));
        let proposal = adapter
            .prepare(&leg_request, &())
            .expect("adapter proposal");
        leg_request.authorize(proposal).expect("prepared leg")
    }

    fn exact_out_leg(
        request: &ExecutionRequest,
        id: u64,
        amount_in: u64,
        amount_out: u64,
    ) -> PreparedLeg {
        let leg_request = request
            .exact_out_leg(LegId::new(id), amount_out, payer_outpoint())
            .expect("leg request");
        let (asset_in, asset_out) = request.kind().pair();
        let adapter = StaticAdapter(proposed_leg(
            id,
            asset_in,
            amount_in,
            asset_out,
            amount_out,
            BTreeMap::new(),
        ));
        let proposal = adapter
            .prepare(&leg_request, &())
            .expect("adapter proposal");
        leg_request.authorize(proposal).expect("prepared leg")
    }

    #[test]
    fn exact_in_aggregates_multiple_legs_with_fee_inclusive_debits() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 100),
            asset_out,
            95,
            recipient(),
            BTreeMap::from([(asset_in, 5)]),
            1_000,
        )
        .expect("request");
        let first = exact_in_leg(&request, 1, 40, 39, BTreeMap::from([(asset_in, 2)]));
        let second = exact_in_leg(&request, 2, 60, 58, BTreeMap::from([(asset_in, 3)]));
        let network_fee = NetworkFee::new(context.policy_asset, 900).expect("fee");
        let route = request
            .validate_route(vec![first, second], network_fee)
            .expect("route");
        let summary = route.summary();

        assert_eq!(summary.execution().input, amount(asset_in, 100));
        assert_eq!(summary.execution().output, amount(asset_out, 97));
        assert_eq!(summary.venue_fees().get(&asset_in), Some(&5));
        assert_eq!(summary.network_fee(), network_fee);
    }

    #[test]
    fn multiple_exact_legs_feed_one_atomic_composition_without_output_aliasing() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let network_fee = NetworkFee::new(context.policy_asset, 100).expect("fee");
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 100),
            asset_out,
            95,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("request");
        let first = exact_in_leg(&request, 1, 40, 40, BTreeMap::new());
        let second = exact_in_leg(&request, 2, 60, 55, BTreeMap::new());
        let route = request
            .validate_route(vec![first, second], network_fee)
            .expect("aggregate exact-in route");

        let wallet = TransactionContribution::new(
            vec![
                input_spec(1, 10, context.policy_asset, 1_000),
                InputSpec::new(
                    InputId::new(2),
                    payer_outpoint(),
                    TxOut {
                        asset: Asset::Explicit(asset_in),
                        value: Value::Explicit(100),
                        nonce: Nonce::Null,
                        script_pubkey: script(20),
                        witness: TxOutWitness::default(),
                    },
                    InputSequence::Final,
                ),
            ],
            vec![OutputSpec::confidential(
                OutputId::new(1),
                context.policy_asset,
                900,
                script(80),
                blinding_key(80),
                BlinderRef::Local(InputId::new(1)),
            )],
            LockTimeConstraint::Unconstrained,
        );
        let composed_route = route
            .compose(CompositionLimits::default(), wallet)
            .expect("atomic composition");
        let first_handle = composed_route
            .layout()
            .leg(LegId::new(1))
            .expect("first leg");
        let second_handle = composed_route
            .layout()
            .leg(LegId::new(2))
            .expect("second leg");
        let composed = composed_route.transaction();

        assert_eq!(composed.pset().inputs().len(), 4);
        assert_eq!(composed.pset().outputs().len(), 6);
        let first_receive = composed
            .layout()
            .output_index(first_handle, OutputId::new(2))
            .expect("first receive");
        let second_receive = composed
            .layout()
            .output_index(second_handle, OutputId::new(2))
            .expect("second receive");
        let payer_input = composed
            .layout()
            .input_index(composed_route.layout().wallet(), InputId::new(2))
            .expect("payer input");
        let first_inventory = composed
            .layout()
            .input_index(first_handle, InputId::new(1))
            .expect("first inventory input");
        let second_inventory = composed
            .layout()
            .input_index(second_handle, InputId::new(1))
            .expect("second inventory input");
        let first_payment = composed
            .layout()
            .output_index(first_handle, OutputId::new(1))
            .expect("first payment");
        let second_payment = composed
            .layout()
            .output_index(second_handle, OutputId::new(1))
            .expect("second payment");
        assert_ne!(first_receive, second_receive);
        assert_eq!(composed.pset().outputs()[first_receive].amount, Some(40));
        assert_eq!(composed.pset().outputs()[second_receive].amount, Some(55));
        assert_eq!(
            composed.pset().outputs()[first_payment].blinder_index,
            Some(u32::try_from(payer_input).expect("PSET index"))
        );
        assert_eq!(
            composed.pset().outputs()[second_payment].blinder_index,
            Some(u32::try_from(payer_input).expect("PSET index"))
        );
        assert_eq!(
            composed.pset().outputs()[first_receive].blinder_index,
            Some(u32::try_from(first_inventory).expect("PSET index"))
        );
        assert_eq!(
            composed.pset().outputs()[second_receive].blinder_index,
            Some(u32::try_from(second_inventory).expect("PSET index"))
        );
        composed
            .manifest()
            .validate(composed.pset())
            .expect("frozen multi-leg manifest");
    }

    #[test]
    fn exact_out_requires_exact_receipt_and_bounded_input() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_out(
            context,
            asset_in,
            105,
            amount(asset_out, 100),
            recipient(),
            BTreeMap::new(),
            1_000,
        )
        .expect("request");
        let first = exact_out_leg(&request, 1, 50, 40);
        let second = exact_out_leg(&request, 2, 54, 60);
        request
            .clone()
            .validate_route(
                vec![first.clone(), second.clone()],
                NetworkFee::new(context.policy_asset, 1_000).expect("fee"),
            )
            .expect("within maximum");

        let too_expensive = exact_out_leg(&request, 3, 56, 60);
        assert!(matches!(
            request.clone().validate_route(
                vec![first, too_expensive],
                NetworkFee::new(context.policy_asset, 1_000).expect("fee"),
            ),
            Err(ExecutionError::MaximumInputExceeded { .. })
        ));

        let wrong_output = exact_out_leg(&request, 4, 54, 59);
        assert!(matches!(
            request.clone().validate_route(
                vec![second, wrong_output],
                NetworkFee::new(context.policy_asset, 1_000).expect("fee"),
            ),
            Err(ExecutionError::ExactOutputMismatch { .. })
        ));

        let allocation = request
            .exact_out_leg(LegId::new(5), 60, payer_outpoint())
            .expect("allocation");
        assert_eq!(
            allocation.authorize(proposed_leg(
                5,
                asset_in,
                54,
                asset_out,
                59,
                BTreeMap::new(),
            )),
            Err(ExecutionError::LegExactOutputMismatch)
        );
    }

    #[test]
    fn context_direction_fee_and_id_mismatches_fail_closed() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 10),
            asset_out,
            9,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("request");
        let valid = exact_in_leg(&request, 1, 10, 9, BTreeMap::new());

        assert_eq!(
            request.clone().validate_route(
                vec![valid.clone(), valid.clone()],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::DuplicateLegId(LegId::new(1)))
        );
        let other_context_request = ExecutionRequest::exact_in(
            test_context(11),
            amount(asset_in, 10),
            asset_out,
            9,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("other context request");
        assert_eq!(
            request.clone().validate_route(
                vec![exact_in_leg(
                    &other_context_request,
                    2,
                    10,
                    9,
                    BTreeMap::new(),
                )],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::ContextMismatch)
        );
        let reverse_request = ExecutionRequest::exact_in(
            context,
            amount(asset_out, 10),
            asset_in,
            9,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("reverse request");
        assert_eq!(
            request.clone().validate_route(
                vec![exact_in_leg(&reverse_request, 2, 10, 9, BTreeMap::new(),)],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::AssetDirectionMismatch)
        );
        assert_eq!(
            request.validate_route(vec![valid], NetworkFee::new(asset(9), 100).expect("fee"),),
            Err(ExecutionError::WrongPolicyAsset)
        );
    }

    #[test]
    fn checked_sums_and_fee_limits_fail_closed() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, u64::MAX),
            asset_out,
            1,
            recipient(),
            BTreeMap::from([(asset_in, 2)]),
            100,
        )
        .expect("request");
        let first = exact_in_leg(&request, 1, u64::MAX, 1, BTreeMap::new());
        let second = exact_in_leg(&request, 2, 1, 1, BTreeMap::new());
        assert_eq!(
            request.clone().validate_route(
                vec![first, second],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::AmountOverflow)
        );

        let fee_leg = exact_in_leg(&request, 3, u64::MAX, 1, BTreeMap::from([(asset_in, 3)]));
        assert!(matches!(
            request.validate_route(
                vec![fee_leg],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::VenueFeeExceeded { .. })
        ));
    }

    #[test]
    fn exact_in_empty_fee_input_and_output_bounds_fail_closed() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 100),
            asset_out,
            95,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("request");
        assert_eq!(
            request.clone().validate_route(
                Vec::new(),
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::NoLegs)
        );
        assert_eq!(
            request.clone().validate_route(
                vec![exact_in_leg(&request, 1, 99, 95, BTreeMap::new())],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::ExactInputMismatch {
                expected: 100,
                actual: 99,
            })
        );
        assert_eq!(
            request.clone().validate_route(
                vec![exact_in_leg(&request, 1, 100, 94, BTreeMap::new())],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            ),
            Err(ExecutionError::MinimumOutputNotMet {
                minimum: 95,
                actual: 94,
            })
        );
        assert_eq!(
            request.clone().validate_route(
                vec![exact_in_leg(&request, 1, 100, 95, BTreeMap::new())],
                NetworkFee::new(context.policy_asset, 101).expect("fee"),
            ),
            Err(ExecutionError::NetworkFeeExceeded {
                maximum: 100,
                actual: 101,
            })
        );

        let route = request
            .clone()
            .validate_route(
                vec![exact_in_leg(&request, 1, 100, 95, BTreeMap::new())],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            )
            .expect("route");
        let wrong_wallet = TransactionContribution::new(
            vec![input_spec(1, 10, context.policy_asset, 1_000)],
            Vec::new(),
            LockTimeConstraint::Unconstrained,
        );
        assert!(matches!(
            route.compose(CompositionLimits::default(), wrong_wallet),
            Err(RouteCompositionError::PayerBlinderNotInWallet { .. })
        ));
    }

    #[test]
    fn payer_blinder_must_not_be_claimed_by_another_venue_leg() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 100),
            asset_out,
            95,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("request");
        let first = exact_in_leg(&request, 1, 40, 40, BTreeMap::new());
        let second_payer = OutPoint::new(Txid::from_byte_array([21; 32]), 0);
        let second_request = request
            .exact_in_leg(LegId::new(2), 60, second_payer)
            .expect("second allocation");
        let second = second_request
            .authorize(
                ProposedLeg::new(
                    ExactExecution::new(amount(asset_in, 60), amount(asset_out, 55))
                        .expect("execution"),
                    BTreeMap::new(),
                    TransactionContribution::new(
                        vec![input_spec(1, 20, asset_out, 55)],
                        vec![
                            OutputSpec::confidential(
                                OutputId::new(1),
                                asset_in,
                                60,
                                script(72),
                                blinding_key(72),
                                BlinderRef::External(second_payer),
                            ),
                            OutputSpec::confidential(
                                OutputId::new(2),
                                asset_out,
                                55,
                                recipient().script_pubkey().clone(),
                                recipient().blinding_key(),
                                BlinderRef::Local(InputId::new(1)),
                            ),
                        ],
                        LockTimeConstraint::Unconstrained,
                    ),
                    OutputId::new(1),
                    OutputId::new(2),
                )
                .expect("proposal"),
            )
            .expect("prepared leg");
        let route = request
            .validate_route(
                vec![first, second],
                NetworkFee::new(context.policy_asset, 100).expect("fee"),
            )
            .expect("route");
        let wallet = TransactionContribution::new(
            vec![
                input_spec(1, 20, asset_in, 40),
                InputSpec::new(
                    InputId::new(2),
                    second_payer,
                    TxOut {
                        asset: Asset::Explicit(asset_in),
                        value: Value::Explicit(60),
                        nonce: Nonce::Null,
                        script_pubkey: script(21),
                        witness: TxOutWitness::default(),
                    },
                    InputSequence::Final,
                ),
            ],
            Vec::new(),
            LockTimeConstraint::Unconstrained,
        );

        assert_eq!(
            route
                .compose(CompositionLimits::default(), wallet)
                .expect_err("cross-leg payer-input claim must fail"),
            RouteCompositionError::PayerBlinderClaimedByVenue {
                payer_leg: LegId::new(1),
                claiming_leg: LegId::new(2),
                outpoint: payer_outpoint(),
            }
        );
    }

    #[test]
    fn proposal_claims_bind_amount_recipient_and_blinding_roles() {
        let context = test_context(10);
        let asset_in = asset(2);
        let asset_out = asset(3);
        let request = ExecutionRequest::exact_in(
            context,
            amount(asset_in, 10),
            asset_out,
            9,
            recipient(),
            BTreeMap::new(),
            100,
        )
        .expect("request");

        let wrong_amount_request = request
            .exact_in_leg(LegId::new(1), 10, payer_outpoint())
            .expect("leg request");
        let wrong_amount = ProposedLeg::new(
            ExactExecution::new(amount(asset_in, 10), amount(asset_out, 9)).expect("execution"),
            BTreeMap::new(),
            TransactionContribution::new(
                vec![input_spec(1, 31, asset_out, 9)],
                vec![
                    OutputSpec::confidential(
                        OutputId::new(1),
                        asset_in,
                        11,
                        script(71),
                        blinding_key(71),
                        BlinderRef::External(payer_outpoint()),
                    ),
                    OutputSpec::confidential(
                        OutputId::new(2),
                        asset_out,
                        9,
                        recipient().script_pubkey().clone(),
                        recipient().blinding_key(),
                        BlinderRef::Local(InputId::new(1)),
                    ),
                ],
                LockTimeConstraint::Unconstrained,
            ),
            OutputId::new(1),
            OutputId::new(2),
        )
        .expect("proposal");
        assert_eq!(
            wrong_amount_request.authorize(wrong_amount),
            Err(ExecutionError::EconomicOutputMismatch(OutputId::new(1)))
        );

        let wrong_recipient_request = request
            .exact_in_leg(LegId::new(2), 10, payer_outpoint())
            .expect("leg request");
        let mut wrong_recipient = proposed_leg(2, asset_in, 10, asset_out, 9, BTreeMap::new());
        wrong_recipient.contribution = TransactionContribution::new(
            vec![input_spec(1, 32, asset_out, 9)],
            vec![
                OutputSpec::confidential(
                    OutputId::new(1),
                    asset_in,
                    10,
                    script(72),
                    blinding_key(72),
                    BlinderRef::External(payer_outpoint()),
                ),
                OutputSpec::confidential(
                    OutputId::new(2),
                    asset_out,
                    9,
                    script(91),
                    recipient().blinding_key(),
                    BlinderRef::Local(InputId::new(1)),
                ),
            ],
            LockTimeConstraint::Unconstrained,
        );
        assert_eq!(
            wrong_recipient_request.authorize(wrong_recipient),
            Err(ExecutionError::RecipientMismatch)
        );

        let extra_external_request = request
            .exact_in_leg(LegId::new(3), 10, payer_outpoint())
            .expect("leg request");
        let mut extra_external = proposed_leg(3, asset_in, 10, asset_out, 9, BTreeMap::new());
        extra_external.contribution = TransactionContribution::new(
            extra_external.contribution.inputs().to_vec(),
            [
                extra_external.contribution.outputs().to_vec(),
                vec![OutputSpec::confidential(
                    OutputId::new(3),
                    asset_out,
                    1,
                    script(92),
                    blinding_key(92),
                    BlinderRef::External(payer_outpoint()),
                )],
            ]
            .concat(),
            LockTimeConstraint::Unconstrained,
        );
        assert_eq!(
            extra_external_request.authorize(extra_external),
            Err(ExecutionError::UnauthorizedExternalBlinder)
        );

        let allocation_mismatch_request = request
            .exact_in_leg(LegId::new(4), 10, payer_outpoint())
            .expect("leg request");
        assert_eq!(
            allocation_mismatch_request.authorize(proposed_leg(
                4,
                asset_in,
                9,
                asset_out,
                9,
                BTreeMap::new(),
            )),
            Err(ExecutionError::LegExactInputMismatch)
        );

        let reused_output_request = request
            .exact_in_leg(LegId::new(5), 10, payer_outpoint())
            .expect("leg request");
        let mut reused_output = proposed_leg(5, asset_in, 10, asset_out, 9, BTreeMap::new());
        reused_output.receive_output = reused_output.payment_output;
        assert_eq!(
            reused_output_request.authorize(reused_output),
            Err(ExecutionError::ReusedEconomicOutput)
        );

        let explicit_payment_request = request
            .exact_in_leg(LegId::new(6), 10, payer_outpoint())
            .expect("leg request");
        let explicit_payment = ProposedLeg::new(
            ExactExecution::new(amount(asset_in, 10), amount(asset_out, 9)).expect("execution"),
            BTreeMap::new(),
            TransactionContribution::new(
                vec![input_spec(1, 36, asset_out, 9)],
                vec![
                    OutputSpec::explicit(OutputId::new(1), asset_in, 10, script(76)),
                    OutputSpec::confidential(
                        OutputId::new(2),
                        asset_out,
                        9,
                        recipient().script_pubkey().clone(),
                        recipient().blinding_key(),
                        BlinderRef::Local(InputId::new(1)),
                    ),
                ],
                LockTimeConstraint::Unconstrained,
            ),
            OutputId::new(1),
            OutputId::new(2),
        )
        .expect("proposal");
        assert_eq!(
            explicit_payment_request.authorize(explicit_payment),
            Err(ExecutionError::EconomicOutputNotConfidential)
        );

        let missing_receive_blinder_request = request
            .exact_in_leg(LegId::new(7), 10, payer_outpoint())
            .expect("leg request");
        let mut missing_receive_blinder =
            proposed_leg(7, asset_in, 10, asset_out, 9, BTreeMap::new());
        missing_receive_blinder.contribution = TransactionContribution::new(
            missing_receive_blinder.contribution.inputs().to_vec(),
            vec![
                missing_receive_blinder.contribution.outputs()[0].clone(),
                OutputSpec::confidential(
                    OutputId::new(2),
                    asset_out,
                    9,
                    recipient().script_pubkey().clone(),
                    recipient().blinding_key(),
                    BlinderRef::Local(InputId::new(99)),
                ),
            ],
            LockTimeConstraint::Unconstrained,
        );
        assert_eq!(
            missing_receive_blinder_request.authorize(missing_receive_blinder),
            Err(ExecutionError::ReceiveOutputNotVenueBlinded)
        );

        let payer_claim_request = request
            .exact_in_leg(LegId::new(8), 10, payer_outpoint())
            .expect("leg request");
        let mut payer_claim = proposed_leg(8, asset_in, 10, asset_out, 9, BTreeMap::new());
        payer_claim.contribution = TransactionContribution::new(
            vec![InputSpec::new(
                InputId::new(1),
                payer_outpoint(),
                TxOut {
                    asset: Asset::Explicit(asset_out),
                    value: Value::Explicit(9),
                    nonce: Nonce::Null,
                    script_pubkey: script(20),
                    witness: TxOutWitness::default(),
                },
                InputSequence::Final,
            )],
            payer_claim.contribution.outputs().to_vec(),
            LockTimeConstraint::Unconstrained,
        );
        assert_eq!(
            payer_claim_request.authorize(payer_claim),
            Err(ExecutionError::VenueClaimsPayerInput)
        );
    }
}
