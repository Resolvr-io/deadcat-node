//! RFQ quote normalization into the venue-neutral transaction composer.
//!
//! The signed quote authenticates provider-supplied prevouts and settlement
//! policy; it does not prove those prevouts are canonical or still unspent.
//! Before taker signing, the wallet-facing whole-PSET authorization compares
//! every prevout with an authoritative chain source; revalidate that the exact
//! market observation is still canonical, fresh, and trading; enforce the
//! quote's fee rate/absolute-fee/weight limits; and enforce the v1 provider
//! profile for every wallet input (tree-less P2TR with explicit `SIGHASH_ALL`).
//! The actual blind/sign operation remains behind a caller-owned wallet trait.
//! A clonable [`TradingMarket`] is preparation evidence, never a timeless
//! authorization to sign.

use std::collections::{BTreeMap, BTreeSet};

use deadcat_client::composition::{
    BlinderRef, InputId, InputSequence, InputSpec, LockTimeConstraint, OutputId, OutputSpec,
    TransactionContribution,
};
use deadcat_client::validation::ValidatedContractView;
use deadcat_client::venue::{
    AssetAmount, ComposedRoute, ExactExecution, ExecutionError, LegExecutionKind, LegId,
    LegPreparationRequest, PreparedLeg, ProposedLeg,
};
use deadcat_rfq_rpc::{
    AssetAmountDto, BlinderRoleDto, FirmQuoteDto, FirmQuoteRequestDto, FirmQuoteValidationError,
    FixedBytes33, InputPlacementDto, OutputPlacementDto, QuoteContextDto, QuoteKindDto,
    QuoteOutputRoleDto, QuoteRecipientDto, ReservationStatusDto, SettlementLayoutDto,
    VerifiedFirmQuote,
};
use deadcat_rpc::{ContractParametersView, ContractStateView};
use deadcat_types::{BinaryMarketState, ChainAnchor, ChainIdentity, ContractId, ContractSyncState};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::secp256k1_zkp::{PublicKey, XOnlyPublicKey};
use elements::{AssetId, OutPoint};
use thiserror::Error;

use crate::session::{LiveQuoteReservation, ReservationHandle, ResolvedRfqSettlement};

/// A client-validated, synchronized market that is still open for trading.
///
/// Constructing this capability checks the materialized market state and
/// expiry height. The caller remains responsible for obtaining the underlying
/// [`ValidatedContractView`] from an independently authenticated, sufficiently
/// fresh chain source as documented by `deadcat-client::validation`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TradingMarket {
    chain: ChainIdentity,
    policy_asset: AssetId,
    contract_id: ContractId,
    collateral_asset: AssetId,
    outcome_assets: BTreeSet<AssetId>,
    observed_at: ChainAnchor,
    expiry_height: u32,
}

impl TradingMarket {
    pub fn from_validated(
        view: &ValidatedContractView,
        chain: ChainIdentity,
        policy_asset: AssetId,
    ) -> Result<Self, RfqVenueError> {
        let contract = view.view();
        let observed_at = match contract.sync_state {
            ContractSyncState::Ready { synced_through } => synced_through,
            ContractSyncState::CatchingUp { .. } => return Err(RfqVenueError::MarketNotReady),
        };
        let ContractParametersView::BinaryMarket { params } = contract.parameters;
        let ContractStateView::BinaryMarket { state } = contract.state;
        if !matches!(state, BinaryMarketState::Trading { .. }) {
            return Err(RfqVenueError::MarketNotTrading);
        }
        if observed_at.height >= params.expiry_height {
            return Err(RfqVenueError::MarketExpired {
                validated_height: observed_at.height,
                expiry_height: params.expiry_height,
            });
        }
        Ok(Self {
            chain,
            policy_asset,
            contract_id: contract.contract_id,
            collateral_asset: params.collateral_asset_id,
            outcome_assets: BTreeSet::from([params.yes_token_asset_id, params.no_token_asset_id]),
            observed_at,
            expiry_height: params.expiry_height,
        })
    }

    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn policy_asset(&self) -> AssetId {
        self.policy_asset
    }

    #[must_use]
    pub const fn contract_id(&self) -> ContractId {
        self.contract_id
    }

    #[must_use]
    pub const fn observed_at(&self) -> ChainAnchor {
        self.observed_at
    }

    #[must_use]
    pub const fn expiry_height(&self) -> u32 {
        self.expiry_height
    }

    pub(crate) fn supports_pair(&self, input_asset: AssetId, output_asset: AssetId) -> bool {
        (input_asset == self.collateral_asset && self.outcome_assets.contains(&output_asset))
            || (output_asset == self.collateral_asset && self.outcome_assets.contains(&input_asset))
    }

    pub(crate) fn is_continuation_of(&self, earlier: &Self) -> bool {
        self.chain == earlier.chain
            && self.policy_asset == earlier.policy_asset
            && self.contract_id == earlier.contract_id
            && self.collateral_asset == earlier.collateral_asset
            && self.outcome_assets == earlier.outcome_assets
            && self.expiry_height == earlier.expiry_height
            && self.observed_at.height >= earlier.observed_at.height
            && (self.observed_at.height != earlier.observed_at.height
                || self.observed_at.hash == earlier.observed_at.hash)
    }

    fn authorize_leg(&self, request: &LegPreparationRequest) -> Result<(), RfqVenueError> {
        let context = request.context();
        if context.chain != self.chain
            || context.policy_asset != self.policy_asset
            || context.market != self.contract_id
        {
            return Err(RfqVenueError::MarketMismatch);
        }
        let (input_asset, output_asset) = leg_pair(request.kind());
        if !self.supports_pair(input_asset, output_asset) {
            return Err(RfqVenueError::UnsupportedMarketAsset);
        }
        Ok(())
    }
}

/// Per-leg slippage allocation needed by the RFQ wire request.
///
/// The venue-neutral leg carries the exact allocated side; the router must
/// additionally allocate the opposite-side bound before asking a venue for a
/// quote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteBounds {
    ExactIn { minimum_output: u64 },
    ExactOut { maximum_input: u64 },
}

/// Exact client-created RFQ request retained through quote authorization.
///
/// Keeping this opaque capability separate from the wire DTO prevents a quote
/// for the same allocated side but different slippage or fee bounds from being
/// attached to the wrong route leg.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RfqQuoteIntent {
    leg_id: LegId,
    market: TradingMarket,
    request: FirmQuoteRequestDto,
}

impl RfqQuoteIntent {
    pub fn new(
        leg: &LegPreparationRequest,
        market: &TradingMarket,
        bounds: QuoteBounds,
        maximum_input_asset_venue_fee: u64,
    ) -> Result<Self, RfqVenueError> {
        market.authorize_leg(leg)?;
        let kind = match (leg.kind(), bounds) {
            (
                LegExecutionKind::ExactIn {
                    input,
                    output_asset,
                },
                QuoteBounds::ExactIn { minimum_output },
            ) => {
                if minimum_output == 0 {
                    return Err(RfqVenueError::ZeroQuoteBound);
                }
                if maximum_input_asset_venue_fee > input.amount() {
                    return Err(RfqVenueError::FeeLimitExceedsGrossInput);
                }
                QuoteKindDto::ExactIn {
                    input: asset_amount_to_dto(input),
                    output_asset,
                    minimum_output,
                }
            }
            (
                LegExecutionKind::ExactOut {
                    input_asset,
                    output,
                },
                QuoteBounds::ExactOut { maximum_input },
            ) => {
                if maximum_input == 0 {
                    return Err(RfqVenueError::ZeroQuoteBound);
                }
                if maximum_input_asset_venue_fee > maximum_input {
                    return Err(RfqVenueError::FeeLimitExceedsGrossInput);
                }
                QuoteKindDto::ExactOut {
                    input_asset,
                    maximum_input,
                    output: asset_amount_to_dto(output),
                }
            }
            _ => return Err(RfqVenueError::QuoteBoundsKindMismatch),
        };
        let recipient = leg.recipient();
        let request = FirmQuoteRequestDto {
            context: QuoteContextDto {
                network: leg.context().chain.network,
                genesis_hash: leg.context().chain.genesis_hash,
                market: leg.context().market,
                policy_asset: leg.context().policy_asset,
            },
            kind,
            recipient: QuoteRecipientDto {
                script_pubkey: recipient.script_pubkey().as_bytes().to_vec(),
                blinding_public_key: FixedBytes33::new(recipient.blinding_key().inner.serialize()),
            },
            maximum_input_asset_venue_fee,
        };
        request.validate()?;
        Ok(Self {
            leg_id: leg.id(),
            market: market.clone(),
            request,
        })
    }

    #[must_use]
    pub const fn leg_id(&self) -> LegId {
        self.leg_id
    }

    #[must_use]
    pub const fn market(&self) -> &TradingMarket {
        &self.market
    }

    #[must_use]
    pub const fn request(&self) -> &FirmQuoteRequestDto {
        &self.request
    }
}

/// A client-authorized RFQ leg paired with the protocol evidence needed for
/// collaborative settlement after global route composition.
#[derive(Clone, Debug)]
pub struct PreparedRfqLeg {
    leg: PreparedLeg,
    binding: RfqLegBinding,
}

impl PreparedRfqLeg {
    pub fn prepare(
        request: LegPreparationRequest,
        intent: &RfqQuoteIntent,
        reservation: &LiveQuoteReservation,
    ) -> Result<Self, RfqVenueError> {
        intent.market.authorize_leg(&request)?;
        if intent.leg_id != request.id() {
            return Err(RfqVenueError::QuoteIntentLegMismatch);
        }
        let leg_id = request.id();
        let payer_blinder = request.payer_blinder();
        // Keep the caller's live reservation available for the subsequent
        // provider-blinding and execute calls. The binding retains a downgraded
        // authenticity capability for durable evidence and layout resolution.
        let handle = *reservation.handle();
        let initial_status = reservation.status().clone();
        let verified_quote = reservation.quote().verified().clone();
        let quote = verified_quote.quote().clone();
        if quote.request != intent.request {
            return Err(RfqVenueError::QuoteIntentMismatch);
        }
        validate_quote_request_for_leg(&quote, &request)?;

        let mut input_ids = Vec::with_capacity(quote.inputs.len());
        let mut inputs = Vec::with_capacity(quote.inputs.len());
        for input in &quote.inputs {
            let local_id = InputId::new(u64::from(input.id));
            input_ids.push((input.id, local_id));
            let internal_key = XOnlyPublicKey::from_slice(&input.internal_key.to_bytes())
                .map_err(|_| RfqVenueError::InvalidProviderInternalKey)?;
            inputs.push(InputSpec::tree_less_p2tr_sighash_all(
                local_id,
                input.outpoint,
                input.witness_utxo.to_txout()?,
                InputSequence::Final,
                internal_key,
            ));
        }

        let mut output_ids = Vec::with_capacity(quote.outputs.len());
        let mut outputs = Vec::with_capacity(quote.outputs.len());
        let mut payment_output = None;
        let mut receive_output = None;
        for output in &quote.outputs {
            let local_id = OutputId::new(u64::from(output.id));
            output_ids.push((output.id, local_id));
            let blinding_key =
                PublicKey::from_slice(&output.destination.blinding_public_key.to_bytes())
                    .map(BitcoinPublicKey::new)
                    .map_err(|_| RfqVenueError::InvalidBlindingKey)?;
            let blinder = match output.blinder {
                BlinderRoleDto::TakerPaymentInput => BlinderRef::External(payer_blinder),
                BlinderRoleDto::ProviderInput { quote_input_id } => {
                    BlinderRef::Local(InputId::new(u64::from(quote_input_id)))
                }
            };
            outputs.push(OutputSpec::confidential(
                local_id,
                output.asset,
                output.amount,
                output.destination.script_pubkey.clone().into(),
                blinding_key,
                blinder,
            ));
            match output.role {
                QuoteOutputRoleDto::ProviderPayment => payment_output = Some(local_id),
                QuoteOutputRoleDto::TakerReceive => receive_output = Some(local_id),
                QuoteOutputRoleDto::ProviderChange => {}
            }
        }
        let payment_output = payment_output.ok_or(RfqVenueError::MissingPaymentOutput)?;
        let receive_output = receive_output.ok_or(RfqVenueError::MissingReceiveOutput)?;
        let contribution =
            TransactionContribution::new(inputs, outputs, LockTimeConstraint::Unconstrained);
        let execution = ExactExecution::new(
            AssetAmount::new(quote.execution.input.asset, quote.execution.input.amount)?,
            AssetAmount::new(quote.execution.output.asset, quote.execution.output.amount)?,
        )?;
        let mut venue_fees = BTreeMap::new();
        if quote.execution.input_asset_venue_fee != 0 {
            venue_fees.insert(
                quote.execution.input.asset,
                quote.execution.input_asset_venue_fee,
            );
        }
        let proposal = ProposedLeg::new(
            execution,
            venue_fees,
            contribution,
            payment_output,
            receive_output,
        )?;
        let leg = request.authorize(proposal)?;
        Ok(Self {
            leg: leg.clone(),
            binding: RfqLegBinding {
                leg_id,
                market: intent.market.clone(),
                payer_blinder,
                prepared_leg: leg,
                input_ids,
                output_ids,
                handle,
                initial_status,
                verified_quote,
            },
        })
    }

    #[must_use]
    pub const fn leg(&self) -> &PreparedLeg {
        &self.leg
    }

    #[must_use]
    pub const fn binding(&self) -> &RfqLegBinding {
        &self.binding
    }

    #[must_use]
    pub fn into_parts(self) -> (PreparedLeg, RfqLegBinding) {
        (self.leg, self.binding)
    }
}

/// Durable RFQ evidence and symbolic mappings retained after `PreparedLeg` is
/// consumed by route validation.
#[derive(Clone, Debug)]
pub struct RfqLegBinding {
    leg_id: LegId,
    market: TradingMarket,
    payer_blinder: OutPoint,
    prepared_leg: PreparedLeg,
    input_ids: Vec<(u16, InputId)>,
    output_ids: Vec<(u16, OutputId)>,
    handle: ReservationHandle,
    initial_status: ReservationStatusDto,
    verified_quote: VerifiedFirmQuote,
}

impl RfqLegBinding {
    #[must_use]
    pub const fn leg_id(&self) -> LegId {
        self.leg_id
    }

    /// Exact validated market capability used to create and authorize this
    /// quote intent. Final settlement refreshes it, but never substitutes a
    /// separately supplied same-contract capability.
    #[must_use]
    pub const fn market(&self) -> &TradingMarket {
        &self.market
    }

    #[must_use]
    pub const fn handle(&self) -> &ReservationHandle {
        &self.handle
    }

    #[must_use]
    pub const fn initial_status(&self) -> &ReservationStatusDto {
        &self.initial_status
    }

    #[must_use]
    pub const fn verified_quote(&self) -> &VerifiedFirmQuote {
        &self.verified_quote
    }

    /// Resolve quote-local IDs against the final multi-contribution layout.
    /// The exact authorized contribution is rechecked before any indices are
    /// returned, preventing a same-leg-ID substitution from reusing evidence.
    pub fn resolve(&self, route: &ComposedRoute) -> Result<ResolvedRfqSettlement, RfqVenueError> {
        let prepared = route
            .authorization()
            .legs()
            .iter()
            .find(|leg| leg.id() == self.leg_id)
            .ok_or(RfqVenueError::RouteLegMissing)?;
        if prepared != &self.prepared_leg {
            return Err(RfqVenueError::RouteLegMismatch);
        }
        let handle = route
            .layout()
            .leg(self.leg_id)
            .ok_or(RfqVenueError::RouteLegMissing)?;
        let composition = route.transaction().layout();
        let taker_payment_input = to_u16(
            composition
                .outpoint_index(self.payer_blinder)
                .ok_or(RfqVenueError::PayerInputMissing)?,
        )?;
        let provider_inputs = self
            .input_ids
            .iter()
            .map(|&(quote_input_id, local_id)| {
                Ok(InputPlacementDto {
                    quote_input_id,
                    transaction_index: to_u16(
                        composition
                            .input_index(handle, local_id)
                            .ok_or(RfqVenueError::ProviderInputMissing(quote_input_id))?,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, RfqVenueError>>()?;
        let quote_outputs = self
            .output_ids
            .iter()
            .map(|&(quote_output_id, local_id)| {
                Ok(OutputPlacementDto {
                    quote_output_id,
                    transaction_index: to_u16(
                        composition
                            .output_index(handle, local_id)
                            .ok_or(RfqVenueError::QuoteOutputMissing(quote_output_id))?,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, RfqVenueError>>()?;
        let layout = SettlementLayoutDto {
            taker_payment_input,
            provider_inputs,
            quote_outputs,
        };
        layout.validate_for_quote(self.verified_quote.quote())?;
        Ok(ResolvedRfqSettlement::new(self.handle, layout))
    }
}

fn validate_quote_request_for_leg(
    quote: &FirmQuoteDto,
    leg: &LegPreparationRequest,
) -> Result<(), RfqVenueError> {
    let context = leg.context();
    if quote.request.context
        != (QuoteContextDto {
            network: context.chain.network,
            genesis_hash: context.chain.genesis_hash,
            market: context.market,
            policy_asset: context.policy_asset,
        })
    {
        return Err(RfqVenueError::QuoteContextMismatch);
    }
    let recipient = leg.recipient();
    if quote.request.recipient.script_pubkey != recipient.script_pubkey().as_bytes()
        || quote.request.recipient.blinding_public_key.to_bytes()
            != recipient.blinding_key().inner.serialize()
    {
        return Err(RfqVenueError::QuoteRecipientMismatch);
    }
    let kind_matches = match (leg.kind(), quote.request.kind) {
        (
            LegExecutionKind::ExactIn {
                input,
                output_asset,
            },
            QuoteKindDto::ExactIn {
                input: quoted_input,
                output_asset: quoted_output_asset,
                ..
            },
        ) => asset_amount_to_dto(input) == quoted_input && output_asset == quoted_output_asset,
        (
            LegExecutionKind::ExactOut {
                input_asset,
                output,
            },
            QuoteKindDto::ExactOut {
                input_asset: quoted_input_asset,
                output: quoted_output,
                ..
            },
        ) => input_asset == quoted_input_asset && asset_amount_to_dto(output) == quoted_output,
        _ => false,
    };
    if !kind_matches {
        return Err(RfqVenueError::QuoteAllocationMismatch);
    }
    Ok(())
}

const fn asset_amount_to_dto(value: AssetAmount) -> AssetAmountDto {
    AssetAmountDto {
        asset: value.asset(),
        amount: value.amount(),
    }
}

const fn leg_pair(kind: LegExecutionKind) -> (AssetId, AssetId) {
    match kind {
        LegExecutionKind::ExactIn {
            input,
            output_asset,
        } => (input.asset(), output_asset),
        LegExecutionKind::ExactOut {
            input_asset,
            output,
        } => (input_asset, output.asset()),
    }
}

fn to_u16(index: usize) -> Result<u16, RfqVenueError> {
    u16::try_from(index).map_err(|_| RfqVenueError::LayoutIndexOverflow(index))
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RfqVenueError {
    #[error("the validated market has not caught up to its authenticated snapshot")]
    MarketNotReady,
    #[error("the validated market is no longer trading")]
    MarketNotTrading,
    #[error("the market expired at height {expiry_height}, validated at {validated_height}")]
    MarketExpired {
        validated_height: u32,
        expiry_height: u32,
    },
    #[error("the RFQ leg names a different market")]
    MarketMismatch,
    #[error("the RFQ pair contains an asset outside the validated market")]
    UnsupportedMarketAsset,
    #[error("the RFQ quote bound uses the wrong exact-in/exact-out mode")]
    QuoteBoundsKindMismatch,
    #[error("the RFQ quote bound must be positive")]
    ZeroQuoteBound,
    #[error("the RFQ venue-fee limit exceeds the leg's gross input limit")]
    FeeLimitExceedsGrossInput,
    #[error("the live quote targets a different chain, market, or policy asset")]
    QuoteContextMismatch,
    #[error("the live quote targets a different recipient")]
    QuoteRecipientMismatch,
    #[error("the live quote does not match the client-allocated side of the leg")]
    QuoteAllocationMismatch,
    #[error("the RFQ quote intent belongs to a different route leg")]
    QuoteIntentLegMismatch,
    #[error("the authenticated quote differs from the exact client-created RFQ request")]
    QuoteIntentMismatch,
    #[error("the quote contains an invalid recipient blinding key")]
    InvalidBlindingKey,
    #[error("the quote contains an invalid provider Taproot internal key")]
    InvalidProviderInternalKey,
    #[error("the quote has no provider-payment output")]
    MissingPaymentOutput,
    #[error("the quote has no taker-receive output")]
    MissingReceiveOutput,
    #[error("the composed route does not contain the bound RFQ leg")]
    RouteLegMissing,
    #[error("the composed route substituted a different contribution for the bound RFQ leg")]
    RouteLegMismatch,
    #[error("the composed route does not contain the taker payment input")]
    PayerInputMissing,
    #[error("the composed route is missing RFQ provider input {0}")]
    ProviderInputMissing(u16),
    #[error("the composed route is missing RFQ quote output {0}")]
    QuoteOutputMissing(u16),
    #[error("global settlement index {0} does not fit the RFQ wire format")]
    LayoutIndexOverflow(usize),
    #[error(transparent)]
    Quote(#[from] FirmQuoteValidationError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
}

#[cfg(test)]
mod tests {
    use deadcat_client::validation::validate_contract_view;
    use deadcat_client::venue::{ConfidentialRecipient, ExecutionRequest, LegId, VenueContext};
    use deadcat_contracts::binary_market::BinaryMarketSlot;
    use deadcat_rpc::{ContractView, LiveOutpoint};
    use deadcat_types::{BinaryMarketParams, ChainPosition, ContractKind, LiquidNetwork};
    use elements::bitcoin::PublicKey as BitcoinPublicKey;
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{BlockHash, Script, Txid};

    use super::*;

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("test asset")
    }

    fn params() -> BinaryMarketParams {
        let secret = SecretKey::from_slice(&[0x31; 32]).expect("test oracle key");
        let keypair = elements::secp256k1_zkp::Keypair::from_secret_key(&Secp256k1::new(), &secret);
        BinaryMarketParams {
            oracle_public_key: keypair.x_only_public_key().0.serialize(),
            collateral_asset_id: asset(1),
            yes_token_asset_id: asset(2),
            no_token_asset_id: asset(3),
            yes_reissuance_token_id: asset(4),
            no_reissuance_token_id: asset(5),
            base_payout: 100,
            expiry_height: 500,
        }
    }

    fn validated_market() -> ValidatedContractView {
        let params = params();
        let creation_txid = Txid::from_byte_array([0x21; 32]);
        let view = ContractView {
            contract_id: ContractId::new(OutPoint::new(creation_txid, 0)),
            kind: ContractKind::BinaryMarketV1,
            sync_state: ContractSyncState::Ready {
                synced_through: ChainAnchor {
                    height: 10,
                    hash: BlockHash::from_byte_array([0x22; 32]),
                },
            },
            creation_position: ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
            parameters: ContractParametersView::BinaryMarket { params },
            state: ContractStateView::BinaryMarket {
                state: BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
            },
            live_outpoints: vec![
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantYesRt as u8,
                    outpoint: OutPoint::new(creation_txid, 0),
                },
                LiveOutpoint {
                    role: BinaryMarketSlot::DormantNoRt as u8,
                    outpoint: OutPoint::new(creation_txid, 1),
                },
            ],
        };
        validate_contract_view(&view).expect("valid market view")
    }

    fn chain() -> ChainIdentity {
        ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: BlockHash::from_byte_array([0x23; 32]),
        }
    }

    fn recipient() -> ConfidentialRecipient {
        let public = PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[0x24; 32]).expect("test blinding key"),
        );
        ConfidentialRecipient::new(Script::from(vec![0x51]), BitcoinPublicKey::new(public))
            .expect("valid recipient")
    }

    fn exact_in_leg(
        context: VenueContext,
        input_asset: AssetId,
        output_asset: AssetId,
    ) -> LegPreparationRequest {
        ExecutionRequest::exact_in(
            context,
            AssetAmount::new(input_asset, 100).expect("input"),
            output_asset,
            80,
            recipient(),
            BTreeMap::from([(input_asset, 5)]),
            1_000,
        )
        .expect("request")
        .exact_in_leg(
            LegId::new(7),
            100,
            OutPoint::new(Txid::from_byte_array([0x25; 32]), 0),
        )
        .expect("leg")
    }

    #[test]
    fn market_capability_binds_chain_and_launch_pairs() {
        let view = validated_market();
        let params = params();
        let policy_asset = asset(9);
        let market =
            TradingMarket::from_validated(&view, chain(), policy_asset).expect("trading market");
        let context = VenueContext {
            chain: chain(),
            market: view.contract_id(),
            policy_asset,
        };
        let supported = exact_in_leg(
            context,
            params.collateral_asset_id,
            params.yes_token_asset_id,
        );
        market.authorize_leg(&supported).expect("launch pair");
        let supported_reverse = exact_in_leg(
            context,
            params.yes_token_asset_id,
            params.collateral_asset_id,
        );
        market
            .authorize_leg(&supported_reverse)
            .expect("reverse launch pair");

        let unsupported =
            exact_in_leg(context, params.yes_token_asset_id, params.no_token_asset_id);
        assert_eq!(
            market.authorize_leg(&unsupported),
            Err(RfqVenueError::UnsupportedMarketAsset)
        );

        let wrong_chain = exact_in_leg(
            VenueContext {
                chain: ChainIdentity {
                    genesis_hash: BlockHash::from_byte_array([0x26; 32]),
                    ..chain()
                },
                ..context
            },
            params.collateral_asset_id,
            params.yes_token_asset_id,
        );
        assert_eq!(
            market.authorize_leg(&wrong_chain),
            Err(RfqVenueError::MarketMismatch)
        );
    }

    #[test]
    fn quote_intent_retains_exact_slippage_and_fee_bounds() {
        let view = validated_market();
        let params = params();
        let policy_asset = asset(9);
        let market =
            TradingMarket::from_validated(&view, chain(), policy_asset).expect("trading market");
        let leg = exact_in_leg(
            VenueContext {
                chain: chain(),
                market: view.contract_id(),
                policy_asset,
            },
            params.collateral_asset_id,
            params.yes_token_asset_id,
        );
        let first = RfqQuoteIntent::new(
            &leg,
            &market,
            QuoteBounds::ExactIn { minimum_output: 80 },
            5,
        )
        .expect("intent");
        let different_slippage = RfqQuoteIntent::new(
            &leg,
            &market,
            QuoteBounds::ExactIn { minimum_output: 81 },
            5,
        )
        .expect("intent");
        let different_fee = RfqQuoteIntent::new(
            &leg,
            &market,
            QuoteBounds::ExactIn { minimum_output: 80 },
            4,
        )
        .expect("intent");
        assert_ne!(first.request(), different_slippage.request());
        assert_ne!(first.request(), different_fee.request());
        assert!(matches!(
            RfqQuoteIntent::new(
                &leg,
                &market,
                QuoteBounds::ExactOut { maximum_input: 100 },
                5,
            ),
            Err(RfqVenueError::QuoteBoundsKindMismatch)
        ));
        assert!(matches!(
            RfqQuoteIntent::new(
                &leg,
                &market,
                QuoteBounds::ExactIn { minimum_output: 80 },
                101,
            ),
            Err(RfqVenueError::FeeLimitExceedsGrossInput)
        ));
    }

    #[test]
    fn exact_out_intent_retains_allocated_output_and_maximum_input() {
        let view = validated_market();
        let params = params();
        let policy_asset = asset(9);
        let market =
            TradingMarket::from_validated(&view, chain(), policy_asset).expect("trading market");
        let context = VenueContext {
            chain: chain(),
            market: view.contract_id(),
            policy_asset,
        };
        let request = ExecutionRequest::exact_out(
            context,
            params.collateral_asset_id,
            120,
            AssetAmount::new(params.yes_token_asset_id, 180).expect("output"),
            recipient(),
            BTreeMap::from([(params.collateral_asset_id, 10)]),
            1_000,
        )
        .expect("request");
        let leg = request
            .exact_out_leg(
                LegId::new(8),
                180,
                OutPoint::new(Txid::from_byte_array([0x27; 32]), 0),
            )
            .expect("leg");
        let intent = RfqQuoteIntent::new(
            &leg,
            &market,
            QuoteBounds::ExactOut { maximum_input: 120 },
            10,
        )
        .expect("intent");
        assert_eq!(
            intent.request().kind,
            QuoteKindDto::ExactOut {
                input_asset: params.collateral_asset_id,
                maximum_input: 120,
                output: AssetAmountDto {
                    asset: params.yes_token_asset_id,
                    amount: 180,
                },
            }
        );
    }
}
