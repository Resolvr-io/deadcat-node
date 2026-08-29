use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use deadcat_client::composition::CompositionLimits;
use deadcat_client::venue::{AssetAmount, ExecutionError, ExecutionRequest, LegId, VenueContext};
use deadcat_rfq_client::{
    AuthenticatedExecutionStatus, ExecuteError, ExecutionAttemptDigest, ExecutionJournal,
    ExecutionJournalError, ExecutionJournalKey, ExecutionJournalObservation, JournaledExecution,
    PreparedRfqLeg, QuoteBounds, QuoteReplay, RfqQuoteIntent, RfqSession, RfqVenueError,
    SessionError, TakerAuthorizationError, TakerSettlementCoordinator, TakerSettlementPlan,
    TakerSettlementPlanError, TakerSettlementSource,
};
use deadcat_rfq_rpc::{IdempotencyKeyDto, ReservationStatusDto, SettlementPset, VerifiedFirmQuote};
use deadcat_rfq_wallet::{
    DurablyArmedTakerFunding, PersistentRfqWallet, TakerFundingError, TakerFundingLease,
    TakerFundingLimits, TakerFundingPool, TakerWalletIdentity,
};
use elements::AssetId;
use rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::fee::{FeePlanningError, plan_network_fee};
use crate::recovery::{
    FundingRecoveryError, execution_taker_input_outpoints, load_funding_recovery,
    validate_execution_identity,
};
use crate::source::TakerInventorySource;

/// Runtime policy for one-provider launch routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RfqTakerConfig {
    funding_limits: TakerFundingLimits,
    composition_limits: CompositionLimits,
    minimum_sats_per_kvb: u64,
    leg_id: LegId,
}

impl RfqTakerConfig {
    pub fn new(
        funding_limits: TakerFundingLimits,
        composition_limits: CompositionLimits,
        minimum_sats_per_kvb: u64,
    ) -> Result<Self, RfqTakerError> {
        if minimum_sats_per_kvb == 0 {
            return Err(RfqTakerError::InvalidConfiguration(
                "minimum fee rate must be nonzero",
            ));
        }
        Ok(Self {
            funding_limits,
            composition_limits,
            minimum_sats_per_kvb,
            leg_id: LegId::new(1),
        })
    }

    #[must_use]
    pub const fn funding_limits(self) -> TakerFundingLimits {
        self.funding_limits
    }

    #[must_use]
    pub const fn composition_limits(self) -> CompositionLimits {
        self.composition_limits
    }

    #[must_use]
    pub const fn minimum_sats_per_kvb(self) -> u64 {
        self.minimum_sats_per_kvb
    }
}

/// User-level exact-input RFQ intent, before a fresh wallet recipient exists.
///
/// `input` is the taker's gross trade-asset debit and already includes any
/// input-asset venue fee. The policy-asset network fee is separate and is paid
/// in addition to this amount, subject to `maximum_network_fee`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactInRfqTrade {
    context: VenueContext,
    input: AssetAmount,
    output_asset: AssetId,
    minimum_output: u64,
    maximum_input_asset_venue_fee: u64,
    maximum_network_fee: u64,
}

impl ExactInRfqTrade {
    #[must_use]
    pub const fn new(
        context: VenueContext,
        input: AssetAmount,
        output_asset: AssetId,
        minimum_output: u64,
        maximum_input_asset_venue_fee: u64,
        maximum_network_fee: u64,
    ) -> Self {
        Self {
            context,
            input,
            output_asset,
            minimum_output,
            maximum_input_asset_venue_fee,
            maximum_network_fee,
        }
    }
}

/// User-level exact-output RFQ intent, before a fresh wallet recipient exists.
///
/// `maximum_input` bounds the taker's gross trade-asset debit, including any
/// input-asset venue fee. The policy-asset network fee is separate and is paid
/// in addition to this amount, subject to `maximum_network_fee`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactOutRfqTrade {
    context: VenueContext,
    input_asset: AssetId,
    maximum_input: u64,
    output: AssetAmount,
    maximum_input_asset_venue_fee: u64,
    maximum_network_fee: u64,
}

impl ExactOutRfqTrade {
    #[must_use]
    pub const fn new(
        context: VenueContext,
        input_asset: AssetId,
        maximum_input: u64,
        output: AssetAmount,
        maximum_input_asset_venue_fee: u64,
        maximum_network_fee: u64,
    ) -> Self {
        Self {
            context,
            input_asset,
            maximum_input,
            output,
            maximum_input_asset_venue_fee,
            maximum_network_fee,
        }
    }
}

enum RequestedTrade {
    ExactIn(ExactInRfqTrade),
    ExactOut(ExactOutRfqTrade),
}

/// Opaque process-local identity for one runtime and its funding pool.
///
/// Pointer identity is deliberate: a prepared trade owns a lease issued by one
/// particular pool, so an otherwise equivalent runtime must not be allowed to
/// authorize or dispatch it.
struct RuntimeProvenance {
    identity: TakerWalletIdentity,
}

impl RuntimeProvenance {
    fn require_session(&self, session: &RfqSession) -> Result<(), RfqTakerError> {
        let actual = *session.client_endpoint_id().as_bytes();
        let expected = self.identity.owner();
        if actual != expected {
            return Err(RfqTakerError::SessionClientIdentityMismatch { expected, actual });
        }
        Ok(())
    }
}

/// A wallet-funded request whose complete worst-case input set is leased before
/// any quote request can be sent.
pub struct ReservedRfqTrade<R> {
    provenance: Arc<RuntimeProvenance>,
    lease: TakerFundingLease<R>,
    request: ExecutionRequest,
    quote_intent: RfqQuoteIntent,
    leg: deadcat_client::venue::LegPreparationRequest,
}

impl<R> ReservedRfqTrade<R> {
    #[must_use]
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }

    #[must_use]
    pub const fn quote_intent(&self) -> &RfqQuoteIntent {
        &self.quote_intent
    }

    /// Send the exact quote request and retain the lease while the caller
    /// reviews the authenticated response.
    pub async fn request_quote(
        self,
        session: &RfqSession,
        idempotency_key: IdempotencyKeyDto,
    ) -> Result<PreparedRfqTrade<R>, RfqTakerError> {
        self.provenance.require_session(session)?;
        let replay = session
            .quote(idempotency_key, self.quote_intent.request().clone())
            .await?;
        let now_millis = trusted_now_millis().map_err(RfqTakerError::Clock)?;
        self.finish_quote(replay, now_millis)
    }

    /// Deterministic clock injection for acceptance and replay tests.
    pub async fn request_quote_at(
        self,
        session: &RfqSession,
        idempotency_key: IdempotencyKeyDto,
        received_at_millis: u64,
        checked_at_millis: u64,
    ) -> Result<PreparedRfqTrade<R>, RfqTakerError> {
        self.provenance.require_session(session)?;
        let replay = session
            .quote_at(
                idempotency_key,
                self.quote_intent.request().clone(),
                received_at_millis,
            )
            .await?;
        self.finish_quote(replay, checked_at_millis)
    }

    fn finish_quote(
        self,
        replay: QuoteReplay,
        now_millis: u64,
    ) -> Result<PreparedRfqTrade<R>, RfqTakerError> {
        let live = replay.live_at(now_millis)?;
        let prepared = PreparedRfqLeg::prepare(self.leg, &self.quote_intent, &live)?;
        Ok(PreparedRfqTrade {
            provenance: self.provenance,
            lease: self.lease,
            request: self.request,
            replay,
            live,
            prepared,
        })
    }
}

/// Authenticated live quote whose wallet inputs remain exclusively leased.
/// Dropping this value before acceptance releases only the process-local lease;
/// no taker signature or Execute request has yet been produced.
pub struct PreparedRfqTrade<R> {
    provenance: Arc<RuntimeProvenance>,
    lease: TakerFundingLease<R>,
    request: ExecutionRequest,
    replay: QuoteReplay,
    live: deadcat_rfq_client::LiveQuoteReservation,
    prepared: PreparedRfqLeg,
}

impl<R> PreparedRfqTrade<R> {
    #[must_use]
    pub fn quote(&self) -> &VerifiedFirmQuote {
        self.live.quote().verified()
    }

    #[must_use]
    pub const fn request(&self) -> &ExecutionRequest {
        &self.request
    }
}

/// Durable caller handle for exact retry, status, and later broadcast work.
#[derive(Clone, Debug)]
pub struct RfqExecutionHandle {
    journaled: JournaledExecution,
    taker_outpoints: BTreeSet<elements::OutPoint>,
}

impl RfqExecutionHandle {
    #[must_use]
    pub fn key(&self) -> ExecutionJournalKey {
        self.journaled.key()
    }

    #[must_use]
    pub fn attempt(&self) -> ExecutionAttemptDigest {
        self.journaled.attempt().digest()
    }

    #[must_use]
    pub const fn observation(&self) -> &ExecutionJournalObservation {
        self.journaled.observation()
    }

    #[must_use]
    pub fn taker_outpoints(&self) -> &BTreeSet<elements::OutPoint> {
        &self.taker_outpoints
    }
}

struct ArmedRfqTrade {
    journaled: JournaledExecution,
    funding: DurablyArmedTakerFunding,
}

impl ArmedRfqTrade {
    fn handle(&self) -> RfqExecutionHandle {
        RfqExecutionHandle {
            journaled: self.journaled.clone(),
            taker_outpoints: self.funding.outpoints().clone(),
        }
    }
}

/// Fail-closed one-provider taker orchestration core.
///
/// Construction reads the complete execution journal before creating the
/// funding pool. If an arm/promotion/journal-observation durability boundary is
/// ambiguous, readiness is revoked until the process reopens and reconstructs
/// state rather than continuing with possibly incomplete exclusions. The
/// embedding process remains responsible for securely pairing and protecting
/// the wallet and journal files across restarts.
pub struct RfqTakerRuntime<R, J> {
    provenance: Arc<RuntimeProvenance>,
    pool: TakerFundingPool<R>,
    journal: J,
    config: RfqTakerConfig,
    ready: AtomicBool,
}

impl<R, J> RfqTakerRuntime<R, J>
where
    R: RngCore + CryptoRng + Send,
    J: ExecutionJournal,
{
    pub fn from_source<S>(
        wallet: Arc<PersistentRfqWallet<R>>,
        identity: TakerWalletIdentity,
        source: &S,
        journal: J,
        config: RfqTakerConfig,
    ) -> Result<Self, RfqTakerError>
    where
        S: TakerInventorySource + ?Sized,
    {
        // Claim before either external read so a previous runtime cannot arm
        // an attempt between our snapshots and the funding-pool handoff.
        let claim = TakerFundingPool::claim(wallet, identity)?;
        let inventory = source
            .inventory()
            .map_err(|error| RfqTakerError::InventorySource(Box::new(error)))?;
        let recovery = load_funding_recovery(&journal, identity)?;
        let pool = claim.initialize(inventory, recovery.exclusions().clone())?;
        Ok(Self {
            provenance: Arc::new(RuntimeProvenance { identity }),
            pool,
            journal,
            config,
            ready: AtomicBool::new(true),
        })
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn reserve_exact_in(
        &self,
        market: &deadcat_rfq_client::TradingMarket,
        trade: ExactInRfqTrade,
    ) -> Result<ReservedRfqTrade<R>, RfqTakerError> {
        self.reserve(market, RequestedTrade::ExactIn(trade))
    }

    pub fn reserve_exact_out(
        &self,
        market: &deadcat_rfq_client::TradingMarket,
        trade: ExactOutRfqTrade,
    ) -> Result<ReservedRfqTrade<R>, RfqTakerError> {
        self.reserve(market, RequestedTrade::ExactOut(trade))
    }

    fn reserve(
        &self,
        market: &deadcat_rfq_client::TradingMarket,
        trade: RequestedTrade,
    ) -> Result<ReservedRfqTrade<R>, RfqTakerError> {
        self.require_ready()?;
        let receive = self.pool.fresh_receive_destination()?;
        let recipient = receive.recipient()?;
        let (request, bounds, maximum_venue_fee, allocated_amount) = match trade {
            RequestedTrade::ExactIn(trade) => {
                let mut fees = BTreeMap::new();
                if trade.maximum_input_asset_venue_fee != 0 {
                    fees.insert(trade.input.asset(), trade.maximum_input_asset_venue_fee);
                }
                let request = ExecutionRequest::exact_in(
                    trade.context,
                    trade.input,
                    trade.output_asset,
                    trade.minimum_output,
                    recipient,
                    fees,
                    trade.maximum_network_fee,
                )?;
                (
                    request,
                    QuoteBounds::ExactIn {
                        minimum_output: trade.minimum_output,
                    },
                    trade.maximum_input_asset_venue_fee,
                    trade.input.amount(),
                )
            }
            RequestedTrade::ExactOut(trade) => {
                let mut fees = BTreeMap::new();
                if trade.maximum_input_asset_venue_fee != 0 {
                    fees.insert(trade.input_asset, trade.maximum_input_asset_venue_fee);
                }
                let request = ExecutionRequest::exact_out(
                    trade.context,
                    trade.input_asset,
                    trade.maximum_input,
                    trade.output,
                    recipient,
                    fees,
                    trade.maximum_network_fee,
                )?;
                (
                    request,
                    QuoteBounds::ExactOut {
                        maximum_input: trade.maximum_input,
                    },
                    trade.maximum_input_asset_venue_fee,
                    trade.output.amount(),
                )
            }
        };
        let lease = self
            .pool
            .reserve_request(&request, receive, self.config.funding_limits)?;
        let leg = match request.kind() {
            deadcat_client::venue::ExecutionKind::ExactIn { .. } => {
                request.exact_in_leg(self.config.leg_id, allocated_amount, lease.payer_blinder())?
            }
            deadcat_client::venue::ExecutionKind::ExactOut { .. } => request.exact_out_leg(
                self.config.leg_id,
                allocated_amount,
                lease.payer_blinder(),
            )?,
        };
        let quote_intent = RfqQuoteIntent::new(&leg, market, bounds, maximum_venue_fee)?;
        Ok(ReservedRfqTrade {
            provenance: Arc::clone(&self.provenance),
            lease,
            request,
            quote_intent,
            leg,
        })
    }

    pub fn refresh_inventory<S>(&self, source: &S) -> Result<(), RfqTakerError>
    where
        S: TakerInventorySource + ?Sized,
    {
        self.require_ready()?;
        // The token is intentionally minted before either external read. A
        // concurrent successful arm changes the revision and makes replacement
        // fail instead of erasing its newly promoted exclusion.
        let token = self.pool.begin_inventory_refresh()?;
        let inventory = source
            .inventory()
            .map_err(|error| RfqTakerError::InventorySource(Box::new(error)))?;
        let recovery = load_funding_recovery(&self.journal, self.provenance.identity)?;
        self.pool
            .replace_inventory(&token, inventory, recovery.exclusions().clone())?;
        Ok(())
    }

    pub async fn accept<S>(
        &self,
        session: &RfqSession,
        source: &S,
        trade: PreparedRfqTrade<R>,
    ) -> Result<RfqExecutionHandle, RfqTakerError>
    where
        S: TakerSettlementSource + ?Sized,
    {
        self.accept_with_clock(session, source, trade, trusted_now_millis)
            .await
    }

    pub async fn accept_at<S>(
        &self,
        session: &RfqSession,
        source: &S,
        trade: PreparedRfqTrade<R>,
        blind_at_millis: u64,
        execute_at_millis: u64,
    ) -> Result<RfqExecutionHandle, RfqTakerError>
    where
        S: TakerSettlementSource + ?Sized,
    {
        let mut observations = [blind_at_millis, execute_at_millis].into_iter();
        self.accept_with_clock(session, source, trade, move || {
            observations
                .next()
                .ok_or(TakerClockError::ObservationExhausted)
        })
        .await
    }

    async fn accept_with_clock<S, F>(
        &self,
        session: &RfqSession,
        source: &S,
        trade: PreparedRfqTrade<R>,
        mut now_millis: F,
    ) -> Result<RfqExecutionHandle, RfqTakerError>
    where
        S: TakerSettlementSource + ?Sized,
        F: FnMut() -> Result<u64, TakerClockError>,
    {
        if !Arc::ptr_eq(&self.provenance, &trade.provenance) {
            return Err(RfqTakerError::ForeignPreparedTrade);
        }
        self.provenance.require_session(session)?;
        self.require_ready()?;
        let fee = plan_network_fee(
            trade.live.quote().verified(),
            self.config.minimum_sats_per_kvb,
            trade.request.max_network_fee(),
        )?;
        let (prepared_leg, binding) = trade.prepared.into_parts();
        let route = trade.request.validate_route(vec![prepared_leg], fee)?;
        let funded = trade
            .lease
            .fund_route(route, self.config.composition_limits)?;
        let (route, settlement_wallet) = funded.into_parts();
        let settlement = binding.resolve(&route)?;
        let plan = TakerSettlementPlan::new(&route, &binding)?;
        let pset = SettlementPset::from_pset(route.transaction().pset())?;
        let blind_at_millis = now_millis().map_err(RfqTakerError::Clock)?;
        let provider_blinded = session
            .blind_at(&trade.live, &settlement, pset, blind_at_millis)
            .await?;
        let coordinator = TakerSettlementCoordinator::new(plan, source, &settlement_wallet);
        let authorized = provider_blinded.authorize_with(&coordinator)?;
        drop(coordinator);
        let attempt = authorized.into_execution_attempt();
        let attempt_key = ExecutionJournalKey::for_attempt(&attempt);
        let attempt_digest = attempt.digest();
        let recovery = trade.replay.to_recovery_record()?;
        let journaled = match self.journal.arm(&recovery, &attempt) {
            Ok(journaled) => journaled,
            Err(source) => {
                self.revoke_readiness();
                return Err(RfqTakerError::JournalArmAmbiguous {
                    key: attempt_key,
                    attempt: attempt_digest,
                    source,
                });
            }
        };
        let funding = match settlement_wallet.mark_durably_armed(&journaled) {
            Ok(funding) => funding,
            Err(source) => {
                self.revoke_readiness();
                return Err(RfqTakerError::FundingPromotionFailed {
                    key: journaled.key(),
                    source,
                });
            }
        };
        let armed = ArmedRfqTrade { journaled, funding };
        let execute_at_millis = match now_millis() {
            Ok(now_millis) => now_millis,
            Err(source) => {
                return Err(RfqTakerError::PostArm {
                    handle: armed.handle(),
                    failure: PostArmFailure::Clock(source),
                });
            }
        };
        let status = match session
            .execute_at(
                &trade.live,
                &settlement,
                &armed.journaled,
                execute_at_millis,
            )
            .await
        {
            Ok(status) => status,
            Err(source) => {
                return Err(RfqTakerError::PostArm {
                    handle: armed.handle(),
                    failure: PostArmFailure::Execute(Box::new(source)),
                });
            }
        };
        self.observe_or_revoke(armed, status)
    }

    /// Discover every execution whose taker inputs must still remain excluded.
    ///
    /// This performs a complete fresh journal scan on each call and deliberately
    /// remains available even after runtime readiness has been revoked. Only an
    /// authenticated `Released` observation is omitted. In particular, `Signed`
    /// remains pending because its valid transaction can still be broadcast.
    pub fn pending_executions(&self) -> Result<Vec<RfqExecutionHandle>, RfqTakerError> {
        let (_, pending) =
            load_funding_recovery(&self.journal, self.provenance.identity)?.into_parts();
        pending
            .into_iter()
            .map(|journaled| {
                let taker_outpoints = execution_taker_input_outpoints(&journaled)?;
                Ok(RfqExecutionHandle {
                    journaled,
                    taker_outpoints,
                })
            })
            .collect()
    }

    /// Status-first, byte-identical recovery for one durable execution.
    pub async fn recover(
        &self,
        session: &RfqSession,
        key: ExecutionJournalKey,
    ) -> Result<RfqExecutionHandle, RfqTakerError> {
        self.provenance.require_session(session)?;
        self.require_ready()?;
        let journaled = self
            .journal
            .load(key)?
            .ok_or(RfqTakerError::ExecutionNotFound)?;
        validate_execution_identity(&journaled, self.provenance.identity)?;
        let outpoints = execution_taker_input_outpoints(&journaled)?;
        let handle = RfqExecutionHandle {
            journaled: journaled.clone(),
            taker_outpoints: outpoints,
        };
        let status = match session.retry_armed_execution(&journaled).await {
            Ok(status) => status,
            Err(source) => {
                return Err(RfqTakerError::PostArm {
                    handle,
                    failure: PostArmFailure::Execute(Box::new(source)),
                });
            }
        };
        match self.journal.observe(key, journaled.revision(), &status) {
            Ok(journaled) => Ok(RfqExecutionHandle {
                journaled,
                taker_outpoints: handle.taker_outpoints,
            }),
            Err(source) => {
                self.revoke_readiness();
                Err(RfqTakerError::PostArm {
                    handle,
                    failure: PostArmFailure::Observe {
                        status: status.status().clone(),
                        source,
                    },
                })
            }
        }
    }

    fn observe_or_revoke(
        &self,
        armed: ArmedRfqTrade,
        status: AuthenticatedExecutionStatus,
    ) -> Result<RfqExecutionHandle, RfqTakerError> {
        let handle = armed.handle();
        match self
            .journal
            .observe(armed.journaled.key(), armed.journaled.revision(), &status)
        {
            Ok(journaled) => Ok(RfqExecutionHandle {
                journaled,
                taker_outpoints: armed.funding.outpoints().clone(),
            }),
            Err(source) => {
                self.revoke_readiness();
                Err(RfqTakerError::PostArm {
                    handle,
                    failure: PostArmFailure::Observe {
                        status: status.status().clone(),
                        source,
                    },
                })
            }
        }
    }

    fn require_ready(&self) -> Result<(), RfqTakerError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(RfqTakerError::RestartRequired)
        }
    }

    fn revoke_readiness(&self) {
        self.ready.store(false, Ordering::Release);
    }
}

impl<R, J> core::fmt::Debug for RfqTakerRuntime<R, J> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("RfqTakerRuntime")
            .field("provenance", &"[opaque runtime identity]")
            .field("pool", &"[wallet-backed and redacted]")
            .field("journal", &"[durable]")
            .field("config", &self.config)
            .field("ready", &self.ready.load(Ordering::Relaxed))
            .finish()
    }
}

fn trusted_now_millis() -> Result<u64, TakerClockError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TakerClockError::BeforeUnixEpoch)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| TakerClockError::Overflow)
}

/// Fail-closed errors from the trusted wall-clock boundary.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TakerClockError {
    #[error("host wall clock is before the Unix epoch")]
    BeforeUnixEpoch,
    #[error("host wall clock exceeds the RFQ millisecond range")]
    Overflow,
    #[error("deterministic clock did not provide every required observation")]
    ObservationExhausted,
}

#[derive(Debug, Error)]
pub enum PostArmFailure {
    #[error("trusted execution-time observation failed: {0}")]
    Clock(#[source] TakerClockError),
    #[error("Execute outcome is uncertain: {0}")]
    Execute(#[source] Box<ExecuteError>),
    #[error("authenticated provider status could not be durably observed: {source}")]
    Observe {
        status: ReservationStatusDto,
        #[source]
        source: ExecutionJournalError,
    },
}

#[derive(Debug, Error)]
pub enum RfqTakerError {
    #[error("invalid taker runtime configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("taker runtime requires restart and journal reconstruction before more funding work")]
    RestartRequired,
    #[error("taker execution was not found in the durable journal")]
    ExecutionNotFound,
    #[error("prepared trade belongs to a different taker runtime")]
    ForeignPreparedTrade,
    #[error(
        "RFQ session client endpoint does not own this taker wallet (expected {expected:?}, got {actual:?})"
    )]
    SessionClientIdentityMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error(transparent)]
    Clock(#[from] TakerClockError),
    #[error("authoritative taker inventory scan failed")]
    InventorySource(#[source] Box<dyn Error + Send + Sync>),
    #[error(transparent)]
    FundingRecovery(#[from] FundingRecoveryError),
    #[error(transparent)]
    Funding(#[from] TakerFundingError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Venue(#[from] RfqVenueError),
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(transparent)]
    SettlementPlan(#[from] TakerSettlementPlanError),
    #[error(transparent)]
    Authorization(#[from] TakerAuthorizationError),
    #[error(transparent)]
    Fee(#[from] FeePlanningError),
    #[error(transparent)]
    Pset(#[from] deadcat_rfq_rpc::PsetError),
    #[error(transparent)]
    Journal(#[from] ExecutionJournalError),
    #[error(
        "journal arm for execution {key:?} (attempt {attempt:?}) is durability-ambiguous; restart is required"
    )]
    JournalArmAmbiguous {
        key: ExecutionJournalKey,
        attempt: ExecutionAttemptDigest,
        #[source]
        source: ExecutionJournalError,
    },
    #[error("journaled execution {key:?} could not promote its wallet inputs; restart is required")]
    FundingPromotionFailed {
        key: ExecutionJournalKey,
        #[source]
        source: TakerFundingError,
    },
    #[error("durably armed execution requires recovery: {failure}")]
    PostArm {
        handle: RfqExecutionHandle,
        #[source]
        failure: PostArmFailure,
    },
}
