//! Authenticated RFQ dispatch and daemon-owned settlement supervision.

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use deadcat_rfq_iroh::{
    ClientId, DiscoveryMode, RequestHandler, Server, ServerConfig, ServerError,
};
use deadcat_rfq_provider::{
    AuthorizedReservationStatus, Clock, DestinationSource, FeeSizeMetric, FirmQuote,
    FirmQuoteRequest, IdempotencyKey, InventorySource, MAX_PENDING_SIGNING_BATCH, OwnerId,
    PricingPolicy, ProviderBlindingCoordinator, ProviderBlindingError, ProviderIdentity,
    ProviderOutputRecovery, ProviderSettlementValidator, ProviderSigner,
    ProviderSigningCoordinator, QuoteAdmissionError, QuoteBlinderRole, QuoteEngine,
    QuoteEngineError, QuoteInputId, QuoteKind, QuoteOutputId, QuoteOutputRole, ReleaseReason,
    ReservationAccess, ReservationId, ReservationState, SettlementChainSource,
    SettlementInputPlacement, SettlementLayout, SettlementOutputPlacement,
    SettlementValidationError,
};
use deadcat_rfq_rpc::{
    AssetAmountDto, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FirmQuoteDto,
    FirmQuoteRequestDto, FixedBytes32, IdempotencyKeyDto, InputPlacementDto, OutputPlacementDto,
    PricingDecisionDto, ProviderCapability, ProviderInfo, QuoteContextDto, QuoteExecutionDto,
    QuoteInputDto, QuoteKindDto, QuoteOutputDto, QuoteOutputRoleDto, QuoteRecipientDto,
    RationalRateDto, ReleaseReasonDto, Request, ReservationStateDto, ReservationStatusDto,
    Response, RpcError, RpcErrorCode, SettlementLayoutDto, SettlementPset, SignedFirmQuote,
    SnapshotEvidenceDto, TxOutDto, owner_id_from_endpoints,
};
use deadcat_types::{ChainIdentity, LiquidNetwork};
use elements::Script;
use elements::secp256k1_zkp::PublicKey;
use iroh::{EndpointId, SecretKey};
use rand::rngs::OsRng;
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock, Semaphore, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::SharedRfqWallet;

const DEFAULT_EXECUTE_QUEUE_CAPACITY: usize = 8;
const MAX_EXECUTE_QUEUE_CAPACITY: usize = 8;
const DEFAULT_MAX_BLOCKING_OPERATIONS: usize = 16;
const MAX_BLOCKING_OPERATIONS: usize = 64;
const DEFAULT_RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_INVENTORY_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_RECOVERY_BATCH_SIZE: usize = 64;
const MAX_QUOTE_ATTEMPTS: usize = 2;

/// Bounded daemon supervision policy.
#[derive(Clone, Debug)]
pub struct HandlerConfig {
    pub execute_queue_capacity: usize,
    pub max_blocking_operations: usize,
    pub recovery_batch_size: usize,
    pub recovery_interval: Duration,
    pub inventory_refresh_interval: Duration,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            execute_queue_capacity: DEFAULT_EXECUTE_QUEUE_CAPACITY,
            max_blocking_operations: DEFAULT_MAX_BLOCKING_OPERATIONS,
            recovery_batch_size: DEFAULT_RECOVERY_BATCH_SIZE,
            recovery_interval: DEFAULT_RECOVERY_INTERVAL,
            inventory_refresh_interval: DEFAULT_INVENTORY_REFRESH_INTERVAL,
        }
    }
}

impl HandlerConfig {
    /// Validate daemon supervision limits before persistent state is opened or
    /// initialized. Startup repeats this check as defense in depth.
    pub fn validate(&self) -> Result<(), HandlerStartError> {
        if self.execute_queue_capacity == 0
            || self.execute_queue_capacity > MAX_EXECUTE_QUEUE_CAPACITY
            || self.max_blocking_operations == 0
            || self.max_blocking_operations > MAX_BLOCKING_OPERATIONS
            || self.recovery_batch_size == 0
            || self.recovery_batch_size > MAX_PENDING_SIGNING_BATCH
            || self.recovery_interval.is_zero()
            || self.inventory_refresh_interval.is_zero()
        {
            return Err(HandlerStartError::InvalidSupervisionLimits);
        }
        Ok(())
    }
}

/// Narrow wallet capabilities required by the concrete runtime.
pub trait RuntimeWallet: ProviderOutputRecovery + ProviderSigner + Send + Sync + 'static {
    fn provider_identity(&self) -> ProviderIdentity;
}

impl RuntimeWallet for SharedRfqWallet {
    fn provider_identity(&self) -> ProviderIdentity {
        self.identity()
    }
}

/// Transport-facing backend seam. The concrete implementation below maps
/// directly onto the provider state machine; the seam makes cancellation and
/// supervision behavior testable without wallet secrets or a live chain.
pub trait RfqBackend: Send + Sync + 'static {
    fn info(&self) -> Result<ProviderInfo, RpcError>;
    fn refresh_inventory(&self) -> Result<(), RpcError>;
    fn recover_pending(&self, limit: usize) -> Result<usize, RpcError>;
    fn quote(
        &self,
        owner: FixedBytes32,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
    ) -> Result<(FirmQuoteDto, ReservationStatusDto), RpcError>;
    fn cancel(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
    ) -> Result<ReservationStatusDto, RpcError>;
    fn blind(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Result<SettlementPset, RpcError>;
    /// Validate and durably commit the exact settlement, without invoking the
    /// signer. A separate daemon worker owns signing recovery.
    fn commit_execute(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Result<ReservationStatusDto, RpcError>;
    fn status(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
    ) -> Result<ReservationStatusDto, RpcError>;
}

/// Direct adapter from the public protocol to the transport-free provider
/// state machine.
pub struct ProviderRfqBackend<S, D, P, C, W, K> {
    quote_engine: QuoteEngine<S, D, P>,
    chain: C,
    wallet: W,
    clock: K,
    chain_identity: ChainIdentity,
}

impl<S, D, P, C, W, K> ProviderRfqBackend<S, D, P, C, W, K>
where
    S: InventorySource,
    D: DestinationSource,
    P: PricingPolicy,
    C: SettlementChainSource,
    W: RuntimeWallet,
    K: Clock,
{
    pub fn new(
        quote_engine: QuoteEngine<S, D, P>,
        chain: C,
        wallet: W,
        clock: K,
        chain_identity: ChainIdentity,
    ) -> Result<Self, HandlerStartError> {
        let identity = quote_engine.inventory().identity();
        if wallet.provider_identity() != identity {
            return Err(HandlerStartError::WalletIdentityMismatch);
        }
        if chain.genesis_hash() != identity.genesis_hash()
            || chain.genesis_hash() != chain_identity.genesis_hash
        {
            return Err(HandlerStartError::ChainIdentityMismatch);
        }
        Ok(Self {
            quote_engine,
            chain,
            wallet,
            clock,
            chain_identity,
        })
    }

    fn book(&self) -> &deadcat_rfq_provider::ReservationBook {
        self.quote_engine.inventory().reservation_book()
    }

    fn access(&self, owner: FixedBytes32, reservation: FixedBytes32) -> ReservationAccess {
        ReservationAccess::new(
            ReservationId::new(reservation.to_bytes()),
            OwnerId::new(owner.to_bytes()),
        )
    }

    fn authorized_status(
        &self,
        access: ReservationAccess,
    ) -> Result<ReservationStatusDto, RpcError> {
        self.book()
            .reservation_status_at(access, &self.clock)
            .map_err(|error| map_provider_error(&error))
            .and_then(|status| status_to_dto(&status))
    }

    fn authorized_status_readonly(
        &self,
        access: ReservationAccess,
    ) -> Result<ReservationStatusDto, RpcError> {
        self.book()
            .reservation_status(access)
            .map_err(|error| map_provider_error(&error))
            .and_then(|status| status_to_dto(&status))
    }
}

impl<S, D, P, C, W, K> RfqBackend for ProviderRfqBackend<S, D, P, C, W, K>
where
    S: InventorySource + Send + Sync + 'static,
    D: DestinationSource + Send + Sync + 'static,
    P: PricingPolicy + Send + Sync + 'static,
    C: SettlementChainSource + Send + Sync + 'static,
    W: RuntimeWallet,
    K: Clock + Send + Sync + 'static,
{
    fn info(&self) -> Result<ProviderInfo, RpcError> {
        let identity = self.quote_engine.inventory().identity();
        Ok(ProviderInfo {
            provider_endpoint: FixedBytes32::new(identity.provider().to_bytes()),
            network: self.chain_identity.network,
            genesis_hash: identity.genesis_hash(),
            policy_asset: identity.policy_asset(),
            capabilities: vec![
                ProviderCapability::FirmQuotes,
                ProviderCapability::ProviderBlinding,
                ProviderCapability::SettlementExecution,
                ProviderCapability::DurableStatus,
            ],
        })
    }

    fn refresh_inventory(&self) -> Result<(), RpcError> {
        self.quote_engine
            .inventory()
            .refresh(&self.clock)
            .map(|_| ())
            .map_err(|error| {
                tracing::error!(error = %error, "authoritative RFQ inventory refresh failed");
                rpc_error(
                    RpcErrorCode::BackendUnavailable,
                    "provider inventory refresh is temporarily unavailable",
                )
            })
    }

    fn recover_pending(&self, limit: usize) -> Result<usize, RpcError> {
        let jobs = self
            .book()
            .pending_signing_jobs(limit)
            .map_err(|error| map_provider_error(&error))?;
        let recovered = jobs.len();
        let coordinator = ProviderSigningCoordinator::new(self.book(), &self.wallet);
        for job in jobs {
            coordinator.finalize(&job, &self.clock).map_err(|error| {
                tracing::error!(error = %error, "RFQ recovery action failed");
                rpc_error(
                    RpcErrorCode::BackendUnavailable,
                    "provider signing recovery is temporarily unavailable",
                )
            })?;
        }
        Ok(recovered)
    }

    fn quote(
        &self,
        owner: FixedBytes32,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
    ) -> Result<(FirmQuoteDto, ReservationStatusDto), RpcError> {
        if request.context.network != self.chain_identity.network
            || request.context.genesis_hash != self.chain_identity.genesis_hash
        {
            return Err(rpc_error(
                RpcErrorCode::UnsupportedMarket,
                "RFQ market is not served on this network",
            ));
        }
        let owner = OwnerId::new(owner.to_bytes());
        let key = IdempotencyKey::new(idempotency_key.to_bytes());
        let domain_request = request_from_dto(request)?;
        let mut attempts = 0;
        let outcome = loop {
            attempts += 1;
            match self
                .quote_engine
                .firm_quote(owner, key, domain_request.clone(), &self.clock)
            {
                Ok(outcome) => break outcome,
                Err(QuoteEngineError::Provider(
                    deadcat_rfq_provider::ProviderError::EligibleInventoryChanged,
                )) if attempts < MAX_QUOTE_ATTEMPTS => {
                    tracing::debug!(attempts, "retrying firm quote after inventory changed");
                }
                Err(error) => return Err(map_quote_error(error)),
            }
        };
        let access = ReservationAccess::new(outcome.quote().reservation_id(), owner);
        let status = self.authorized_status(access)?;
        Ok((
            quote_to_dto(outcome.quote(), self.chain_identity.network),
            status,
        ))
    }

    fn cancel(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
    ) -> Result<ReservationStatusDto, RpcError> {
        let access = self.access(owner, reservation_id);
        self.book()
            .cancel(access, &self.clock)
            .map_err(|error| map_provider_error(&error))?;
        self.authorized_status_readonly(access)
    }

    fn blind(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Result<SettlementPset, RpcError> {
        let access = self.access(owner, reservation_id);
        let layout = layout_from_dto(layout)?;
        let blinded = ProviderBlindingCoordinator::new(self.quote_engine.inventory())
            .blind(access, &layout, pset.as_bytes(), &self.clock, &mut OsRng)
            .map_err(map_blinding_error)?;
        SettlementPset::from_bytes(blinded.into_bytes()).map_err(|_| {
            rpc_error(
                RpcErrorCode::InternalError,
                "provider produced an invalid blinded PSET",
            )
        })
    }

    fn commit_execute(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Result<ReservationStatusDto, RpcError> {
        let access = self.access(owner, reservation_id);
        let layout = layout_from_dto(layout)?;
        let intent = ProviderSettlementValidator::new(self.book(), &self.chain, &self.wallet)
            .validate(access, &layout, pset.as_bytes())
            .map_err(map_settlement_error)?;
        // This durable transition occurs only inside the daemon-owned execute
        // worker. The transport future owns merely a oneshot receiver and can
        // be cancelled without dropping this call or the work below it.
        let outcome = intent
            .commit(self.book(), &self.clock)
            .map_err(|error| map_provider_error(&error))?;
        // The irreversible durable transition ends this admission operation.
        // Signing is deliberately supervised by a separate daemon worker so
        // a slow wallet or HSM cannot prevent unrelated live reservations
        // from reaching their acceptance deadline.
        let _ = outcome;
        self.authorized_status_readonly(access)
    }

    fn status(
        &self,
        owner: FixedBytes32,
        reservation_id: FixedBytes32,
    ) -> Result<ReservationStatusDto, RpcError> {
        self.authorized_status(self.access(owner, reservation_id))
    }
}

struct ExecuteCommand {
    owner: FixedBytes32,
    reservation_id: FixedBytes32,
    layout: SettlementLayoutDto,
    pset: SettlementPset,
    reply: oneshot::Sender<Result<ReservationStatusDto, RpcError>>,
}

/// Authenticated transport handler with a daemon-owned execute worker.
pub struct AuthenticatedRfqHandler<B> {
    backend: Arc<B>,
    provider_key: Arc<SecretKey>,
    execute_tx: mpsc::Sender<ExecuteCommand>,
    blocking_permits: Arc<Semaphore>,
    admission: Arc<AdmissionGate>,
    supervisor: Arc<HandlerSupervisor>,
}

struct AdmissionState {
    accepting: bool,
    signer_healthy: bool,
}

type AdmissionGate = RwLock<AdmissionState>;

struct WorkerTasks {
    execute: JoinHandle<()>,
    signing: JoinHandle<()>,
    inventory: JoinHandle<()>,
}

struct HandlerSupervisor {
    admission: Arc<AdmissionGate>,
    execute_shutdown: watch::Sender<bool>,
    signing_shutdown: watch::Sender<bool>,
    inventory_shutdown: watch::Sender<bool>,
    tasks: Mutex<Option<WorkerTasks>>,
}

impl HandlerSupervisor {
    async fn shutdown(&self) {
        // Close public admission immediately, then cross the write barrier.
        // Any execute operation that already holds the read side is allowed
        // to finish its validate -> durable-commit boundary first.
        self.admission.write().await.accepting = false;

        let _ = self.inventory_shutdown.send(true);
        let _ = self.execute_shutdown.send(true);
        let tasks = self.tasks.lock().ok().and_then(|mut tasks| tasks.take());
        if let Some(tasks) = tasks {
            // Execute closes and drains its queue first. Only after no further
            // point-of-no-return transition is possible may signing drain the
            // durable pending index and exit.
            let _ = tasks.execute.await;
            let _ = self.signing_shutdown.send(true);
            let _ = tasks.signing.await;
            let _ = tasks.inventory.await;
        }
    }
}

impl Drop for HandlerSupervisor {
    fn drop(&mut self) {
        if let Ok(mut admission) = self.admission.try_write() {
            admission.accepting = false;
        }
        let _ = self.execute_shutdown.send(true);
        let _ = self.signing_shutdown.send(true);
        let _ = self.inventory_shutdown.send(true);
        if let Ok(tasks) = self.tasks.get_mut()
            && let Some(tasks) = tasks.take()
        {
            tasks.execute.abort();
            tasks.signing.abort();
            tasks.inventory.abort();
        }
    }
}

impl<B> Clone for AuthenticatedRfqHandler<B> {
    fn clone(&self) -> Self {
        Self {
            backend: Arc::clone(&self.backend),
            provider_key: Arc::clone(&self.provider_key),
            execute_tx: self.execute_tx.clone(),
            blocking_permits: Arc::clone(&self.blocking_permits),
            admission: Arc::clone(&self.admission),
            supervisor: Arc::clone(&self.supervisor),
        }
    }
}

impl<B: RfqBackend> AuthenticatedRfqHandler<B> {
    pub async fn start(backend: B, provider_key: SecretKey) -> Result<Self, HandlerStartError> {
        Self::start_with_config(backend, provider_key, HandlerConfig::default()).await
    }

    /// Compatibility constructor for callers that only customize execute
    /// admission and recovery cadence.
    pub async fn start_with_limits(
        backend: B,
        provider_key: SecretKey,
        execute_queue_capacity: usize,
        recovery_interval: Duration,
    ) -> Result<Self, HandlerStartError> {
        Self::start_with_config(
            backend,
            provider_key,
            HandlerConfig {
                execute_queue_capacity,
                recovery_interval,
                ..HandlerConfig::default()
            },
        )
        .await
    }

    pub async fn start_with_config(
        backend: B,
        provider_key: SecretKey,
        config: HandlerConfig,
    ) -> Result<Self, HandlerStartError> {
        config.validate()?;
        let backend = Arc::new(backend);
        let info_backend = Arc::clone(&backend);
        let info = tokio::task::spawn_blocking(move || info_backend.info())
            .await
            .map_err(|_| HandlerStartError::StartupTaskPanicked)?
            .map_err(HandlerStartError::Backend)?;
        if info.provider_endpoint.to_bytes() != *provider_key.public().as_bytes() {
            return Err(HandlerStartError::TransportIdentityMismatch);
        }

        // ADR 0008 requires an authoritative wallet reconciliation before any
        // recovered signing job can reach the signer after restart.
        let startup_backend = Arc::clone(&backend);
        let recovery_batch_size = config.recovery_batch_size;
        tokio::task::spawn_blocking(move || {
            startup_backend.refresh_inventory()?;
            loop {
                let recovered = startup_backend.recover_pending(recovery_batch_size)?;
                if recovered < recovery_batch_size {
                    return Ok::<(), RpcError>(());
                }
            }
        })
        .await
        .map_err(|_| HandlerStartError::StartupTaskPanicked)?
        .map_err(HandlerStartError::Backend)?;

        // A canonical settlement is at most one MiB. Capping this queue at
        // eight therefore bounds queued PSET bytes to eight MiB, plus the one
        // command actively owned by the daemon worker.
        let (execute_tx, execute_rx) = mpsc::channel(config.execute_queue_capacity);
        let (signing_tx, signing_rx) = mpsc::channel(1);
        let (execute_shutdown, execute_shutdown_rx) = watch::channel(false);
        let (signing_shutdown, signing_shutdown_rx) = watch::channel(false);
        let (inventory_shutdown, inventory_shutdown_rx) = watch::channel(false);
        let admission = Arc::new(RwLock::new(AdmissionState {
            accepting: true,
            signer_healthy: true,
        }));
        let execute_task = tokio::spawn(execute_worker(
            Arc::clone(&backend),
            execute_rx,
            signing_tx,
            Arc::clone(&admission),
            execute_shutdown_rx,
        ));
        let signing_task = tokio::spawn(signing_worker(
            Arc::clone(&backend),
            signing_rx,
            Arc::clone(&admission),
            config.recovery_batch_size,
            config.recovery_interval,
            signing_shutdown_rx,
        ));
        let inventory_task = tokio::spawn(inventory_worker(
            Arc::clone(&backend),
            config.inventory_refresh_interval,
            inventory_shutdown_rx,
        ));
        let supervisor = Arc::new(HandlerSupervisor {
            admission: Arc::clone(&admission),
            execute_shutdown,
            signing_shutdown,
            inventory_shutdown,
            tasks: Mutex::new(Some(WorkerTasks {
                execute: execute_task,
                signing: signing_task,
                inventory: inventory_task,
            })),
        });
        Ok(Self {
            backend,
            provider_key: Arc::new(provider_key),
            execute_tx,
            blocking_permits: Arc::new(Semaphore::new(config.max_blocking_operations)),
            admission,
            supervisor,
        })
    }

    /// Bind transport with the exact persistent identity retained for owner
    /// derivation and quote attestation.
    pub async fn bind_server(
        self: Arc<Self>,
        discovery: DiscoveryMode,
        config: ServerConfig,
    ) -> Result<Server<Self>, ServerError> {
        let provider_key = self.provider_key.as_ref().clone();
        Server::bind(provider_key, discovery, config, self).await
    }

    /// Stop and join all daemon-owned workers. In-flight blocking work is
    /// allowed to reach its durability boundary before the join completes.
    pub async fn shutdown(&self) {
        self.supervisor.shutdown().await;
    }

    fn identities(&self, peer: ClientId) -> Result<(EndpointId, FixedBytes32), RpcError> {
        let client = EndpointId::from_bytes(&peer).map_err(|_| {
            rpc_error(
                RpcErrorCode::InternalError,
                "authenticated transport supplied an invalid client identity",
            )
        })?;
        let owner = owner_id_from_endpoints(self.provider_key.public(), client);
        Ok((client, owner))
    }
}

impl<B: RfqBackend> RequestHandler for AuthenticatedRfqHandler<B> {
    fn handle(
        &self,
        peer: ClientId,
        request: Request,
    ) -> impl Future<Output = Result<Response, RpcError>> + Send {
        let backend = Arc::clone(&self.backend);
        let provider_key = Arc::clone(&self.provider_key);
        let execute_tx = self.execute_tx.clone();
        let blocking_permits = Arc::clone(&self.blocking_permits);
        let admission = Arc::clone(&self.admission);
        let identities = self.identities(peer);
        async move {
            let (client, owner) = identities?;
            match request {
                Request::GetInfo => {
                    let info = run_blocking(blocking_permits, move || backend.info()).await?;
                    Ok(Response::Info { info })
                }
                Request::RequestFirmQuote {
                    idempotency_key,
                    request,
                } => {
                    let quote_admission = admission_guard(Arc::clone(&admission)).await?;
                    let (result, quote_admission) = run_blocking(blocking_permits, move || {
                        backend
                            .quote(owner, idempotency_key, request)
                            .map(|result| (result, quote_admission))
                    })
                    .await?;
                    let (quote, status) = result;
                    let quote = SignedFirmQuote::sign(
                        quote,
                        provider_key.as_ref(),
                        client,
                        idempotency_key,
                    )
                    .map_err(|error| {
                        tracing::error!(error = %error, "provider quote attestation failed");
                        rpc_error(
                            RpcErrorCode::InternalError,
                            "provider could not attest its firm quote",
                        )
                    })?;
                    // Keep the admission barrier through attestation so a
                    // signer-health transition cannot become visible before
                    // an already-admitted quote is fully constructed.
                    drop(quote_admission);
                    Ok(Response::FirmQuote { quote, status })
                }
                Request::CancelReservation { reservation_id } => {
                    let status = run_blocking(blocking_permits, move || {
                        backend.cancel(owner, reservation_id)
                    })
                    .await?;
                    Ok(Response::ReservationCancelled { status })
                }
                Request::BlindPset {
                    reservation_id,
                    layout,
                    pset,
                } => {
                    let blind_admission = admission_guard(Arc::clone(&admission)).await?;
                    let (pset, blind_admission) = run_blocking(blocking_permits, move || {
                        backend
                            .blind(owner, reservation_id, layout, pset)
                            .map(|pset| (pset, blind_admission))
                    })
                    .await?;
                    drop(blind_admission);
                    Ok(Response::BlindedPset {
                        reservation_id,
                        pset,
                    })
                }
                Request::Execute {
                    reservation_id,
                    layout,
                    pset,
                } => {
                    drop(admission_guard(Arc::clone(&admission)).await?);
                    let (reply, response) = oneshot::channel();
                    execute_tx
                        .try_send(ExecuteCommand {
                            owner,
                            reservation_id,
                            layout,
                            pset,
                            reply,
                        })
                        .map_err(|error| match error {
                            mpsc::error::TrySendError::Full(_) => RpcError::with_retry_after(
                                RpcErrorCode::RateLimited,
                                "provider execute queue is full",
                                Some(250),
                            )
                            .expect("static rate-limit error is valid"),
                            mpsc::error::TrySendError::Closed(_) => rpc_error(
                                RpcErrorCode::BackendUnavailable,
                                "provider execute supervisor is unavailable",
                            ),
                        })?;
                    let status = response.await.map_err(|_| {
                        rpc_error(
                            RpcErrorCode::BackendUnavailable,
                            "provider execute supervisor stopped",
                        )
                    })??;
                    Ok(Response::ExecutionAccepted { status })
                }
                Request::GetReservationStatus { reservation_id } => {
                    let status = run_blocking(blocking_permits, move || {
                        backend.status(owner, reservation_id)
                    })
                    .await?;
                    Ok(Response::ReservationStatus { status })
                }
            }
        }
    }
}

async fn execute_worker<B: RfqBackend>(
    backend: Arc<B>,
    mut commands: mpsc::Receiver<ExecuteCommand>,
    signing_tx: mpsc::Sender<()>,
    admission: Arc<AdmissionGate>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                process_execute_command(
                    Arc::clone(&backend),
                    command,
                    &signing_tx,
                    Arc::clone(&admission),
                ).await;
            }
        }
    }

    // Stop senders from extending shutdown, but finish every command already
    // accepted by the bounded daemon queue. The admission gate rejects any
    // queued command that had not begun its commit boundary before shutdown.
    commands.close();
    while let Some(command) = commands.recv().await {
        process_execute_command(
            Arc::clone(&backend),
            command,
            &signing_tx,
            Arc::clone(&admission),
        )
        .await;
    }
}

async fn process_execute_command<B: RfqBackend>(
    backend: Arc<B>,
    command: ExecuteCommand,
    signing_tx: &mpsc::Sender<()>,
    admission: Arc<AdmissionGate>,
) {
    let ExecuteCommand {
        owner,
        reservation_id,
        layout,
        pset,
        reply,
    } = command;
    let commit_admission = match admission_guard(admission).await {
        Ok(admission) => admission,
        Err(error) => {
            let _ = reply.send(Err(error));
            return;
        }
    };
    let result = tokio::task::spawn_blocking(move || {
        // This read guard spans validation and the final durable transition.
        // Signer degradation and graceful shutdown both take the write side,
        // so neither can become externally visible midway through a commit.
        let _admission = commit_admission;
        backend.commit_execute(owner, reservation_id, layout, pset)
    })
    .await
    .unwrap_or_else(|_| {
        Err(rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider execute worker panicked",
        ))
    });
    if result.is_ok() {
        let _ = signing_tx.try_send(());
    }
    let _ = reply.send(result);
}

async fn signing_worker<B: RfqBackend>(
    backend: Arc<B>,
    mut notifications: mpsc::Receiver<()>,
    admission: Arc<AdmissionGate>,
    recovery_batch_size: usize,
    recovery_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut recovery = tokio::time::interval_at(
        tokio::time::Instant::now() + recovery_interval,
        recovery_interval,
    );
    recovery.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let shutting_down = tokio::select! {
            _ = shutdown.changed() => true,
            notification = notifications.recv() => {
                notification.is_none()
            }
            _ = recovery.tick() => false,
        };
        loop {
            let recovery_backend = Arc::clone(&backend);
            let result = tokio::task::spawn_blocking(move || {
                recovery_backend.recover_pending(recovery_batch_size)
            })
            .await;
            match result {
                Ok(Ok(recovered)) if recovered == recovery_batch_size => {}
                Ok(Ok(_)) if shutting_down => return,
                Ok(Ok(_)) => break,
                Ok(Err(error)) => {
                    mark_signer_degraded(Arc::clone(&admission)).await;
                    tracing::error!(error = %error.message(), "RFQ signer degraded; quote, blind, and execute admission stopped");
                    if shutting_down {
                        // A permanently unavailable signer must not make
                        // process shutdown hang forever. The exact committed
                        // job remains durable for startup recovery.
                        return;
                    } else {
                        break;
                    }
                }
                Err(error) => {
                    mark_signer_degraded(Arc::clone(&admission)).await;
                    tracing::error!(error = %error, "RFQ signing worker panicked; quote, blind, and execute admission stopped");
                    if shutting_down {
                        return;
                    } else {
                        break;
                    }
                }
            }
        }
    }
}

async fn mark_signer_degraded(admission: Arc<AdmissionGate>) {
    admission.write().await.signer_healthy = false;
}

async fn inventory_worker<B: RfqBackend>(
    backend: Arc<B>,
    inventory_refresh_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut inventory = tokio::time::interval_at(
        tokio::time::Instant::now() + inventory_refresh_interval,
        inventory_refresh_interval,
    );
    inventory.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = inventory.tick() => {
                let inventory_backend = Arc::clone(&backend);
                match tokio::task::spawn_blocking(move || inventory_backend.refresh_inventory()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => tracing::error!(error = %error.message(), "periodic RFQ inventory refresh failed"),
                    Err(error) => tracing::error!(error = %error, "periodic RFQ inventory refresh task panicked"),
                }
            }
        }
    }
}

async fn admission_guard(
    admission: Arc<AdmissionGate>,
) -> Result<OwnedRwLockReadGuard<AdmissionState>, RpcError> {
    let state = admission.read_owned().await;
    if !state.accepting {
        return Err(rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider is shutting down",
        ));
    }
    if !state.signer_healthy {
        return Err(rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider signer requires operator recovery",
        ));
    }
    Ok(state)
}

async fn run_blocking<T: Send + 'static>(
    permits: Arc<Semaphore>,
    operation: impl FnOnce() -> Result<T, RpcError> + Send + 'static,
) -> Result<T, RpcError> {
    let permit = permits.try_acquire_owned().map_err(|error| match error {
        tokio::sync::TryAcquireError::NoPermits => RpcError::with_retry_after(
            RpcErrorCode::RateLimited,
            "provider operation capacity is full",
            Some(50),
        )
        .expect("static rate-limit error is valid"),
        tokio::sync::TryAcquireError::Closed => rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider operation supervisor stopped",
        ),
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| {
        rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider operation panicked",
        )
    })?
}

#[derive(Debug, Error)]
pub enum HandlerStartError {
    #[error("wallet identity does not match the quote engine")]
    WalletIdentityMismatch,
    #[error("settlement chain identity does not match the quote engine")]
    ChainIdentityMismatch,
    #[error("Iroh transport identity does not match the provider identity")]
    TransportIdentityMismatch,
    #[error("RFQ supervision limits are invalid or exceed their hard caps")]
    InvalidSupervisionLimits,
    #[error("initial inventory reconciliation or recovery task panicked")]
    StartupTaskPanicked,
    #[error("provider startup recovery failed: {0:?}")]
    Backend(RpcError),
}

fn request_from_dto(request: FirmQuoteRequestDto) -> Result<FirmQuoteRequest, RpcError> {
    let context = deadcat_rfq_provider::QuoteContext::new(
        ChainIdentity {
            network: request.context.network,
            genesis_hash: request.context.genesis_hash,
        },
        request.context.market,
        request.context.policy_asset,
    );
    let kind = match request.kind {
        QuoteKindDto::ExactIn {
            input,
            output_asset,
            minimum_output,
        } => QuoteKind::ExactIn {
            input: deadcat_rfq_provider::AssetAmount::new(input.asset, input.amount)
                .map_err(|_| invalid_request())?,
            output_asset,
            minimum_output,
        },
        QuoteKindDto::ExactOut {
            input_asset,
            maximum_input,
            output,
        } => QuoteKind::ExactOut {
            input_asset,
            maximum_input,
            output: deadcat_rfq_provider::AssetAmount::new(output.asset, output.amount)
                .map_err(|_| invalid_request())?,
        },
    };
    let blinding_public_key =
        PublicKey::from_slice(&request.recipient.blinding_public_key.to_bytes())
            .map_err(|_| invalid_request())?;
    let recipient = deadcat_rfq_provider::QuoteRecipient::new(
        Script::from(request.recipient.script_pubkey),
        blinding_public_key,
    )
    .map_err(|_| invalid_request())?;
    FirmQuoteRequest::new(
        context,
        kind,
        recipient,
        request.maximum_input_asset_venue_fee,
    )
    .map_err(|_| invalid_request())
}

fn layout_from_dto(layout: SettlementLayoutDto) -> Result<SettlementLayout, RpcError> {
    let provider_inputs = layout
        .provider_inputs
        .into_iter()
        .map(|placement: InputPlacementDto| {
            SettlementInputPlacement::new(
                QuoteInputId::new(placement.quote_input_id),
                usize::from(placement.transaction_index),
            )
        })
        .collect();
    let quote_outputs = layout
        .quote_outputs
        .into_iter()
        .map(|placement: OutputPlacementDto| {
            SettlementOutputPlacement::new(
                QuoteOutputId::new(placement.quote_output_id),
                usize::from(placement.transaction_index),
            )
        })
        .collect();
    SettlementLayout::new(
        usize::from(layout.taker_payment_input),
        provider_inputs,
        quote_outputs,
    )
    .map_err(|_| rpc_error(RpcErrorCode::InvalidLayout, "settlement layout is invalid"))
}

fn quote_to_dto(quote: &FirmQuote, network: LiquidNetwork) -> FirmQuoteDto {
    let provider = quote.provider();
    let request = request_to_dto(quote.request());
    let execution = quote.execution();
    let pricing = quote.pricing();
    let snapshot = quote.snapshot();
    let fee = quote.fee_policy();
    FirmQuoteDto {
        reservation_id: FixedBytes32::new(quote.reservation_id().to_bytes()),
        provider_endpoint: FixedBytes32::new(provider.provider().to_bytes()),
        network,
        genesis_hash: provider.genesis_hash(),
        policy_asset: provider.policy_asset(),
        request,
        execution: QuoteExecutionDto {
            input: AssetAmountDto {
                asset: execution.input().asset(),
                amount: execution.input().amount(),
            },
            output: AssetAmountDto {
                asset: execution.output().asset(),
                amount: execution.output().amount(),
            },
            input_asset_venue_fee: execution.input_asset_venue_fee(),
        },
        pricing: PricingDecisionDto {
            rate: RationalRateDto {
                numerator: pricing.rate().numerator(),
                denominator: pricing.rate().denominator(),
            },
            input_asset_venue_fee: pricing.input_asset_venue_fee(),
            policy_id: FixedBytes32::new(pricing.policy_id().to_bytes()),
            revision: pricing.revision().value(),
        },
        snapshot: SnapshotEvidenceDto {
            block_hash: snapshot.anchor().block_hash(),
            block_height: snapshot.anchor().block_height(),
            snapshot_commitment: FixedBytes32::new(snapshot.commitment().to_bytes()),
            allocation_revision: snapshot.allocation_revision(),
            eligible_commitment: FixedBytes32::new(snapshot.eligible_commitment()),
        },
        inputs: quote
            .contribution()
            .inputs()
            .iter()
            .map(|input| QuoteInputDto {
                id: input.id().value(),
                outpoint: input.outpoint(),
                witness_utxo: TxOutDto::from_txout(input.witness_utxo()),
                inventory_binding: FixedBytes32::new(input.inventory_binding().to_bytes()),
            })
            .collect(),
        outputs: quote
            .contribution()
            .outputs()
            .iter()
            .map(|output| QuoteOutputDto {
                id: output.id().value(),
                role: match output.role() {
                    QuoteOutputRole::ProviderPayment => QuoteOutputRoleDto::ProviderPayment,
                    QuoteOutputRole::TakerReceive => QuoteOutputRoleDto::TakerReceive,
                    QuoteOutputRole::ProviderChange => QuoteOutputRoleDto::ProviderChange,
                },
                asset: output.asset(),
                amount: output.amount(),
                destination: recipient_to_dto(output.destination()),
                blinder: match output.blinder() {
                    QuoteBlinderRole::TakerPaymentInput => BlinderRoleDto::TakerPaymentInput,
                    QuoteBlinderRole::ProviderInput(input) => BlinderRoleDto::ProviderInput {
                        quote_input_id: input.value(),
                    },
                },
            })
            .collect(),
        created_at_millis: quote.created_at().value(),
        accept_before_millis: quote.accept_before().value(),
        fee_policy: FeePolicyDto {
            policy_asset: fee.policy_asset(),
            minimum_sats_per_kvb: fee.minimum_sats_per_kvb(),
            minimum_absolute_fee: fee.minimum_absolute_fee(),
            maximum_transaction_weight: fee.maximum_transaction_weight(),
            size_metric: match fee.size_metric() {
                FeeSizeMetric::RegularVbytes => FeeSizeMetricDto::RegularVbytes,
                FeeSizeMetric::DiscountVbytes => FeeSizeMetricDto::DiscountVbytes,
            },
        },
        recovery_metadata_commitment: FixedBytes32::new(quote.recovery_metadata_commitment()),
        quote_commitment: FixedBytes32::new(quote.commitment().to_bytes()),
    }
}

fn request_to_dto(request: &FirmQuoteRequest) -> FirmQuoteRequestDto {
    let context = request.context();
    FirmQuoteRequestDto {
        context: QuoteContextDto {
            network: context.chain().network,
            genesis_hash: context.chain().genesis_hash,
            market: context.market(),
            policy_asset: context.policy_asset(),
        },
        kind: match request.kind() {
            QuoteKind::ExactIn {
                input,
                output_asset,
                minimum_output,
            } => QuoteKindDto::ExactIn {
                input: AssetAmountDto {
                    asset: input.asset(),
                    amount: input.amount(),
                },
                output_asset,
                minimum_output,
            },
            QuoteKind::ExactOut {
                input_asset,
                maximum_input,
                output,
            } => QuoteKindDto::ExactOut {
                input_asset,
                maximum_input,
                output: AssetAmountDto {
                    asset: output.asset(),
                    amount: output.amount(),
                },
            },
        },
        recipient: recipient_to_dto(request.recipient()),
        maximum_input_asset_venue_fee: request.maximum_input_asset_venue_fee(),
    }
}

fn recipient_to_dto(recipient: &deadcat_rfq_provider::QuoteRecipient) -> QuoteRecipientDto {
    QuoteRecipientDto {
        script_pubkey: recipient.script_pubkey().as_bytes().to_vec(),
        blinding_public_key: deadcat_rfq_rpc::FixedBytes33::new(
            recipient.blinding_public_key().serialize(),
        ),
    }
}

fn status_to_dto(status: &AuthorizedReservationStatus) -> Result<ReservationStatusDto, RpcError> {
    let reservation = status.reservation();
    let state = match reservation.state() {
        ReservationState::Reserved => ReservationStateDto::Reserved,
        ReservationState::Released { reason, at } => ReservationStateDto::Released {
            reason: match reason {
                ReleaseReason::Expired => ReleaseReasonDto::Expired,
                ReleaseReason::ClientCancelled => ReleaseReasonDto::ClientCancelled,
                ReleaseReason::ProviderRejected => ReleaseReasonDto::ProviderRejected,
            },
            at_millis: at.value(),
        },
        ReservationState::Committed {
            commitment,
            committed_at,
        } => ReservationStateDto::Committed {
            signing_commitment: FixedBytes32::new(commitment.to_bytes()),
            committed_at_millis: committed_at.value(),
        },
        ReservationState::Signed {
            commitment,
            artifact,
            committed_at,
            signed_at,
        } => {
            let signed = status.signed_artifact().ok_or_else(|| {
                rpc_error(
                    RpcErrorCode::InternalError,
                    "signed reservation is missing its durable artifact",
                )
            })?;
            ReservationStateDto::Signed {
                signing_commitment: FixedBytes32::new(commitment.to_bytes()),
                artifact_digest: FixedBytes32::new(artifact.to_bytes()),
                committed_at_millis: committed_at.value(),
                signed_at_millis: signed_at.value(),
                signed_pset: SettlementPset::from_bytes(signed.bytes().to_vec()).map_err(|_| {
                    rpc_error(
                        RpcErrorCode::InternalError,
                        "durable signed artifact is not a valid PSET",
                    )
                })?,
            }
        }
    };
    let dto = ReservationStatusDto {
        reservation_id: FixedBytes32::new(reservation.id().to_bytes()),
        quote_commitment: FixedBytes32::new(reservation.quote_commitment().to_bytes()),
        created_at_millis: reservation.created_at().value(),
        accept_before_millis: reservation.accept_before().value(),
        state,
    };
    dto.validate().map_err(|error| {
        tracing::error!(error = %error, "provider produced invalid public reservation status");
        rpc_error(
            RpcErrorCode::InternalError,
            "provider reservation status is internally inconsistent",
        )
    })?;
    Ok(dto)
}

fn map_quote_error<S, D, P>(error: QuoteEngineError<S, D, P>) -> RpcError
where
    S: Error + Send + Sync + 'static,
    D: Error + Send + Sync + 'static,
    P: Error + Send + Sync + 'static,
{
    tracing::warn!(error = %error, "firm quote request rejected");
    match error {
        QuoteEngineError::Provider(error) => map_provider_error(&error),
        QuoteEngineError::Admission(error) => match error {
            QuoteAdmissionError::MarketNotConfigured => rpc_error(
                RpcErrorCode::UnsupportedMarket,
                "RFQ market is not configured",
            ),
            QuoteAdmissionError::PairNotConfigured => rpc_error(
                RpcErrorCode::UnsupportedPair,
                "RFQ asset pair is not configured",
            ),
            QuoteAdmissionError::FillOutsideConfiguredRange
            | QuoteAdmissionError::VenueFeeLimitExceeded
            | QuoteAdmissionError::FeeConsumesInput
            | QuoteAdmissionError::MinimumOutputNotMet
            | QuoteAdmissionError::MaximumInputExceeded
            | QuoteAdmissionError::RoundedAmountIsZero => rpc_error(
                RpcErrorCode::FillOutOfRange,
                "requested RFQ fill is outside provider limits",
            ),
            QuoteAdmissionError::InsufficientInventory
            | QuoteAdmissionError::InventoryTooFragmented
            | QuoteAdmissionError::TooManyProviderInputs => rpc_error(
                RpcErrorCode::InsufficientInventory,
                "provider has insufficient eligible inventory",
            ),
            QuoteAdmissionError::SelectionSearchBudgetExceeded => rpc_error(
                RpcErrorCode::BackendUnavailable,
                "provider quote selection budget was exhausted",
            ),
            _ => rpc_error(
                RpcErrorCode::InternalError,
                "provider could not derive a valid quote",
            ),
        },
        QuoteEngineError::Inventory(_)
        | QuoteEngineError::Destination(_)
        | QuoteEngineError::Pricing(_) => rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider quote backend is temporarily unavailable",
        ),
    }
}

fn map_provider_error(error: &deadcat_rfq_provider::ProviderError) -> RpcError {
    tracing::warn!(error = %error, "provider state operation failed");
    use deadcat_rfq_provider::ProviderError;
    match error {
        ProviderError::ReservationNotFound(_) | ProviderError::ReservationOwnerMismatch(_) => {
            rpc_error(
                RpcErrorCode::ReservationUnavailable,
                "reservation is unavailable",
            )
        }
        ProviderError::ReservationAlreadyReleased(_) => rpc_error(
            RpcErrorCode::ReservationReleased,
            "reservation has been released",
        ),
        ProviderError::PointOfNoReturn(_) | ProviderError::DifferentSigningIntent(_) => rpc_error(
            RpcErrorCode::PointOfNoReturn,
            "reservation crossed the signing point of no return",
        ),
        ProviderError::ReservationDeadlineElapsed { .. } => {
            rpc_error(RpcErrorCode::QuoteExpired, "firm quote has expired")
        }
        ProviderError::IdempotencyConflict { .. } => rpc_error(
            RpcErrorCode::IdempotencyConflict,
            "idempotency key was reused with different terms",
        ),
        ProviderError::OwnerLiveQuoteLimit { .. } | ProviderError::GlobalLiveQuoteLimit { .. } => {
            rpc_error(
                RpcErrorCode::LiveQuoteLimit,
                "provider live quote limit reached",
            )
        }
        ProviderError::FeePolicy(_) => rpc_error(
            RpcErrorCode::FeePolicyRejected,
            "settlement fee policy rejected the transaction",
        ),
        ProviderError::EligibleInventoryChanged => rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider inventory changed while constructing the quote",
        ),
        _ => rpc_error(
            RpcErrorCode::InternalError,
            "provider durable state operation failed",
        ),
    }
}

fn map_blinding_error<S>(error: ProviderBlindingError<S>) -> RpcError
where
    S: Error + Send + Sync + 'static,
{
    tracing::warn!(error = %error, "provider blinding rejected");
    match error {
        ProviderBlindingError::Provider(error) => map_provider_error(&error),
        ProviderBlindingError::PointOfNoReturn(_) => rpc_error(
            RpcErrorCode::PointOfNoReturn,
            "reservation crossed the signing point of no return",
        ),
        ProviderBlindingError::Settlement(error) => map_settlement_error(error),
        ProviderBlindingError::Inventory(_) => rpc_error(
            RpcErrorCode::BackendUnavailable,
            "provider inventory is temporarily unavailable",
        ),
        _ => rpc_error(
            RpcErrorCode::InvalidPset,
            "PSET cannot be blinded for this reservation",
        ),
    }
}

fn map_settlement_error(error: SettlementValidationError) -> RpcError {
    tracing::warn!(error = %error, "settlement validation rejected");
    match error {
        SettlementValidationError::Provider(error) => map_provider_error(&error),
        SettlementValidationError::LayoutIndexOutOfRange
        | SettlementValidationError::LayoutInputMismatch
        | SettlementValidationError::LayoutOutputMismatch => rpc_error(
            RpcErrorCode::InvalidLayout,
            "settlement layout does not match the firm quote",
        ),
        SettlementValidationError::FeePolicy(_) => rpc_error(
            RpcErrorCode::FeePolicyRejected,
            "settlement fee policy rejected the transaction",
        ),
        SettlementValidationError::ChainSource(_)
        | SettlementValidationError::AuthoritativePrevoutCount { .. }
        | SettlementValidationError::AuthoritativePrevoutMismatch(_)
        | SettlementValidationError::WrongChain { .. } => rpc_error(
            RpcErrorCode::BackendUnavailable,
            "authoritative settlement chain state is temporarily unavailable",
        ),
        _ => rpc_error(RpcErrorCode::InvalidPset, "settlement PSET is invalid"),
    }
}

fn invalid_request() -> RpcError {
    rpc_error(RpcErrorCode::InvalidRequest, "invalid RFQ request")
}

fn rpc_error(code: RpcErrorCode, message: &'static str) -> RpcError {
    RpcError::new(code, message).expect("static runtime RPC error satisfies public bounds")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    use deadcat_rfq_rpc::{FixedBytes33, InputPlacementDto, OutputPlacementDto};
    use deadcat_types::ContractId;
    use elements::hashes::Hash as _;
    use elements::pset::PartiallySignedTransaction;
    use elements::{AssetId, BlockHash, OutPoint, Txid};

    use super::*;

    #[derive(Default)]
    struct ExecuteState {
        entered: AtomicBool,
        completed: AtomicBool,
        release: Mutex<bool>,
        wake: Condvar,
    }

    #[derive(Default)]
    struct RecoveryState {
        block: AtomicBool,
        entered: AtomicBool,
        release: Mutex<bool>,
        wake: Condvar,
    }

    #[derive(Default)]
    struct StatusState {
        block: AtomicBool,
        entered: AtomicBool,
        completed: AtomicBool,
        release: Mutex<bool>,
        wake: Condvar,
    }

    #[derive(Default)]
    struct QuoteState {
        block: AtomicBool,
        entered: AtomicBool,
        completed: AtomicBool,
        release: Mutex<bool>,
        wake: Condvar,
    }

    struct FakeBackend {
        provider: EndpointId,
        owners: Arc<Mutex<Vec<FixedBytes32>>>,
        recoveries: Arc<AtomicUsize>,
        startup_events: Arc<Mutex<Vec<&'static str>>>,
        recovery_fails: Arc<AtomicBool>,
        recovery: Arc<RecoveryState>,
        quote: Arc<QuoteState>,
        status: Arc<StatusState>,
        execute: Arc<ExecuteState>,
    }

    impl FakeBackend {
        fn status() -> ReservationStatusDto {
            ReservationStatusDto {
                reservation_id: FixedBytes32::new([7; 32]),
                quote_commitment: FixedBytes32::new([8; 32]),
                created_at_millis: 1_000,
                accept_before_millis: 2_000,
                state: ReservationStateDto::Reserved,
            }
        }

        fn record(&self, owner: FixedBytes32) {
            self.owners.lock().expect("owner lock").push(owner);
        }
    }

    impl RfqBackend for FakeBackend {
        fn info(&self) -> Result<ProviderInfo, RpcError> {
            Ok(ProviderInfo {
                provider_endpoint: FixedBytes32::new(*self.provider.as_bytes()),
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_byte_array([1; 32]),
                policy_asset: AssetId::from_byte_array([2; 32]),
                capabilities: vec![ProviderCapability::DurableStatus],
            })
        }

        fn refresh_inventory(&self) -> Result<(), RpcError> {
            self.startup_events.lock().expect("events").push("refresh");
            Ok(())
        }

        fn recover_pending(&self, _limit: usize) -> Result<usize, RpcError> {
            self.startup_events.lock().expect("events").push("recover");
            self.recoveries.fetch_add(1, Ordering::SeqCst);
            if self.recovery.block.load(Ordering::SeqCst) {
                self.recovery.entered.store(true, Ordering::SeqCst);
                self.recovery.wake.notify_all();
                let mut release = self.recovery.release.lock().expect("recovery lock");
                while !*release {
                    release = self.recovery.wake.wait(release).expect("recovery wait");
                }
            }
            if self.recovery_fails.load(Ordering::SeqCst) {
                return Err(rpc_error(
                    RpcErrorCode::BackendUnavailable,
                    "injected signer failure",
                ));
            }
            Ok(0)
        }

        fn quote(
            &self,
            _owner: FixedBytes32,
            _idempotency_key: IdempotencyKeyDto,
            _request: FirmQuoteRequestDto,
        ) -> Result<(FirmQuoteDto, ReservationStatusDto), RpcError> {
            if self.quote.block.load(Ordering::SeqCst) {
                self.quote.entered.store(true, Ordering::SeqCst);
                self.quote.wake.notify_all();
                let mut release = self.quote.release.lock().expect("quote lock");
                while !*release {
                    release = self.quote.wake.wait(release).expect("quote wait");
                }
                self.quote.completed.store(true, Ordering::SeqCst);
            }
            Err(rpc_error(
                RpcErrorCode::UnsupportedMarket,
                "test backend has no markets",
            ))
        }

        fn cancel(
            &self,
            owner: FixedBytes32,
            _reservation_id: FixedBytes32,
        ) -> Result<ReservationStatusDto, RpcError> {
            self.record(owner);
            Ok(Self::status())
        }

        fn blind(
            &self,
            owner: FixedBytes32,
            _reservation_id: FixedBytes32,
            _layout: SettlementLayoutDto,
            pset: SettlementPset,
        ) -> Result<SettlementPset, RpcError> {
            self.record(owner);
            Ok(pset)
        }

        fn commit_execute(
            &self,
            owner: FixedBytes32,
            _reservation_id: FixedBytes32,
            _layout: SettlementLayoutDto,
            _pset: SettlementPset,
        ) -> Result<ReservationStatusDto, RpcError> {
            self.record(owner);
            self.execute.entered.store(true, Ordering::SeqCst);
            self.execute.wake.notify_all();
            let mut release = self.execute.release.lock().expect("execute lock");
            while !*release {
                release = self.execute.wake.wait(release).expect("execute wait");
            }
            self.execute.completed.store(true, Ordering::SeqCst);
            Ok(Self::status())
        }

        fn status(
            &self,
            owner: FixedBytes32,
            _reservation_id: FixedBytes32,
        ) -> Result<ReservationStatusDto, RpcError> {
            self.record(owner);
            if self.status.block.load(Ordering::SeqCst) {
                self.status.entered.store(true, Ordering::SeqCst);
                self.status.wake.notify_all();
                let mut release = self.status.release.lock().expect("status lock");
                while !*release {
                    release = self.status.wake.wait(release).expect("status wait");
                }
                self.status.completed.store(true, Ordering::SeqCst);
            }
            Ok(Self::status())
        }
    }

    struct FakeHarness {
        backend: FakeBackend,
        owners: Arc<Mutex<Vec<FixedBytes32>>>,
        recoveries: Arc<AtomicUsize>,
        startup_events: Arc<Mutex<Vec<&'static str>>>,
        recovery_fails: Arc<AtomicBool>,
        recovery: Arc<RecoveryState>,
        quote: Arc<QuoteState>,
        status: Arc<StatusState>,
        execute: Arc<ExecuteState>,
    }

    fn fake_backend(provider: EndpointId) -> FakeHarness {
        let owners = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(AtomicUsize::new(0));
        let startup_events = Arc::new(Mutex::new(Vec::new()));
        let recovery_fails = Arc::new(AtomicBool::new(false));
        let recovery = Arc::new(RecoveryState::default());
        let quote = Arc::new(QuoteState::default());
        let status = Arc::new(StatusState::default());
        let execute = Arc::new(ExecuteState::default());
        FakeHarness {
            backend: FakeBackend {
                provider,
                owners: Arc::clone(&owners),
                recoveries: Arc::clone(&recoveries),
                startup_events: Arc::clone(&startup_events),
                recovery_fails: Arc::clone(&recovery_fails),
                recovery: Arc::clone(&recovery),
                quote: Arc::clone(&quote),
                status: Arc::clone(&status),
                execute: Arc::clone(&execute),
            },
            owners,
            recoveries,
            startup_events,
            recovery_fails,
            recovery,
            quote,
            status,
            execute,
        }
    }

    fn execute_request() -> Request {
        Request::Execute {
            reservation_id: FixedBytes32::new([7; 32]),
            layout: SettlementLayoutDto {
                taker_payment_input: 0,
                provider_inputs: vec![InputPlacementDto {
                    quote_input_id: 1,
                    transaction_index: 1,
                }],
                quote_outputs: vec![OutputPlacementDto {
                    quote_output_id: 1,
                    transaction_index: 0,
                }],
            },
            pset: SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
                .expect("test PSET"),
        }
    }

    fn quote_request() -> Request {
        Request::RequestFirmQuote {
            idempotency_key: FixedBytes32::new([6; 32]),
            request: FirmQuoteRequestDto {
                context: QuoteContextDto {
                    network: LiquidNetwork::ElementsRegtest,
                    genesis_hash: BlockHash::from_byte_array([1; 32]),
                    market: ContractId::new(OutPoint::new(Txid::from_byte_array([3; 32]), 0)),
                    policy_asset: AssetId::from_byte_array([2; 32]),
                },
                kind: QuoteKindDto::ExactIn {
                    input: AssetAmountDto {
                        asset: AssetId::from_byte_array([2; 32]),
                        amount: 100,
                    },
                    output_asset: AssetId::from_byte_array([4; 32]),
                    minimum_output: 90,
                },
                recipient: QuoteRecipientDto {
                    script_pubkey: vec![0x51],
                    blinding_public_key: FixedBytes33::new([2; 33]),
                },
                maximum_input_asset_venue_fee: 10,
            },
        }
    }

    fn blind_request() -> Request {
        let Request::Execute {
            reservation_id,
            layout,
            pset,
        } = execute_request()
        else {
            unreachable!("execute fixture")
        };
        Request::BlindPset {
            reservation_id,
            layout,
            pset,
        }
    }

    async fn wait_for(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !flag.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("state transition before timeout");
    }

    #[tokio::test]
    async fn derives_owner_from_both_authenticated_endpoints() {
        let provider_key = SecretKey::from_bytes(&[11; 32]);
        let client = SecretKey::from_bytes(&[12; 32]).public();
        let FakeHarness {
            backend,
            owners,
            recoveries,
            startup_events,
            ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start_with_limits(
            backend,
            provider_key.clone(),
            2,
            Duration::from_secs(60),
        )
        .await
        .expect("handler");
        assert_eq!(recoveries.load(Ordering::SeqCst), 1);
        assert_eq!(
            startup_events.lock().expect("events").as_slice(),
            ["refresh", "recover"]
        );

        let response = handler
            .handle(
                *client.as_bytes(),
                Request::GetReservationStatus {
                    reservation_id: FixedBytes32::new([7; 32]),
                },
            )
            .await
            .expect("status");
        assert!(matches!(response, Response::ReservationStatus { .. }));
        assert_eq!(
            owners.lock().expect("owners").as_slice(),
            &[owner_id_from_endpoints(provider_key.public(), client)]
        );
    }

    #[tokio::test]
    async fn execute_survives_transport_future_cancellation() {
        let provider_key = SecretKey::from_bytes(&[21; 32]);
        let client = SecretKey::from_bytes(&[22; 32]).public();
        let FakeHarness {
            backend, execute, ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start_with_limits(
            backend,
            provider_key,
            2,
            Duration::from_secs(60),
        )
        .await
        .expect("handler");

        let request_handler = handler.clone();
        let transport_future = tokio::spawn(async move {
            request_handler
                .handle(*client.as_bytes(), execute_request())
                .await
        });
        wait_for(&execute.entered).await;
        transport_future.abort();
        transport_future
            .await
            .expect_err("transport future cancelled");

        *execute.release.lock().expect("execute release") = true;
        execute.wake.notify_all();
        wait_for(&execute.completed).await;
    }

    #[tokio::test]
    async fn rejects_transport_identity_mismatch_before_serving() {
        let provider_key = SecretKey::from_bytes(&[31; 32]);
        let other_key = SecretKey::from_bytes(&[32; 32]);
        let FakeHarness { backend, .. } = fake_backend(provider_key.public());
        assert!(matches!(
            AuthenticatedRfqHandler::start_with_limits(
                backend,
                other_key,
                1,
                Duration::from_secs(1),
            )
            .await,
            Err(HandlerStartError::TransportIdentityMismatch)
        ));
    }

    #[tokio::test]
    async fn canonical_server_binding_uses_the_attestation_identity() {
        let provider_key = SecretKey::from_bytes(&[33; 32]);
        let expected_endpoint = provider_key.public();
        let FakeHarness { backend, .. } = fake_backend(expected_endpoint);
        let handler = Arc::new(
            AuthenticatedRfqHandler::start(backend, provider_key)
                .await
                .expect("handler"),
        );

        let server = Arc::clone(&handler)
            .bind_server(DiscoveryMode::Disabled, ServerConfig::default())
            .await
            .expect("server");
        assert_eq!(server.endpoint_id(), expected_endpoint);

        server
            .spawn()
            .shutdown_and_join()
            .await
            .expect("server shutdown");
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn signer_degradation_stops_quote_and_execute_admission() {
        let provider_key = SecretKey::from_bytes(&[41; 32]);
        let client = SecretKey::from_bytes(&[42; 32]).public();
        let FakeHarness {
            backend,
            recovery_fails,
            execute,
            ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start_with_limits(
            backend,
            provider_key,
            2,
            Duration::from_secs(60),
        )
        .await
        .expect("handler");
        *execute.release.lock().expect("execute release") = true;
        recovery_fails.store(true, Ordering::SeqCst);

        handler
            .handle(*client.as_bytes(), execute_request())
            .await
            .expect("commit accepted before signer failure is observed");
        tokio::time::timeout(Duration::from_secs(2), async {
            while handler.admission.read().await.signer_healthy {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("signer degradation observed");

        let quote_error = handler
            .handle(*client.as_bytes(), quote_request())
            .await
            .expect_err("new quote must be rejected");
        assert_eq!(quote_error.code(), RpcErrorCode::BackendUnavailable);
        let blind_error = handler
            .handle(*client.as_bytes(), blind_request())
            .await
            .expect_err("new blinding must be rejected");
        assert_eq!(blind_error.code(), RpcErrorCode::BackendUnavailable);
        let error = handler
            .handle(*client.as_bytes(), execute_request())
            .await
            .expect_err("new execute must be rejected");
        assert_eq!(error.code(), RpcErrorCode::BackendUnavailable);
        tokio::time::timeout(Duration::from_secs(1), handler.shutdown())
            .await
            .expect("persistent signer failure cannot hang shutdown");
    }

    #[tokio::test]
    async fn signer_health_transition_waits_for_in_flight_commit_boundary() {
        let provider_key = SecretKey::from_bytes(&[81; 32]);
        let client = SecretKey::from_bytes(&[82; 32]).public();
        let FakeHarness {
            backend, execute, ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start(backend, provider_key)
            .await
            .expect("handler");

        let execute_handler = handler.clone();
        let execution = tokio::spawn(async move {
            execute_handler
                .handle(*client.as_bytes(), execute_request())
                .await
        });
        wait_for(&execute.entered).await;

        let degradation_admission = Arc::clone(&handler.admission);
        let degradation = tokio::spawn(mark_signer_degraded(degradation_admission));
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !degradation.is_finished(),
            "degradation cannot become visible midway through commit"
        );

        *execute.release.lock().expect("execute release") = true;
        execute.wake.notify_all();
        execution
            .await
            .expect("execute task")
            .expect("in-flight commit finishes");
        degradation.await.expect("degradation transition");
        assert!(!handler.admission.read().await.signer_healthy);
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn blocked_signer_does_not_block_unrelated_execute_commit() {
        let provider_key = SecretKey::from_bytes(&[61; 32]);
        let client = SecretKey::from_bytes(&[62; 32]).public();
        let FakeHarness {
            backend,
            recovery,
            execute,
            ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start(backend, provider_key)
            .await
            .expect("handler");
        *execute.release.lock().expect("execute release") = true;
        recovery.block.store(true, Ordering::SeqCst);

        handler
            .handle(*client.as_bytes(), execute_request())
            .await
            .expect("first execute commits");
        wait_for(&recovery.entered).await;

        tokio::time::timeout(
            Duration::from_secs(1),
            handler.handle(*client.as_bytes(), execute_request()),
        )
        .await
        .expect("execute commit is independent from signer")
        .expect("second execute commits");

        *recovery.release.lock().expect("recovery release") = true;
        recovery.wake.notify_all();
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_blocking_request_retains_its_admission_permit() {
        let provider_key = SecretKey::from_bytes(&[71; 32]);
        let client = SecretKey::from_bytes(&[72; 32]).public();
        let FakeHarness {
            backend, status, ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start_with_config(
            backend,
            provider_key,
            HandlerConfig {
                execute_queue_capacity: 1,
                max_blocking_operations: 1,
                recovery_batch_size: 1,
                recovery_interval: Duration::from_secs(60),
                inventory_refresh_interval: Duration::from_secs(60),
            },
        )
        .await
        .expect("handler");
        status.block.store(true, Ordering::SeqCst);

        let first_handler = handler.clone();
        let first = tokio::spawn(async move {
            first_handler
                .handle(
                    *client.as_bytes(),
                    Request::GetReservationStatus {
                        reservation_id: FixedBytes32::new([7; 32]),
                    },
                )
                .await
        });
        wait_for(&status.entered).await;
        first.abort();
        first.await.expect_err("transport request cancelled");

        let error = handler
            .handle(
                *client.as_bytes(),
                Request::GetReservationStatus {
                    reservation_id: FixedBytes32::new([7; 32]),
                },
            )
            .await
            .expect_err("detached blocking work still consumes capacity");
        assert_eq!(error.code(), RpcErrorCode::RateLimited);

        *status.release.lock().expect("status release") = true;
        status.wake.notify_all();
        wait_for(&status.completed).await;
        handler.shutdown().await;
    }

    #[tokio::test]
    async fn cancelled_quote_retains_the_shutdown_admission_barrier() {
        let provider_key = SecretKey::from_bytes(&[73; 32]);
        let client = SecretKey::from_bytes(&[74; 32]).public();
        let FakeHarness { backend, quote, .. } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start(backend, provider_key)
            .await
            .expect("handler");
        quote.block.store(true, Ordering::SeqCst);

        let quote_handler = handler.clone();
        let request = tokio::spawn(async move {
            quote_handler
                .handle(*client.as_bytes(), quote_request())
                .await
        });
        wait_for(&quote.entered).await;
        request.abort();
        request.await.expect_err("transport request cancelled");

        let shutdown_handler = handler.clone();
        let shutdown = tokio::spawn(async move { shutdown_handler.shutdown().await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !shutdown.is_finished(),
            "detached quote work must retain the shutdown barrier"
        );

        *quote.release.lock().expect("quote release") = true;
        quote.wake.notify_all();
        wait_for(&quote.completed).await;
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown completes after detached quote")
            .expect("shutdown task");
    }

    #[tokio::test]
    async fn shutdown_joins_daemon_workers_and_closes_execute_admission() {
        let provider_key = SecretKey::from_bytes(&[51; 32]);
        let client = SecretKey::from_bytes(&[52; 32]).public();
        let FakeHarness { backend, .. } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start(backend, provider_key)
            .await
            .expect("handler");
        handler.shutdown().await;
        let error = handler
            .handle(*client.as_bytes(), execute_request())
            .await
            .expect_err("execute supervisor is closed");
        assert_eq!(error.code(), RpcErrorCode::BackendUnavailable);

        let quote_error = handler
            .handle(*client.as_bytes(), quote_request())
            .await
            .expect_err("quote admission remains closed after shutdown");
        assert_eq!(quote_error.code(), RpcErrorCode::BackendUnavailable);

        assert!(matches!(
            handler
                .handle(*client.as_bytes(), Request::GetInfo)
                .await
                .expect("safe info remains available"),
            Response::Info { .. }
        ));
    }

    #[tokio::test]
    async fn shutdown_waits_for_in_flight_commit_then_drains_signing() {
        let provider_key = SecretKey::from_bytes(&[91; 32]);
        let client = SecretKey::from_bytes(&[92; 32]).public();
        let FakeHarness {
            backend,
            recoveries,
            execute,
            ..
        } = fake_backend(provider_key.public());
        let handler = AuthenticatedRfqHandler::start(backend, provider_key)
            .await
            .expect("handler");

        let execute_handler = handler.clone();
        let execution = tokio::spawn(async move {
            execute_handler
                .handle(*client.as_bytes(), execute_request())
                .await
        });
        wait_for(&execute.entered).await;

        let shutdown_handler = handler.clone();
        let shutdown = tokio::spawn(async move { shutdown_handler.shutdown().await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!shutdown.is_finished());

        *execute.release.lock().expect("execute release") = true;
        execute.wake.notify_all();
        execution
            .await
            .expect("execute task")
            .expect("in-flight commit finishes");
        shutdown.await.expect("graceful shutdown");
        assert!(execute.completed.load(Ordering::SeqCst));
        assert!(
            recoveries.load(Ordering::SeqCst) >= 2,
            "startup recovery plus final shutdown drain"
        );
    }

    #[test]
    fn transient_provider_and_chain_contradictions_are_retryable() {
        type TestQuoteError = QuoteEngineError<std::io::Error, std::io::Error, std::io::Error>;

        let selection = map_quote_error(TestQuoteError::Admission(
            QuoteAdmissionError::SelectionSearchBudgetExceeded,
        ));
        assert_eq!(selection.code(), RpcErrorCode::BackendUnavailable);

        let changed = map_quote_error(TestQuoteError::Provider(
            deadcat_rfq_provider::ProviderError::EligibleInventoryChanged,
        ));
        assert_eq!(changed.code(), RpcErrorCode::BackendUnavailable);

        for error in [
            SettlementValidationError::AuthoritativePrevoutCount {
                expected: 1,
                actual: 0,
            },
            SettlementValidationError::AuthoritativePrevoutMismatch(0),
            SettlementValidationError::WrongChain {
                expected: BlockHash::from_byte_array([1; 32]),
                actual: BlockHash::from_byte_array([2; 32]),
            },
        ] {
            assert_eq!(
                map_settlement_error(error).code(),
                RpcErrorCode::BackendUnavailable
            );
        }
    }
}
