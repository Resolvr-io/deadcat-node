//! Authenticated RFQ transport sessions and durable reservation bindings.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use deadcat_rfq_iroh::{Client, ClientConfig, ClientError};
use deadcat_rfq_rpc::{
    AttestationError, FirmQuoteDto, FirmQuoteRequestDto, FirmQuoteValidationError, FixedBytes32,
    IdempotencyKeyDto, LiveFirmQuote, ProviderCapability, ProviderInfo, Request, RequestEnvelope,
    RequestId, ReservationIdDto, ReservationStatusDto, Response, SettlementLayoutDto,
    SettlementPset, SignedFirmQuote, VerifiedFirmQuote,
};
use deadcat_types::ChainIdentity;
use elements::AssetId;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use thiserror::Error;

use crate::settlement::{
    ExecutionAttempt, ExecutionAttemptDigest, ExecutionAttemptError, ProviderBlindedPset,
};

const STARTUP_REQUEST_ID: u64 = 1;
const REQUIRED_CAPABILITIES: [ProviderCapability; 4] = [
    ProviderCapability::FirmQuotes,
    ProviderCapability::ProviderBlinding,
    ProviderCapability::SettlementExecution,
    ProviderCapability::DurableStatus,
];

/// Pinned provider address and the chain context expected from that provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderTarget {
    endpoint: EndpointAddr,
    chain: ChainIdentity,
    policy_asset: AssetId,
}

impl ProviderTarget {
    #[must_use]
    pub const fn new(endpoint: EndpointAddr, chain: ChainIdentity, policy_asset: AssetId) -> Self {
        Self {
            endpoint,
            chain,
            policy_asset,
        }
    }

    #[must_use]
    pub const fn endpoint(&self) -> &EndpointAddr {
        &self.endpoint
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id
    }

    #[must_use]
    pub const fn chain(&self) -> ChainIdentity {
        self.chain
    }

    #[must_use]
    pub const fn policy_asset(&self) -> AssetId {
        self.policy_asset
    }
}

/// Transport limits plus local policy for accepting provider quote clocks.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    transport: ClientConfig,
    max_quote_lifetime_millis: u64,
    max_future_clock_skew_millis: u64,
}

impl SessionConfig {
    pub fn new(
        transport: ClientConfig,
        max_quote_lifetime_millis: u64,
        max_future_clock_skew_millis: u64,
    ) -> Result<Self, SessionError> {
        if max_quote_lifetime_millis == 0 {
            return Err(SessionError::InvalidConfig(
                "max_quote_lifetime_millis must be positive",
            ));
        }
        if max_future_clock_skew_millis == 0 {
            return Err(SessionError::InvalidConfig(
                "max_future_clock_skew_millis must be positive",
            ));
        }
        Ok(Self {
            transport,
            max_quote_lifetime_millis,
            max_future_clock_skew_millis,
        })
    }

    #[must_use]
    pub const fn transport(&self) -> &ClientConfig {
        &self.transport
    }

    #[must_use]
    pub const fn max_quote_lifetime_millis(&self) -> u64 {
        self.max_quote_lifetime_millis
    }

    #[must_use]
    pub const fn max_future_clock_skew_millis(&self) -> u64 {
        self.max_future_clock_skew_millis
    }
}

/// Stable identity binding copied out of an authenticated firm quote.
///
/// Status methods require this handle rather than a bare reservation ID so a
/// valid response for a different replay or reservation cannot be confused
/// with the record the caller is recovering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationHandle {
    provider_endpoint: EndpointId,
    client_endpoint: EndpointId,
    chain: ChainIdentity,
    policy_asset: AssetId,
    reservation_id: ReservationIdDto,
    quote_commitment: FixedBytes32,
    created_at_millis: u64,
    accept_before_millis: u64,
}

impl ReservationHandle {
    fn from_quote(
        quote: &FirmQuoteDto,
        provider_endpoint: EndpointId,
        client_endpoint: EndpointId,
    ) -> Self {
        Self {
            provider_endpoint,
            client_endpoint,
            chain: ChainIdentity {
                network: quote.network,
                genesis_hash: quote.genesis_hash,
            },
            policy_asset: quote.policy_asset,
            reservation_id: quote.reservation_id,
            quote_commitment: quote.quote_commitment,
            created_at_millis: quote.created_at_millis,
            accept_before_millis: quote.accept_before_millis,
        }
    }

    #[must_use]
    pub const fn provider_endpoint(&self) -> EndpointId {
        self.provider_endpoint
    }

    #[must_use]
    pub const fn client_endpoint(&self) -> EndpointId {
        self.client_endpoint
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
    pub const fn reservation_id(&self) -> ReservationIdDto {
        self.reservation_id
    }

    #[must_use]
    pub const fn quote_commitment(&self) -> FixedBytes32 {
        self.quote_commitment
    }

    #[must_use]
    pub const fn created_at_millis(&self) -> u64 {
        self.created_at_millis
    }

    #[must_use]
    pub const fn accept_before_millis(&self) -> u64 {
        self.accept_before_millis
    }

    /// Validate both the status structure and every durable quote binding.
    pub fn validate_status(&self, status: &ReservationStatusDto) -> Result<(), SessionError> {
        status
            .validate()
            .map_err(SessionError::InvalidReservationStatus)?;
        if status.reservation_id != self.reservation_id {
            return Err(SessionError::ReservationBindingMismatch("reservation_id"));
        }
        if status.quote_commitment != self.quote_commitment {
            return Err(SessionError::ReservationBindingMismatch("quote_commitment"));
        }
        if status.created_at_millis != self.created_at_millis {
            return Err(SessionError::ReservationBindingMismatch(
                "created_at_millis",
            ));
        }
        if status.accept_before_millis != self.accept_before_millis {
            return Err(SessionError::ReservationBindingMismatch(
                "accept_before_millis",
            ));
        }
        Ok(())
    }

    fn validate_context(
        &self,
        provider_endpoint: EndpointId,
        client_endpoint: EndpointId,
        chain: ChainIdentity,
        policy_asset: AssetId,
    ) -> Result<(), SessionError> {
        if self.provider_endpoint != provider_endpoint {
            return Err(SessionError::HandleProviderMismatch);
        }
        if self.client_endpoint != client_endpoint {
            return Err(SessionError::HandleClientMismatch);
        }
        if self.chain != chain {
            return Err(SessionError::HandleChainMismatch);
        }
        if self.policy_asset != policy_asset {
            return Err(SessionError::HandlePolicyAssetMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuoteClockPolicyRejection {
    TrustedClockUnavailable,
    InvalidTimeline,
    LifetimeExceeded {
        actual_millis: u64,
        maximum_millis: u64,
    },
    ClockTooFarAhead {
        created_at_millis: u64,
        received_at_millis: u64,
        maximum_skew_millis: u64,
    },
}

impl QuoteClockPolicyRejection {
    const fn into_session_error(self) -> SessionError {
        match self {
            Self::TrustedClockUnavailable => SessionError::TrustedClockUnavailable,
            Self::InvalidTimeline => SessionError::InvalidQuoteTimeline,
            Self::LifetimeExceeded {
                actual_millis,
                maximum_millis,
            } => SessionError::QuoteLifetimeExceeded {
                actual_millis,
                maximum_millis,
            },
            Self::ClockTooFarAhead {
                created_at_millis,
                received_at_millis,
                maximum_skew_millis,
            } => SessionError::QuoteClockTooFarAhead {
                created_at_millis,
                now_millis: received_at_millis,
                maximum_skew_millis,
            },
        }
    }
}

struct AuthenticatedQuote {
    quote: VerifiedFirmQuote,
    handle: ReservationHandle,
    received_at_millis: Option<u64>,
    clock_policy_rejection: Option<QuoteClockPolicyRejection>,
}

impl AuthenticatedQuote {
    fn new(
        quote: VerifiedFirmQuote,
        handle: ReservationHandle,
        config: &SessionConfig,
        received_at_millis: Option<u64>,
    ) -> Self {
        Self {
            clock_policy_rejection: match received_at_millis {
                Some(received_at_millis) => quote_clock_policy_rejection(
                    config,
                    quote.quote().created_at_millis,
                    quote.quote().accept_before_millis,
                    received_at_millis,
                ),
                None => Some(QuoteClockPolicyRejection::TrustedClockUnavailable),
            },
            quote,
            handle,
            received_at_millis,
        }
    }

    fn into_replay(self, status: ReservationStatusDto) -> Result<QuoteReplay, SessionError> {
        self.handle.validate_status(&status)?;
        Ok(QuoteReplay {
            quote: self.quote,
            handle: self.handle,
            status,
            received_at_millis: self.received_at_millis,
            clock_policy_rejection: self.clock_policy_rejection,
            trusted_time: TrustedTime::new(self.received_at_millis.unwrap_or(0)),
        })
    }
}

/// Monotonic high-water mark shared by every capability derived from one
/// authenticated replay.
///
/// Wall-clock readings may move backwards. Settlement authority must not: a
/// later observation that expires a quote cannot be bypassed through an older
/// clone or an already-minted live capability.
#[derive(Clone, Debug)]
struct TrustedTime(Arc<AtomicU64>);

impl TrustedTime {
    fn new(initial_millis: u64) -> Self {
        Self(Arc::new(AtomicU64::new(initial_millis)))
    }

    fn observe(&self, now_millis: u64) -> Result<(), SessionError> {
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |previous_millis| {
                (now_millis >= previous_millis).then_some(now_millis)
            })
            .map(|_| ())
            .map_err(|previous_millis| SessionError::ClockMovedBackwards {
                previous_millis,
                now_millis,
            })
    }
}

/// Authentic quote and initial durable status, retained even after expiry.
///
/// This is deliberately not itself settlement authority. Call [`Self::live_at`]
/// with a fresh trusted wall-clock reading before beginning settlement.
#[derive(Clone, Debug)]
pub struct QuoteReplay {
    quote: VerifiedFirmQuote,
    handle: ReservationHandle,
    status: ReservationStatusDto,
    received_at_millis: Option<u64>,
    clock_policy_rejection: Option<QuoteClockPolicyRejection>,
    trusted_time: TrustedTime,
}

impl QuoteReplay {
    #[must_use]
    pub const fn quote(&self) -> &VerifiedFirmQuote {
        &self.quote
    }

    #[must_use]
    pub const fn handle(&self) -> &ReservationHandle {
        &self.handle
    }

    #[must_use]
    pub const fn status(&self) -> &ReservationStatusDto {
        &self.status
    }

    /// Trusted wall time at which this signed quote was first received.
    #[must_use]
    pub const fn received_at_millis(&self) -> Option<u64> {
        self.received_at_millis
    }

    /// Reapply the local lifetime and provider-clock policy recorded when this
    /// quote was authenticated.
    ///
    /// A rejected quote remains authentic recovery evidence, but cannot be
    /// promoted to settlement authority.
    pub fn validate_clock_policy(&self) -> Result<(), SessionError> {
        match self.clock_policy_rejection {
            Some(rejection) => Err(rejection.into_session_error()),
            None => Ok(()),
        }
    }

    /// Convert authentic replay evidence into current settlement authority.
    ///
    /// The replay is borrowed, so an expiry error preserves the handle needed
    /// to poll durable status after a request or response timeout.
    pub fn live_at(&self, now_millis: u64) -> Result<LiveQuoteReservation, SessionError> {
        self.validate_clock_policy()?;
        self.trusted_time.observe(now_millis)?;
        if !matches!(
            &self.status.state,
            deadcat_rfq_rpc::ReservationStateDto::Reserved
        ) {
            return Err(SessionError::ReservationNotReserved);
        }
        Ok(LiveQuoteReservation {
            quote: self.quote.clone().live_at(now_millis)?,
            handle: self.handle,
            status: self.status.clone(),
            trusted_time: self.trusted_time.clone(),
        })
    }

    #[must_use]
    pub fn into_parts(self) -> (VerifiedFirmQuote, ReservationHandle, ReservationStatusDto) {
        (self.quote, self.handle, self.status)
    }
}

/// Authenticated reservation whose acceptance window was checked recently.
#[derive(Clone, Debug)]
pub struct LiveQuoteReservation {
    quote: LiveFirmQuote,
    handle: ReservationHandle,
    status: ReservationStatusDto,
    trusted_time: TrustedTime,
}

/// Final global settlement positions bound to one exact RFQ reservation.
///
/// Only the quote-to-route adapter can construct this capability. Session
/// methods compare its complete durable handle with the live reservation before
/// sending a provider-blinding or execute request, preventing similarly shaped
/// reservations from being cross-wired locally.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRfqSettlement {
    handle: ReservationHandle,
    layout: SettlementLayoutDto,
}

impl ResolvedRfqSettlement {
    pub(crate) const fn new(handle: ReservationHandle, layout: SettlementLayoutDto) -> Self {
        Self { handle, layout }
    }

    #[must_use]
    pub const fn handle(&self) -> &ReservationHandle {
        &self.handle
    }

    #[must_use]
    pub const fn layout(&self) -> &SettlementLayoutDto {
        &self.layout
    }
}

impl LiveQuoteReservation {
    #[must_use]
    pub const fn quote(&self) -> &LiveFirmQuote {
        &self.quote
    }

    #[must_use]
    pub const fn handle(&self) -> &ReservationHandle {
        &self.handle
    }

    #[must_use]
    pub const fn status(&self) -> &ReservationStatusDto {
        &self.status
    }

    #[must_use]
    pub fn into_parts(self) -> (LiveFirmQuote, ReservationHandle, ReservationStatusDto) {
        (self.quote, self.handle, self.status)
    }
}

/// Connected, provider-pinned RFQ session with collision-free request IDs.
pub struct RfqSession {
    client: Client,
    target: ProviderTarget,
    config: SessionConfig,
    provider_info: ProviderInfo,
    request_ids: RequestIds,
}

impl RfqSession {
    /// Connect through normal Iroh discovery and verify provider metadata.
    pub async fn connect(
        target: ProviderTarget,
        client_identity: SecretKey,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        let client = Client::connect(
            target.endpoint.clone(),
            client_identity,
            config.transport.clone(),
        )
        .await?;
        Self::initialize(client, target, config).await
    }

    /// Connect with relay and discovery disabled and verify provider metadata.
    pub async fn dial_direct(
        target: ProviderTarget,
        client_identity: SecretKey,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        let client = Client::dial_direct(
            target.endpoint.clone(),
            client_identity,
            config.transport.clone(),
        )
        .await?;
        Self::initialize(client, target, config).await
    }

    async fn initialize(
        client: Client,
        target: ProviderTarget,
        config: SessionConfig,
    ) -> Result<Self, SessionError> {
        let startup = verify_startup(&client, &target).await;
        let provider_info = match startup {
            Ok(info) => info,
            Err(error) => {
                client.close().await;
                return Err(error);
            }
        };
        Ok(Self {
            client,
            target,
            config,
            provider_info,
            request_ids: RequestIds::after_startup(),
        })
    }

    #[must_use]
    pub const fn target(&self) -> &ProviderTarget {
        &self.target
    }

    #[must_use]
    pub const fn config(&self) -> &SessionConfig {
        &self.config
    }

    #[must_use]
    pub const fn provider_info(&self) -> &ProviderInfo {
        &self.provider_info
    }

    #[must_use]
    pub fn client_endpoint_id(&self) -> EndpointId {
        self.client.endpoint_id()
    }

    #[must_use]
    pub fn provider_endpoint_id(&self) -> EndpointId {
        self.client.provider_endpoint_id()
    }

    /// Request and authenticate a quote using a post-response system-clock
    /// observation.
    ///
    /// Clock-policy or clock-read failures do not discard an otherwise
    /// authentic quote. Instead, the returned replay remains usable for durable
    /// status recovery while [`QuoteReplay::live_at`] refuses settlement.
    pub async fn quote(
        &self,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
    ) -> Result<QuoteReplay, SessionError> {
        self.quote_with_clock(idempotency_key, request, system_time_millis)
            .await
    }

    /// Request and authenticate a quote, sampling the supplied clock only
    /// after the complete provider response has arrived.
    ///
    /// This injection point exists so applications and tests can supply a
    /// trusted clock. Returning `None` records that no trusted observation was
    /// available: authentic replay and recovery bindings are still returned,
    /// but settlement promotion is denied.
    pub async fn quote_with_clock<F>(
        &self,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
        received_at: F,
    ) -> Result<QuoteReplay, SessionError>
    where
        F: FnOnce() -> Option<u64>,
    {
        self.validate_request_context(&request)?;
        let (signed_quote, status) = self.request_signed_quote(idempotency_key, &request).await?;
        let received_at_millis = received_at();
        let authenticated = self.authenticate_signed_quote(
            signed_quote,
            idempotency_key,
            &request,
            received_at_millis,
        )?;
        authenticated.into_replay(status)
    }

    /// Request and authenticate a quote with an exact caller-supplied receipt
    /// observation.
    ///
    /// This low-level override is intended for deterministic replay and tests.
    /// Production callers should prefer [`Self::quote`], which samples the
    /// clock after the network response rather than accepting a value that may
    /// have been computed before the request. Local policy rejection is
    /// retained with the authentic replay and enforced at promotion.
    pub async fn quote_at(
        &self,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
        received_at_millis: u64,
    ) -> Result<QuoteReplay, SessionError> {
        self.quote_with_clock(idempotency_key, request, || Some(received_at_millis))
            .await
    }

    /// Descriptive alias for [`Self::quote_at`].
    pub async fn request_firm_quote_at(
        &self,
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
        received_at_millis: u64,
    ) -> Result<QuoteReplay, SessionError> {
        self.quote_at(idempotency_key, request, received_at_millis)
            .await
    }

    /// Reauthenticate a persisted signed quote and recover its current durable
    /// status through a session using the same stable client identity.
    ///
    /// Callers must persist the exact original request, idempotency key, and
    /// trusted first-receipt time alongside the signed quote. The signed quote
    /// is borrowed so a transient status failure cannot destroy the caller's
    /// recovery artifact. Local clock-policy rejection is retained in the
    /// returned replay rather than discarding its authenticated handle.
    pub async fn recover_persisted_quote_at(
        &self,
        signed_quote: &SignedFirmQuote,
        idempotency_key: IdempotencyKeyDto,
        request: &FirmQuoteRequestDto,
        received_at_millis: u64,
    ) -> Result<QuoteReplay, SessionError> {
        self.validate_request_context(request)?;
        let authenticated = self.authenticate_signed_quote(
            signed_quote.clone(),
            idempotency_key,
            request,
            Some(received_at_millis),
        )?;
        let status = self.status(&authenticated.handle).await?;
        authenticated.into_replay(status)
    }

    /// Cancel a reservation and validate the complete returned binding.
    pub async fn cancel(
        &self,
        handle: &ReservationHandle,
    ) -> Result<ReservationStatusDto, SessionError> {
        self.validate_handle_context(handle)?;
        let response = self
            .call(Request::CancelReservation {
                reservation_id: handle.reservation_id,
            })
            .await?;
        let Response::ReservationCancelled { status } = response else {
            return Err(SessionError::UnexpectedResponse("reservation cancellation"));
        };
        handle.validate_status(&status)?;
        Ok(status)
    }

    /// Ask the provider to blind its part of a live settlement PSET.
    pub async fn blind_at(
        &self,
        reservation: &LiveQuoteReservation,
        settlement: &ResolvedRfqSettlement,
        pset: SettlementPset,
        now_millis: u64,
    ) -> Result<ProviderBlindedPset, SessionError> {
        self.validate_handle_context(&reservation.handle)?;
        validate_settlement_binding(&reservation.handle, settlement)?;
        validate_still_live(reservation, now_millis)?;
        settlement
            .layout
            .validate_for_quote(reservation.quote.quote())
            .map_err(SessionError::InvalidSettlementLayout)?;
        let response = self
            .call(Request::BlindPset {
                reservation_id: reservation.handle.reservation_id,
                layout: settlement.layout.clone(),
                pset,
            })
            .await?;
        let Response::BlindedPset {
            reservation_id,
            pset,
        } = response
        else {
            return Err(SessionError::UnexpectedResponse("blinded PSET"));
        };
        if reservation_id != reservation.handle.reservation_id {
            return Err(SessionError::ReservationBindingMismatch("reservation_id"));
        }
        Ok(ProviderBlindedPset::from_provider_response(
            settlement, pset,
        ))
    }

    /// Submit an exact, journalable taker-authorized attempt for provider
    /// validation and signing.
    ///
    /// Persist [`ExecutionAttempt::to_record`] before calling this method. The
    /// attempt is borrowed so every failure preserves the exact retry bytes.
    /// Once dispatch begins, any error is conservatively ambiguous: the daemon
    /// may already have queued or durably committed the attempt. Do not build a
    /// different attempt for the same reservation after
    /// [`ExecuteError::SubmissionUncertain`]. Poll status and retry only this
    /// exact attempt until a terminal release or matching future protocol
    /// commitment resolves the ambiguity.
    pub async fn execute_at(
        &self,
        reservation: &LiveQuoteReservation,
        settlement: &ResolvedRfqSettlement,
        attempt: &ExecutionAttempt,
        now_millis: u64,
    ) -> Result<ReservationStatusDto, ExecuteError> {
        self.validate_handle_context(&reservation.handle)
            .map_err(ExecuteError::BeforeSubmission)?;
        validate_settlement_binding(&reservation.handle, settlement)
            .map_err(ExecuteError::BeforeSubmission)?;
        attempt
            .validate_for_settlement(settlement)
            .map_err(SessionError::InvalidExecutionAttempt)
            .map_err(ExecuteError::BeforeSubmission)?;
        validate_still_live(reservation, now_millis).map_err(ExecuteError::BeforeSubmission)?;
        settlement
            .layout
            .validate_for_quote(reservation.quote.quote())
            .map_err(SessionError::InvalidSettlementLayout)
            .map_err(ExecuteError::BeforeSubmission)?;

        let request_id = self
            .request_ids
            .next()
            .map_err(ExecuteError::BeforeSubmission)?;
        let response = self
            .client
            .call(RequestEnvelope::new(
                request_id,
                Request::Execute {
                    reservation_id: reservation.handle.reservation_id,
                    layout: attempt.layout().clone(),
                    pset: attempt.pset().clone(),
                },
            ))
            .await
            .map_err(|source| ExecuteError::SubmissionUncertain {
                attempt: attempt.digest(),
                source: SessionError::Client(source),
            })?;
        let Response::ExecutionAccepted { status } = response else {
            return Err(ExecuteError::SubmissionUncertain {
                attempt: attempt.digest(),
                source: SessionError::UnexpectedResponse("settlement execution"),
            });
        };
        reservation
            .handle
            .validate_status(&status)
            .map_err(|source| ExecuteError::SubmissionUncertain {
                attempt: attempt.digest(),
                source,
            })?;
        Ok(status)
    }

    /// Recover the durable status for an authentic reservation replay.
    pub async fn status(
        &self,
        handle: &ReservationHandle,
    ) -> Result<ReservationStatusDto, SessionError> {
        self.validate_handle_context(handle)?;
        let response = self
            .call(Request::GetReservationStatus {
                reservation_id: handle.reservation_id,
            })
            .await?;
        let Response::ReservationStatus { status } = response else {
            return Err(SessionError::UnexpectedResponse("reservation status"));
        };
        handle.validate_status(&status)?;
        Ok(status)
    }

    pub async fn close(self) {
        self.client.close().await;
    }

    async fn call(&self, request: Request) -> Result<Response, SessionError> {
        let request_id = self.request_ids.next()?;
        self.client
            .call(RequestEnvelope::new(request_id, request))
            .await
            .map_err(SessionError::Client)
    }

    async fn request_signed_quote(
        &self,
        idempotency_key: IdempotencyKeyDto,
        request: &FirmQuoteRequestDto,
    ) -> Result<(SignedFirmQuote, ReservationStatusDto), SessionError> {
        let response = self
            .call(Request::RequestFirmQuote {
                idempotency_key,
                request: request.clone(),
            })
            .await?;
        let Response::FirmQuote { quote, status } = response else {
            return Err(SessionError::UnexpectedResponse("firm quote"));
        };
        Ok((quote, status))
    }

    fn validate_request_context(&self, request: &FirmQuoteRequestDto) -> Result<(), SessionError> {
        if request.context.network != self.target.chain.network
            || request.context.genesis_hash != self.target.chain.genesis_hash
            || request.context.policy_asset != self.target.policy_asset
        {
            return Err(SessionError::RequestContextMismatch);
        }
        Ok(())
    }

    fn validate_handle_context(&self, handle: &ReservationHandle) -> Result<(), SessionError> {
        handle.validate_context(
            self.client.provider_endpoint_id(),
            self.client.endpoint_id(),
            self.target.chain,
            self.target.policy_asset,
        )
    }

    fn authenticate_signed_quote(
        &self,
        signed_quote: SignedFirmQuote,
        idempotency_key: IdempotencyKeyDto,
        request: &FirmQuoteRequestDto,
        received_at_millis: Option<u64>,
    ) -> Result<AuthenticatedQuote, SessionError> {
        let quote = signed_quote.verify(
            self.target.endpoint_id(),
            self.client.endpoint_id(),
            idempotency_key,
            request,
        )?;
        let handle = ReservationHandle::from_quote(
            quote.quote(),
            self.client.provider_endpoint_id(),
            self.client.endpoint_id(),
        );
        self.validate_handle_context(&handle)?;
        Ok(AuthenticatedQuote::new(
            quote,
            handle,
            &self.config,
            received_at_millis,
        ))
    }
}

fn validate_settlement_binding(
    reservation: &ReservationHandle,
    settlement: &ResolvedRfqSettlement,
) -> Result<(), SessionError> {
    if settlement.handle != *reservation {
        return Err(SessionError::SettlementReservationMismatch);
    }
    Ok(())
}

fn validate_still_live(
    reservation: &LiveQuoteReservation,
    now_millis: u64,
) -> Result<(), SessionError> {
    reservation.trusted_time.observe(now_millis)?;
    reservation.quote.verified().live_at(now_millis)?;
    Ok(())
}

fn system_time_millis() -> Option<u64> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(elapsed.as_millis()).ok()
}

#[cfg(test)]
fn validate_quote_clock(
    config: &SessionConfig,
    created_at_millis: u64,
    accept_before_millis: u64,
    now_millis: u64,
) -> Result<(), SessionError> {
    match quote_clock_policy_rejection(config, created_at_millis, accept_before_millis, now_millis)
    {
        Some(rejection) => Err(rejection.into_session_error()),
        None => Ok(()),
    }
}

fn quote_clock_policy_rejection(
    config: &SessionConfig,
    created_at_millis: u64,
    accept_before_millis: u64,
    received_at_millis: u64,
) -> Option<QuoteClockPolicyRejection> {
    let Some(lifetime) = accept_before_millis.checked_sub(created_at_millis) else {
        return Some(QuoteClockPolicyRejection::InvalidTimeline);
    };
    if lifetime > config.max_quote_lifetime_millis {
        return Some(QuoteClockPolicyRejection::LifetimeExceeded {
            actual_millis: lifetime,
            maximum_millis: config.max_quote_lifetime_millis,
        });
    }
    let latest_creation = received_at_millis.saturating_add(config.max_future_clock_skew_millis);
    if created_at_millis > latest_creation {
        return Some(QuoteClockPolicyRejection::ClockTooFarAhead {
            created_at_millis,
            received_at_millis,
            maximum_skew_millis: config.max_future_clock_skew_millis,
        });
    }
    None
}

async fn verify_startup(
    client: &Client,
    target: &ProviderTarget,
) -> Result<ProviderInfo, SessionError> {
    let actual_peer = client.provider_endpoint_id();
    if actual_peer != target.endpoint_id() {
        return Err(SessionError::PeerEndpointMismatch {
            expected: target.endpoint_id(),
            actual: actual_peer,
        });
    }
    let response = client
        .call(RequestEnvelope::new(
            RequestId(STARTUP_REQUEST_ID),
            Request::GetInfo,
        ))
        .await?;
    let Response::Info { info } = response else {
        return Err(SessionError::UnexpectedResponse("provider info"));
    };
    let expected_endpoint = FixedBytes32::new(*target.endpoint_id().as_bytes());
    if info.provider_endpoint != expected_endpoint {
        return Err(SessionError::InfoEndpointMismatch {
            expected: expected_endpoint,
            actual: info.provider_endpoint,
        });
    }
    let actual_chain = ChainIdentity {
        network: info.network,
        genesis_hash: info.genesis_hash,
    };
    if actual_chain != target.chain {
        return Err(SessionError::ChainMismatch {
            expected: target.chain,
            actual: actual_chain,
        });
    }
    if info.policy_asset != target.policy_asset {
        return Err(SessionError::PolicyAssetMismatch {
            expected: target.policy_asset,
            actual: info.policy_asset,
        });
    }
    if !has_required_capabilities(&info.capabilities) {
        return Err(SessionError::CapabilityMismatch {
            advertised: info.capabilities,
        });
    }
    Ok(info)
}

fn has_required_capabilities(capabilities: &[ProviderCapability]) -> bool {
    capabilities.len() >= REQUIRED_CAPABILITIES.len()
        && REQUIRED_CAPABILITIES.iter().all(|required| {
            capabilities
                .iter()
                .filter(|advertised| *advertised == required)
                .count()
                == 1
        })
}

struct RequestIds(AtomicU64);

impl RequestIds {
    const fn after_startup() -> Self {
        Self(AtomicU64::new(STARTUP_REQUEST_ID))
    }

    fn next(&self) -> Result<RequestId, SessionError> {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map(|last| RequestId(last + 1))
            .map_err(|_| SessionError::RequestIdExhausted)
    }
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid RFQ session configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("RFQ client error: {0}")]
    Client(#[from] ClientError),
    #[error("firm quote attestation error: {0}")]
    Attestation(#[from] AttestationError),
    #[error("authenticated provider endpoint differs from the pinned endpoint")]
    PeerEndpointMismatch {
        expected: EndpointId,
        actual: EndpointId,
    },
    #[error("provider metadata endpoint differs from the pinned endpoint")]
    InfoEndpointMismatch {
        expected: FixedBytes32,
        actual: FixedBytes32,
    },
    #[error("provider chain differs from the pinned chain")]
    ChainMismatch {
        expected: ChainIdentity,
        actual: ChainIdentity,
    },
    #[error("provider policy asset differs from the pinned policy asset")]
    PolicyAssetMismatch { expected: AssetId, actual: AssetId },
    #[error("provider did not advertise each required RFQ capability exactly once")]
    CapabilityMismatch { advertised: Vec<ProviderCapability> },
    #[error("quote request context differs from the pinned session context")]
    RequestContextMismatch,
    #[error("trusted wall-clock time was unavailable after receiving the firm quote")]
    TrustedClockUnavailable,
    #[error("firm quote has an invalid time interval")]
    InvalidQuoteTimeline,
    #[error("firm quote lifetime {actual_millis}ms exceeds configured maximum {maximum_millis}ms")]
    QuoteLifetimeExceeded {
        actual_millis: u64,
        maximum_millis: u64,
    },
    #[error(
        "firm quote creation time {created_at_millis} is more than {maximum_skew_millis}ms ahead of trusted time {now_millis}"
    )]
    QuoteClockTooFarAhead {
        created_at_millis: u64,
        now_millis: u64,
        maximum_skew_millis: u64,
    },
    #[error("reservation status is structurally invalid: {0}")]
    InvalidReservationStatus(#[source] FirmQuoteValidationError),
    #[error("reservation replay is not in the reserved state")]
    ReservationNotReserved,
    #[error("trusted RFQ clock moved backwards from {previous_millis} to {now_millis}")]
    ClockMovedBackwards {
        previous_millis: u64,
        now_millis: u64,
    },
    #[error("settlement layout is invalid for the authenticated quote: {0}")]
    InvalidSettlementLayout(#[source] FirmQuoteValidationError),
    #[error("resolved settlement layout belongs to a different RFQ reservation")]
    SettlementReservationMismatch,
    #[error("invalid RFQ execution attempt: {0}")]
    InvalidExecutionAttempt(#[source] ExecutionAttemptError),
    #[error("reservation handle belongs to a different provider")]
    HandleProviderMismatch,
    #[error("reservation handle belongs to a different authenticated client")]
    HandleClientMismatch,
    #[error("reservation handle belongs to a different Liquid chain")]
    HandleChainMismatch,
    #[error("reservation handle uses a different Liquid policy asset")]
    HandlePolicyAssetMismatch,
    #[error("reservation response does not match handle field {0}")]
    ReservationBindingMismatch(&'static str),
    #[error("RFQ request ID space exhausted")]
    RequestIdExhausted,
    #[error("RFQ transport returned an unexpected response for {0}")]
    UnexpectedResponse(&'static str),
}

/// Failure while submitting one exact taker-authorized execution attempt.
#[derive(Debug, Error)]
pub enum ExecuteError {
    /// Local validation failed before any execute request was dispatched.
    #[error("RFQ execution was rejected before submission: {0}")]
    BeforeSubmission(#[source] SessionError),
    /// Dispatch began, so the provider may have crossed its durable commit
    /// boundary even though the client did not receive a valid acknowledgement.
    #[error("RFQ execution outcome is uncertain for attempt {attempt:?}: {source}")]
    SubmissionUncertain {
        attempt: ExecutionAttemptDigest,
        #[source]
        source: SessionError,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use deadcat_rfq_rpc::{
        AssetAmountDto, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FixedBytes33,
        PricingDecisionDto, QuoteContextDto, QuoteExecutionDto, QuoteInputDto, QuoteKindDto,
        QuoteOutputDto, QuoteOutputRoleDto, QuoteRecipientDto, RationalRateDto, ReleaseReasonDto,
        ReservationStateDto, SnapshotEvidenceDto, TxOutDto,
    };
    use deadcat_types::{ContractId, LiquidNetwork};
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey as SecpSecretKey};
    use elements::{BlockHash, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness, Txid};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;

    fn chain() -> ChainIdentity {
        ChainIdentity {
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: BlockHash::from_byte_array([5; 32]),
        }
    }

    fn policy_asset() -> AssetId {
        AssetId::from_slice(&[6; 32]).expect("policy asset")
    }

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("fixture asset")
    }

    fn outpoint(marker: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
    }

    fn keypair(marker: u8) -> Keypair {
        let secret = SecpSecretKey::from_slice(&[marker; 32]).expect("fixture secret key");
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn p2tr_script(marker: u8) -> Script {
        let (internal_key, _) = keypair(marker).x_only_public_key();
        Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None)
    }

    fn blinding_public_key(marker: u8) -> PublicKey {
        let secret = SecpSecretKey::from_slice(&[marker; 32]).expect("fixture blinding key");
        PublicKey::from_secret_key(&Secp256k1::new(), &secret)
    }

    fn recipient(spend_marker: u8, blinding_marker: u8) -> QuoteRecipientDto {
        QuoteRecipientDto {
            script_pubkey: p2tr_script(spend_marker).as_bytes().to_vec(),
            blinding_public_key: FixedBytes33::new(
                blinding_public_key(blinding_marker).serialize(),
            ),
        }
    }

    fn confidential_txout(asset: AssetId, amount: u64) -> TxOut {
        let secp = Secp256k1::new();
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: p2tr_script(0x41),
            witness: TxOutWitness::empty(),
        };
        let mut rng = StdRng::from_seed([0x42; 32]);
        explicit
            .to_non_last_confidential(
                &mut rng,
                &secp,
                blinding_public_key(0x43),
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("confidential provider prevout")
            .0
    }

    fn signed_quote_fixture() -> (
        SignedFirmQuote,
        FirmQuoteRequestDto,
        SecretKey,
        SecretKey,
        IdempotencyKeyDto,
    ) {
        let provider_key = SecretKey::from_bytes(&[0x21; 32]);
        let client_key = SecretKey::from_bytes(&[0x22; 32]);
        let input_asset = policy_asset();
        let output_asset = asset(0x23);
        let client_recipient = recipient(0x24, 0x25);
        let provider_recipient = recipient(0x26, 0x27);
        let request = FirmQuoteRequestDto {
            context: QuoteContextDto {
                network: chain().network,
                genesis_hash: chain().genesis_hash,
                market: ContractId::new(outpoint(0x28, 0)),
                policy_asset: input_asset,
            },
            kind: QuoteKindDto::ExactIn {
                input: AssetAmountDto {
                    asset: input_asset,
                    amount: 100,
                },
                output_asset,
                minimum_output: 200,
            },
            recipient: client_recipient.clone(),
            maximum_input_asset_venue_fee: 0,
        };
        let quote = FirmQuoteDto {
            reservation_id: FixedBytes32::new([0x29; 32]),
            provider_endpoint: FixedBytes32::new(*provider_key.public().as_bytes()),
            network: chain().network,
            genesis_hash: chain().genesis_hash,
            policy_asset: input_asset,
            request: request.clone(),
            execution: QuoteExecutionDto {
                input: AssetAmountDto {
                    asset: input_asset,
                    amount: 100,
                },
                output: AssetAmountDto {
                    asset: output_asset,
                    amount: 200,
                },
                input_asset_venue_fee: 0,
            },
            pricing: PricingDecisionDto {
                rate: RationalRateDto {
                    numerator: 2,
                    denominator: 1,
                },
                input_asset_venue_fee: 0,
                policy_id: FixedBytes32::new([0x2a; 32]),
                revision: 1,
            },
            snapshot: SnapshotEvidenceDto {
                block_hash: BlockHash::from_byte_array([0x2b; 32]),
                block_height: 1,
                snapshot_commitment: FixedBytes32::new([0x2c; 32]),
                allocation_revision: 1,
                eligible_commitment: FixedBytes32::new([0x2d; 32]),
            },
            inputs: vec![QuoteInputDto {
                id: 1,
                outpoint: outpoint(0x2e, 0),
                witness_utxo: TxOutDto::from_txout(&confidential_txout(output_asset, 200)),
                inventory_binding: FixedBytes32::new([0x2f; 32]),
            }],
            outputs: vec![
                QuoteOutputDto {
                    id: 1,
                    role: QuoteOutputRoleDto::ProviderPayment,
                    asset: input_asset,
                    amount: 100,
                    destination: provider_recipient,
                    blinder: BlinderRoleDto::TakerPaymentInput,
                },
                QuoteOutputDto {
                    id: 2,
                    role: QuoteOutputRoleDto::TakerReceive,
                    asset: output_asset,
                    amount: 200,
                    destination: client_recipient,
                    blinder: BlinderRoleDto::ProviderInput { quote_input_id: 1 },
                },
            ],
            created_at_millis: 1_000,
            accept_before_millis: 10_000,
            fee_policy: FeePolicyDto {
                policy_asset: input_asset,
                minimum_sats_per_kvb: 100,
                minimum_absolute_fee: 1,
                maximum_transaction_weight: 100_000,
                size_metric: FeeSizeMetricDto::DiscountVbytes,
            },
            recovery_metadata_commitment: FixedBytes32::new([0x30; 32]),
            quote_commitment: FixedBytes32::new([0x31; 32]),
        };
        let idempotency_key = FixedBytes32::new([0x32; 32]);
        let signed =
            SignedFirmQuote::sign(quote, &provider_key, client_key.public(), idempotency_key)
                .expect("valid signed quote");
        (signed, request, provider_key, client_key, idempotency_key)
    }

    fn replay(received_at_millis: Option<u64>) -> QuoteReplay {
        let (signed, request, provider_key, client_key, idempotency_key) = signed_quote_fixture();
        let verified = signed
            .verify(
                provider_key.public(),
                client_key.public(),
                idempotency_key,
                &request,
            )
            .expect("authentic quote");
        let handle = ReservationHandle::from_quote(
            verified.quote(),
            provider_key.public(),
            client_key.public(),
        );
        let config = SessionConfig::new(ClientConfig::default(), 10_000, 1_000).expect("config");
        AuthenticatedQuote::new(verified, handle, &config, received_at_millis)
            .into_replay(ReservationStatusDto {
                reservation_id: FixedBytes32::new([0x29; 32]),
                quote_commitment: FixedBytes32::new([0x31; 32]),
                created_at_millis: 1_000,
                accept_before_millis: 10_000,
                state: ReservationStateDto::Reserved,
            })
            .expect("bound replay")
    }

    fn handle() -> ReservationHandle {
        ReservationHandle {
            provider_endpoint: SecretKey::from_bytes(&[3; 32]).public(),
            client_endpoint: SecretKey::from_bytes(&[4; 32]).public(),
            chain: chain(),
            policy_asset: policy_asset(),
            reservation_id: FixedBytes32::new([1; 32]),
            quote_commitment: FixedBytes32::new([2; 32]),
            created_at_millis: 100,
            accept_before_millis: 200,
        }
    }

    fn status() -> ReservationStatusDto {
        ReservationStatusDto {
            reservation_id: FixedBytes32::new([1; 32]),
            quote_commitment: FixedBytes32::new([2; 32]),
            created_at_millis: 100,
            accept_before_millis: 200,
            state: ReservationStateDto::Reserved,
        }
    }

    #[test]
    fn session_clock_limits_must_be_positive() {
        assert!(matches!(
            SessionConfig::new(ClientConfig::default(), 0, 1),
            Err(SessionError::InvalidConfig(_))
        ));
        assert!(matches!(
            SessionConfig::new(ClientConfig::default(), 1, 0),
            Err(SessionError::InvalidConfig(_))
        ));
    }

    #[test]
    fn quote_clock_policy_bounds_lifetime_and_future_skew_but_preserves_expired_replay() {
        let config = SessionConfig::new(ClientConfig::default(), 100, 10).expect("config");
        validate_quote_clock(&config, 100, 200, 90).expect("maximum allowed skew and lifetime");
        validate_quote_clock(&config, 100, 200, 300).expect("expired authentic replay");
        assert!(matches!(
            validate_quote_clock(&config, 100, 201, 100),
            Err(SessionError::QuoteLifetimeExceeded { .. })
        ));
        assert!(matches!(
            validate_quote_clock(&config, 111, 200, 100),
            Err(SessionError::QuoteClockTooFarAhead { .. })
        ));
    }

    #[test]
    fn handle_checks_every_status_binding_field() {
        let handle = handle();
        handle.validate_status(&status()).expect("matching status");

        let mut cases = Vec::new();
        let mut mismatched = status();
        mismatched.reservation_id = FixedBytes32::new([3; 32]);
        cases.push(mismatched);
        let mut mismatched = status();
        mismatched.quote_commitment = FixedBytes32::new([3; 32]);
        cases.push(mismatched);
        let mut mismatched = status();
        mismatched.created_at_millis = 99;
        cases.push(mismatched);
        let mut mismatched = status();
        mismatched.accept_before_millis = 201;
        cases.push(mismatched);

        for mismatched in cases {
            assert!(matches!(
                handle.validate_status(&mismatched),
                Err(SessionError::ReservationBindingMismatch(_))
            ));
        }
    }

    #[test]
    fn handle_binds_endpoints_chain_and_policy_asset() {
        let handle = handle();
        handle
            .validate_context(
                handle.provider_endpoint(),
                handle.client_endpoint(),
                chain(),
                policy_asset(),
            )
            .expect("matching session context");

        assert!(matches!(
            handle.validate_context(
                SecretKey::from_bytes(&[9; 32]).public(),
                handle.client_endpoint(),
                chain(),
                policy_asset(),
            ),
            Err(SessionError::HandleProviderMismatch)
        ));
        assert!(matches!(
            handle.validate_context(
                handle.provider_endpoint(),
                SecretKey::from_bytes(&[10; 32]).public(),
                chain(),
                policy_asset(),
            ),
            Err(SessionError::HandleClientMismatch)
        ));
        let wrong_chain = ChainIdentity {
            genesis_hash: BlockHash::from_byte_array([7; 32]),
            ..chain()
        };
        assert!(matches!(
            handle.validate_context(
                handle.provider_endpoint(),
                handle.client_endpoint(),
                wrong_chain,
                policy_asset(),
            ),
            Err(SessionError::HandleChainMismatch)
        ));
        assert!(matches!(
            handle.validate_context(
                handle.provider_endpoint(),
                handle.client_endpoint(),
                chain(),
                AssetId::from_slice(&[8; 32]).expect("other policy asset"),
            ),
            Err(SessionError::HandlePolicyAssetMismatch)
        ));
    }

    #[test]
    fn blind_then_execute_preflights_share_a_monotonic_high_watermark() {
        let replay = replay(Some(1_500));
        let live = replay.live_at(1_500).expect("initial live authority");

        validate_still_live(&live, 2_000).expect("blind-time preflight");
        assert!(matches!(
            validate_still_live(&live, 1_800),
            Err(SessionError::ClockMovedBackwards {
                previous_millis: 2_000,
                now_millis: 1_800,
            })
        ));
    }

    #[test]
    fn later_live_promotion_prevents_an_earlier_promotion_from_another_clone() {
        let first_replay = replay(Some(1_500));
        let second_replay = first_replay.clone();

        first_replay.live_at(2_500).expect("later promotion");
        assert!(matches!(
            second_replay.live_at(2_000),
            Err(SessionError::ClockMovedBackwards {
                previous_millis: 2_500,
                now_millis: 2_000,
            })
        ));
    }

    #[test]
    fn missing_post_response_clock_becomes_recovery_only_policy_rejection() {
        let replay = replay(None);
        assert_eq!(replay.received_at_millis(), None);
        assert_eq!(
            replay.handle().reservation_id(),
            FixedBytes32::new([0x29; 32])
        );
        assert!(matches!(
            replay.validate_clock_policy(),
            Err(SessionError::TrustedClockUnavailable)
        ));
        assert!(matches!(
            replay.live_at(1_500),
            Err(SessionError::TrustedClockUnavailable)
        ));
    }

    #[test]
    fn resolved_layout_cannot_cross_reservations() {
        let reservation = handle();
        let mut other = reservation;
        other.quote_commitment = FixedBytes32::new([9; 32]);
        let settlement = ResolvedRfqSettlement::new(
            other,
            SettlementLayoutDto {
                taker_payment_input: 0,
                provider_inputs: Vec::new(),
                quote_outputs: Vec::new(),
            },
        );
        assert!(matches!(
            validate_settlement_binding(&reservation, &settlement),
            Err(SessionError::SettlementReservationMismatch)
        ));
    }

    #[test]
    fn structurally_invalid_status_is_rejected_before_binding() {
        let mut invalid = status();
        invalid.state = ReservationStateDto::Released {
            reason: ReleaseReasonDto::Expired,
            at_millis: 199,
        };
        assert!(matches!(
            handle().validate_status(&invalid),
            Err(SessionError::InvalidReservationStatus(_))
        ));
    }

    #[test]
    fn capability_set_requires_all_four_without_duplicates() {
        assert!(has_required_capabilities(&REQUIRED_CAPABILITIES));
        assert!(!has_required_capabilities(&REQUIRED_CAPABILITIES[..3]));
        assert!(!has_required_capabilities(&[
            ProviderCapability::FirmQuotes,
            ProviderCapability::FirmQuotes,
            ProviderCapability::SettlementExecution,
            ProviderCapability::DurableStatus,
        ]));
    }

    #[test]
    fn concurrent_request_ids_are_unique_and_skip_startup_id() {
        let ids = Arc::new(RequestIds::after_startup());
        let threads = (0..8)
            .map(|_| {
                let ids = Arc::clone(&ids);
                std::thread::spawn(move || {
                    (0..128)
                        .map(|_| ids.next().expect("request ID").0)
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let actual = threads
            .into_iter()
            .flat_map(|thread| thread.join().expect("request ID thread"))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual.len(), 8 * 128);
        assert_eq!(actual.first(), Some(&(STARTUP_REQUEST_ID + 1)));
    }

    #[test]
    fn exhausted_request_ids_never_wrap() {
        let ids = RequestIds(AtomicU64::new(u64::MAX));
        assert!(matches!(ids.next(), Err(SessionError::RequestIdExhausted)));
        assert_eq!(ids.0.load(Ordering::Relaxed), u64::MAX);
    }
}
