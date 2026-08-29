//! Authenticated RFQ transport sessions and durable reservation bindings.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use deadcat_rfq_iroh::{Client, ClientConfig, ClientError};
use deadcat_rfq_rpc::{
    AttestationError, FirmQuoteDto, FirmQuoteRequestDto, FirmQuoteValidationError, FixedBytes32,
    IdempotencyKeyDto, LiveFirmQuote, ProviderCapability, ProviderInfo, Request, RequestEnvelope,
    RequestId, ReservationIdDto, ReservationStateDto, ReservationStatusDto, Response,
    SettlementLayoutDto, SettlementPset, SignedFirmQuote, VerifiedFirmQuote,
};
use deadcat_types::ChainIdentity;
use elements::AssetId;
use iroh::{EndpointAddr, EndpointId, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::journal::{ExecutionJournalKey, ExecutionJournalRecordError, JournaledExecution};
use crate::settlement::{
    ExecutionAttempt, ExecutionAttemptDigest, ExecutionAttemptError, ProviderBlindedPset,
};

const STARTUP_REQUEST_ID: u64 = 1;
pub const QUOTE_RECOVERY_RECORD_VERSION: u32 = 1;
const QUOTE_RECOVERY_RECORD_DOMAIN: &[u8] = b"deadcat/rfq/client-quote-recovery/v1";
const REQUIRED_CAPABILITIES: [ProviderCapability; 4] = [
    ProviderCapability::FirmQuotes,
    ProviderCapability::ProviderBlinding,
    ProviderCapability::SettlementExecution,
    ProviderCapability::DurableStatus,
];

/// An execution status accepted through an authenticated RFQ session and
/// validated against one exact durably journaled attempt.
///
/// This is an in-memory capability, not a wire or persistence type. Its
/// contents can be inspected, but only [`RfqSession::execute_at`] and
/// [`RfqSession::retry_armed_execution`] can construct it. Requiring this type
/// at the execution-journal boundary prevents a caller from forging a raw
/// [`ReservationStatusDto`]—most importantly a false `Released` status that
/// could otherwise make wallet inputs appear reusable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedExecutionStatus {
    journal_key: ExecutionJournalKey,
    attempt_digest: ExecutionAttemptDigest,
    status: ReservationStatusDto,
}

impl AuthenticatedExecutionStatus {
    fn new(journaled: &JournaledExecution, status: ReservationStatusDto) -> Self {
        Self {
            journal_key: journaled.key(),
            attempt_digest: journaled.attempt().digest(),
            status,
        }
    }

    pub(crate) const fn journal_key(&self) -> ExecutionJournalKey {
        self.journal_key
    }

    pub(crate) const fn attempt_digest(&self) -> ExecutionAttemptDigest {
        self.attempt_digest
    }

    #[must_use]
    pub const fn status(&self) -> &ReservationStatusDto {
        &self.status
    }
}

/// Serializable evidence needed to reauthenticate a firm quote after restart.
///
/// `received_at_millis` is the trusted first receipt observation. Recovery
/// deliberately reuses it instead of sampling a new time, so restarting cannot
/// relax the client's quote-clock policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRecoveryRecord {
    version: u32,
    signed_quote: SignedFirmQuote,
    request: FirmQuoteRequestDto,
    idempotency_key: IdempotencyKeyDto,
    received_at_millis: u64,
    digest: FixedBytes32,
}

impl QuoteRecoveryRecord {
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn signed_quote(&self) -> &SignedFirmQuote {
        &self.signed_quote
    }

    #[must_use]
    pub const fn request(&self) -> &FirmQuoteRequestDto {
        &self.request
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> IdempotencyKeyDto {
        self.idempotency_key
    }

    #[must_use]
    pub const fn received_at_millis(&self) -> u64 {
        self.received_at_millis
    }

    #[must_use]
    pub const fn digest(&self) -> FixedBytes32 {
        self.digest
    }

    fn new(
        signed_quote: SignedFirmQuote,
        request: FirmQuoteRequestDto,
        idempotency_key: IdempotencyKeyDto,
        received_at_millis: u64,
    ) -> Result<Self, SessionError> {
        let mut record = Self {
            version: QUOTE_RECOVERY_RECORD_VERSION,
            signed_quote,
            request,
            idempotency_key,
            received_at_millis,
            digest: FixedBytes32::new([0; 32]),
        };
        record.digest = quote_recovery_digest(&record)?;
        Ok(record)
    }

    pub(crate) fn validate_integrity(&self) -> Result<(), SessionError> {
        if self.version != QUOTE_RECOVERY_RECORD_VERSION {
            return Err(SessionError::UnsupportedQuoteRecoveryRecordVersion {
                actual: self.version,
            });
        }
        if self.digest != quote_recovery_digest(self)? {
            return Err(SessionError::QuoteRecoveryRecordDigestMismatch);
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct QuoteRecoveryDigestInput<'a> {
    version: u32,
    signed_quote: &'a SignedFirmQuote,
    request: &'a FirmQuoteRequestDto,
    idempotency_key: IdempotencyKeyDto,
    received_at_millis: u64,
}

fn quote_recovery_digest(record: &QuoteRecoveryRecord) -> Result<FixedBytes32, SessionError> {
    let input = QuoteRecoveryDigestInput {
        version: record.version,
        signed_quote: &record.signed_quote,
        request: &record.request,
        idempotency_key: record.idempotency_key,
        received_at_millis: record.received_at_millis,
    };
    let encoded =
        postcard::to_allocvec(&input).map_err(SessionError::QuoteRecoveryRecordEncoding)?;
    let mut digest = Sha256::new();
    digest.update(QUOTE_RECOVERY_RECORD_DOMAIN);
    digest.update((encoded.len() as u64).to_be_bytes());
    digest.update(encoded);
    Ok(FixedBytes32::new(digest.finalize().into()))
}

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
            recovery_only: false,
        })
    }

    fn into_recovery_replay(
        self,
        status: ReservationStatusDto,
    ) -> Result<QuoteReplay, SessionError> {
        let mut replay = self.into_replay(status)?;
        replay.recovery_only = true;
        Ok(replay)
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
    recovery_only: bool,
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

    /// Snapshot the complete authenticated quote recovery artifact.
    ///
    /// Quotes received without a trusted first-receipt observation remain
    /// useful as in-process authenticity evidence, but cannot produce a
    /// restart record whose clock policy can be replayed faithfully.
    pub fn to_recovery_record(&self) -> Result<QuoteRecoveryRecord, SessionError> {
        let received_at_millis = self
            .received_at_millis
            .ok_or(SessionError::TrustedClockUnavailable)?;
        QuoteRecoveryRecord::new(
            self.quote.signed().clone(),
            self.quote.quote().request.clone(),
            self.quote.signed().attestation.idempotency_key,
            received_at_millis,
        )
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
        if self.recovery_only {
            return Err(SessionError::PersistedQuoteRecoveryOnly);
        }
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
        let record = QuoteRecoveryRecord::new(
            signed_quote.clone(),
            request.clone(),
            idempotency_key,
            received_at_millis,
        )?;
        self.recover_quote(&record).await
    }

    /// Reauthenticate a self-contained quote record and fetch durable status.
    ///
    /// Status is fetched before this returns. The returned replay is
    /// deliberately recovery-only and can never be promoted to new settlement
    /// authority, even if restart configuration is looser or the in-memory
    /// trusted-time high-water mark was lost. Ambiguous execution recovery uses
    /// [`Self::retry_armed_execution`] to replay only the journaled bytes.
    pub async fn recover_quote(
        &self,
        record: &QuoteRecoveryRecord,
    ) -> Result<QuoteReplay, SessionError> {
        record.validate_integrity()?;
        self.validate_request_context(&record.request)?;
        let authenticated = self.authenticate_signed_quote(
            record.signed_quote.clone(),
            record.idempotency_key,
            &record.request,
            Some(record.received_at_millis),
        )?;
        let status = self.status(&authenticated.handle).await?;
        authenticated.into_recovery_replay(status)
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

    /// Submit an exact, durably armed taker-authorized attempt for provider
    /// validation and signing.
    ///
    /// The journal capability type-enforces durable write-before-dispatch. Once
    /// dispatch begins, any error is conservatively ambiguous: the daemon may
    /// already have queued or durably committed the attempt. Poll status and
    /// retry only the exact journaled bytes until durable status resolves the
    /// ambiguity.
    pub async fn execute_at(
        &self,
        reservation: &LiveQuoteReservation,
        settlement: &ResolvedRfqSettlement,
        journaled: &JournaledExecution,
        now_millis: u64,
    ) -> Result<AuthenticatedExecutionStatus, ExecuteError> {
        self.validate_handle_context(&reservation.handle)
            .map_err(ExecuteError::BeforeSubmission)?;
        validate_settlement_binding(&reservation.handle, settlement)
            .map_err(ExecuteError::BeforeSubmission)?;
        journaled
            .validate_handle(&reservation.handle)
            .map_err(SessionError::InvalidExecutionAttempt)
            .map_err(ExecuteError::BeforeSubmission)?;
        journaled
            .validate_dispatchable()
            .map_err(SessionError::InvalidExecutionJournal)
            .map_err(ExecuteError::BeforeSubmission)?;
        journaled
            .attempt()
            .validate_for_settlement(settlement)
            .map_err(SessionError::InvalidExecutionAttempt)
            .map_err(ExecuteError::BeforeSubmission)?;
        validate_still_live(reservation, now_millis).map_err(ExecuteError::BeforeSubmission)?;
        settlement
            .layout
            .validate_for_quote(reservation.quote.quote())
            .map_err(SessionError::InvalidSettlementLayout)
            .map_err(ExecuteError::BeforeSubmission)?;

        let status = self
            .dispatch_execution(&reservation.handle, journaled.attempt())
            .await?;
        journaled
            .validate_next_status(&status)
            .map_err(SessionError::InvalidExecutionJournal)
            .map_err(|source| ExecuteError::SubmissionUncertain {
                attempt: journaled.attempt().digest(),
                source,
            })?;
        Ok(AuthenticatedExecutionStatus::new(journaled, status))
    }

    /// Recover status and, only while it is still reserved, replay one exact
    /// durably armed execution attempt.
    ///
    /// This is the only execute path that intentionally skips a local quote
    /// expiry check. The journal capability proves the exact bytes were armed
    /// before dispatch could begin; after an ambiguous outcome the provider's
    /// durable state is authoritative. No new settlement may be constructed
    /// through this method after expiry.
    pub async fn retry_armed_execution(
        &self,
        journaled: &JournaledExecution,
    ) -> Result<AuthenticatedExecutionStatus, ExecuteError> {
        let uncertain = |source| ExecuteError::SubmissionUncertain {
            attempt: journaled.attempt().digest(),
            source,
        };
        let replay = self
            .recover_quote(journaled.quote())
            .await
            .map_err(uncertain)?;
        journaled
            .validate_handle(&replay.handle)
            .map_err(SessionError::InvalidExecutionAttempt)
            .map_err(uncertain)?;
        journaled
            .validate_next_status(&replay.status)
            .map_err(SessionError::InvalidExecutionJournal)
            .map_err(uncertain)?;
        if !matches!(replay.status.state, ReservationStateDto::Reserved) {
            return Ok(AuthenticatedExecutionStatus::new(journaled, replay.status));
        }
        let status = self
            .dispatch_execution(&replay.handle, journaled.attempt())
            .await?;
        journaled
            .validate_next_status(&status)
            .map_err(SessionError::InvalidExecutionJournal)
            .map_err(uncertain)?;
        Ok(AuthenticatedExecutionStatus::new(journaled, status))
    }

    async fn dispatch_execution(
        &self,
        handle: &ReservationHandle,
        attempt: &ExecutionAttempt,
    ) -> Result<ReservationStatusDto, ExecuteError> {
        let request_id = self
            .request_ids
            .next()
            .map_err(ExecuteError::BeforeSubmission)?;
        let response = self
            .client
            .call(RequestEnvelope::new(
                request_id,
                Request::Execute {
                    reservation_id: handle.reservation_id,
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
        handle
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
    #[error("unsupported quote-recovery record version {actual}")]
    UnsupportedQuoteRecoveryRecordVersion { actual: u32 },
    #[error("quote-recovery record digest does not match its contents")]
    QuoteRecoveryRecordDigestMismatch,
    #[error("quote-recovery record encoding failed: {0}")]
    QuoteRecoveryRecordEncoding(#[source] postcard::Error),
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
    #[error("a persisted quote replay is recovery-only and cannot authorize new settlement")]
    PersistedQuoteRecoveryOnly,
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
    #[error("invalid RFQ execution journal state: {0}")]
    InvalidExecutionJournal(#[source] ExecutionJournalRecordError),
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
        InputPlacementDto, OutputPlacementDto, PricingDecisionDto, QuoteContextDto,
        QuoteExecutionDto, QuoteInputDto, QuoteKindDto, QuoteOutputDto, QuoteOutputRoleDto,
        QuoteRecipientDto, RationalRateDto, ReleaseReasonDto, ReservationStateDto,
        SnapshotEvidenceDto, TxOutDto,
    };
    use deadcat_types::{ContractId, LiquidNetwork};
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
    use elements::secp256k1_zkp::{Keypair, PublicKey, Secp256k1, SecretKey as SecpSecretKey};
    use elements::{BlockHash, OutPoint, Script, TxOut, TxOutSecrets, TxOutWitness, Txid};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use crate::journal::{
        ExecutionJournal as _, ExecutionJournalError, ExecutionJournalRecordError,
        MAX_EXECUTION_JOURNAL_PAGE_SIZE, RedbExecutionJournal,
    };
    use crate::settlement::ExecutionBinding;

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
                internal_key: FixedBytes32::new(keypair(0x41).x_only_public_key().0.serialize()),
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

    fn replay_for_reservation(reservation_index: u16) -> QuoteReplay {
        let (signed, request, provider_key, client_key, idempotency_key) = signed_quote_fixture();
        let mut quote = signed.quote;
        let mut reservation_id = [0_u8; 32];
        reservation_id[30..].copy_from_slice(&reservation_index.to_be_bytes());
        quote.reservation_id = FixedBytes32::new(reservation_id);
        let signed =
            SignedFirmQuote::sign(quote, &provider_key, client_key.public(), idempotency_key)
                .expect("valid indexed signed quote");
        let verified = signed
            .verify(
                provider_key.public(),
                client_key.public(),
                idempotency_key,
                &request,
            )
            .expect("authentic indexed quote");
        let handle = ReservationHandle::from_quote(
            verified.quote(),
            provider_key.public(),
            client_key.public(),
        );
        let config = SessionConfig::new(ClientConfig::default(), 10_000, 1_000).expect("config");
        AuthenticatedQuote::new(verified, handle, &config, Some(1_500))
            .into_replay(ReservationStatusDto {
                reservation_id: FixedBytes32::new(reservation_id),
                quote_commitment: FixedBytes32::new([0x31; 32]),
                created_at_millis: 1_000,
                accept_before_millis: 10_000,
                state: ReservationStateDto::Reserved,
            })
            .expect("bound indexed replay")
    }

    fn execution_attempt(replay: &QuoteReplay, fee: u64) -> ExecutionAttempt {
        let layout = SettlementLayoutDto {
            taker_payment_input: 0,
            provider_inputs: vec![InputPlacementDto {
                quote_input_id: 1,
                transaction_index: 1,
            }],
            quote_outputs: vec![
                OutputPlacementDto {
                    quote_output_id: 1,
                    transaction_index: 0,
                },
                OutputPlacementDto {
                    quote_output_id: 2,
                    transaction_index: 1,
                },
            ],
        };
        let settlement = ResolvedRfqSettlement::new(*replay.handle(), layout.clone());
        let binding = ExecutionBinding::from_settlement(&settlement);
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut taker_input = PsetInput::from_prevout(outpoint(0x51, 0));
        taker_input.witness_utxo = Some(TxOut {
            asset: Asset::Explicit(policy_asset()),
            value: Value::Explicit(fee),
            nonce: Nonce::Null,
            script_pubkey: p2tr_script(0x52),
            witness: TxOutWitness::empty(),
        });
        let mut provider_input = PsetInput::from_prevout(outpoint(0x53, 0));
        provider_input.witness_utxo = Some(confidential_txout(asset(0x23), 200));
        pset.add_input(taker_input);
        pset.add_input(provider_input);
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(fee, policy_asset())));
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(1, asset(0x23))));
        let pset = SettlementPset::from_pset(&pset).expect("fixture PSET");
        ExecutionAttempt::new(binding, layout, pset)
    }

    fn bound_status(replay: &QuoteReplay, state: ReservationStateDto) -> ReservationStatusDto {
        ReservationStatusDto {
            reservation_id: replay.handle().reservation_id(),
            quote_commitment: replay.handle().quote_commitment(),
            created_at_millis: replay.handle().created_at_millis(),
            accept_before_millis: replay.handle().accept_before_millis(),
            state,
        }
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
        assert!(matches!(
            replay.to_recovery_record(),
            Err(SessionError::TrustedClockUnavailable)
        ));
    }

    #[test]
    fn quote_recovery_record_preserves_exact_authentication_and_first_receipt() {
        let replay = replay(Some(1_500));
        let record = replay.to_recovery_record().expect("recovery record");
        let encoded = serde_json::to_vec(&record).expect("serialize recovery record");
        let decoded: QuoteRecoveryRecord =
            serde_json::from_slice(&encoded).expect("deserialize recovery record");

        assert_eq!(decoded, record);
        assert_eq!(decoded.version(), QUOTE_RECOVERY_RECORD_VERSION);
        assert_eq!(decoded.received_at_millis(), 1_500);
        assert_eq!(decoded.request(), &decoded.signed_quote().quote.request);
        assert_eq!(
            decoded.idempotency_key(),
            decoded.signed_quote().attestation.idempotency_key
        );

        let mut tampered = serde_json::to_value(&decoded).expect("recovery JSON");
        tampered["received_at_millis"] = serde_json::json!(1_501);
        let tampered: QuoteRecoveryRecord =
            serde_json::from_value(tampered).expect("structural recovery JSON");
        assert!(matches!(
            tampered.validate_integrity(),
            Err(SessionError::QuoteRecoveryRecordDigestMismatch)
        ));
    }

    #[test]
    fn persisted_recovery_cannot_promote_under_a_looser_restart_clock_policy() {
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
        let strict = SessionConfig::new(ClientConfig::default(), 100, 1_000).expect("strict");
        let strict_replay = AuthenticatedQuote::new(verified, handle, &strict, Some(1_500))
            .into_replay(bound_status(
                &replay(Some(1_500)),
                ReservationStateDto::Reserved,
            ))
            .expect("authentic rejected replay");
        assert!(matches!(
            strict_replay.validate_clock_policy(),
            Err(SessionError::QuoteLifetimeExceeded { .. })
        ));
        let persisted = strict_replay
            .to_recovery_record()
            .expect("persist rejected quote evidence");

        let verified = persisted
            .signed_quote()
            .clone()
            .verify(
                provider_key.public(),
                client_key.public(),
                persisted.idempotency_key(),
                persisted.request(),
            )
            .expect("reauthenticate persisted quote");
        let loose = SessionConfig::new(ClientConfig::default(), 10_000, 1_000).expect("loose");
        let recovered = AuthenticatedQuote::new(verified, handle, &loose, Some(1_500))
            .into_recovery_replay(strict_replay.status().clone())
            .expect("recovery replay");
        recovered
            .validate_clock_policy()
            .expect("looser policy would otherwise accept");
        assert!(matches!(
            recovered.live_at(1_500),
            Err(SessionError::PersistedQuoteRecoveryOnly)
        ));
    }

    #[test]
    fn durable_journal_arms_idempotently_reopens_and_rejects_conflicts_and_tampering() {
        let replay = replay(Some(1_500));
        let quote = replay.to_recovery_record().expect("recovery record");
        let attempt = execution_attempt(&replay, 50);
        let other_attempt = execution_attempt(&replay, 51);
        let directory = tempfile::tempdir().expect("journal directory");
        let path = directory.path().join("executions.redb");

        {
            let journal = RedbExecutionJournal::create(&path).expect("create journal");
            let armed = journal.arm(&quote, &attempt).expect("durably arm");
            assert_eq!(armed.revision(), 0);
            let same = journal.arm(&quote, &attempt).expect("idempotent arm");
            assert_eq!(same.to_record(), armed.to_record());
            assert!(matches!(
                journal.arm(&quote, &other_attempt),
                Err(ExecutionJournalError::AttemptConflict)
            ));
        }

        let reopened = RedbExecutionJournal::open(&path).expect("reopen journal");
        let discovered = reopened
            .list_after(None, 10)
            .expect("discover journal after restart without an in-memory key");
        assert_eq!(discovered.len(), 1);
        let loaded = &discovered[0];
        assert_eq!(loaded.attempt().digest(), attempt.digest());
        assert_eq!(loaded.quote().received_at_millis(), 1_500);

        let mut tampered = serde_json::to_value(loaded.to_record()).expect("record JSON");
        tampered["quote"]["received_at_millis"] = serde_json::json!(1_501);
        let mut tampered: crate::journal::ExecutionJournalRecord =
            serde_json::from_value(tampered).expect("structural record JSON");
        tampered
            .recompute_digest_for_test()
            .expect("valid outer digest over tampered inner record");
        assert!(matches!(
            tampered.validate(),
            Err(ExecutionJournalRecordError::InvalidQuoteRecoveryRecord)
        ));

        let mut other_handle = *replay.handle();
        other_handle.quote_commitment = FixedBytes32::new([0x77; 32]);
        let layout = attempt.layout().clone();
        let other_settlement = ResolvedRfqSettlement::new(other_handle, layout.clone());
        let cross_wired = ExecutionAttempt::new(
            ExecutionBinding::from_settlement(&other_settlement),
            layout,
            attempt.pset().clone(),
        );
        assert!(matches!(
            reopened.arm(&quote, &cross_wired),
            Err(ExecutionJournalError::InvalidRecord(
                ExecutionJournalRecordError::QuoteAttemptBindingMismatch
            ))
        ));

        let mut incomplete_layout = attempt.layout().clone();
        incomplete_layout.quote_outputs.pop();
        let incomplete_settlement =
            ResolvedRfqSettlement::new(*replay.handle(), incomplete_layout.clone());
        let incomplete = ExecutionAttempt::new(
            ExecutionBinding::from_settlement(&incomplete_settlement),
            incomplete_layout,
            attempt.pset().clone(),
        );
        assert!(matches!(
            reopened.arm(&quote, &incomplete),
            Err(ExecutionJournalError::InvalidRecord(
                ExecutionJournalRecordError::InvalidLayoutForQuote(_)
            ))
        ));
    }

    #[test]
    fn journal_pagination_rejects_a_misplaced_row_after_the_first_full_page() {
        let directory = tempfile::tempdir().expect("journal directory");
        let journal = RedbExecutionJournal::create(directory.path().join("executions.redb"))
            .expect("create journal");
        let mut records = Vec::with_capacity(MAX_EXECUTION_JOURNAL_PAGE_SIZE + 1);
        for reservation_index in 0..=MAX_EXECUTION_JOURNAL_PAGE_SIZE {
            let replay = replay_for_reservation(
                u16::try_from(reservation_index).expect("page fixture fits u16"),
            );
            let quote = replay.to_recovery_record().expect("recovery record");
            let attempt = execution_attempt(&replay, 50);
            records.push(journal.arm(&quote, &attempt).expect("durably arm row"));
        }

        let first_page = journal
            .list_after(None, MAX_EXECUTION_JOURNAL_PAGE_SIZE)
            .expect("first full page");
        assert_eq!(first_page.len(), MAX_EXECUTION_JOURNAL_PAGE_SIZE);
        let cursor = first_page.last().expect("full page has a cursor").key();
        assert_eq!(cursor, records[MAX_EXECUTION_JOURNAL_PAGE_SIZE - 1].key());

        journal
            .overwrite_record_at_storage_key_for_test(
                records[MAX_EXECUTION_JOURNAL_PAGE_SIZE].key(),
                &records[0].to_record(),
            )
            .expect("inject a valid record under the wrong second-page key");
        assert!(matches!(
            journal.list_after(Some(cursor), MAX_EXECUTION_JOURNAL_PAGE_SIZE),
            Err(ExecutionJournalError::KeyMismatch)
        ));
    }

    #[test]
    fn durable_journal_cas_enforces_monotonic_provider_observations() {
        let replay = replay(Some(1_500));
        let quote = replay.to_recovery_record().expect("recovery record");
        let attempt = execution_attempt(&replay, 50);
        let directory = tempfile::tempdir().expect("journal directory");
        let journal = RedbExecutionJournal::create(directory.path().join("executions.redb"))
            .expect("create journal");
        let armed = journal.arm(&quote, &attempt).expect("durably arm");
        let key = armed.key();

        let other_attempt = execution_attempt(&replay, 51);
        let other_directory = tempfile::tempdir().expect("other journal directory");
        let other_journal =
            RedbExecutionJournal::create(other_directory.path().join("executions.redb"))
                .expect("create other journal");
        let other_armed = other_journal
            .arm(&quote, &other_attempt)
            .expect("durably arm other exact attempt");
        let cross_attempt_status = AuthenticatedExecutionStatus::new(
            &other_armed,
            bound_status(&replay, ReservationStateDto::Reserved),
        );
        assert!(matches!(
            journal.observe(key, 0, &cross_attempt_status),
            Err(ExecutionJournalError::AuthenticatedStatusAttemptMismatch)
        ));

        let reserved = AuthenticatedExecutionStatus::new(
            &armed,
            bound_status(&replay, ReservationStateDto::Reserved),
        );
        let observed = journal
            .observe(key, 0, &reserved)
            .expect("record reserved status");
        assert_eq!(observed.revision(), 1);
        let idempotent = journal
            .observe(key, 1, &reserved)
            .expect("idempotent observation");
        assert_eq!(idempotent.revision(), 1);

        let committed = AuthenticatedExecutionStatus::new(
            &armed,
            bound_status(
                &replay,
                ReservationStateDto::Committed {
                    signing_commitment: FixedBytes32::new([0x78; 32]),
                    committed_at_millis: 2_000,
                },
            ),
        );
        assert!(matches!(
            journal.observe(key, 0, &committed),
            Err(ExecutionJournalError::RevisionConflict {
                expected: 0,
                actual: 1
            })
        ));
        let committed = journal
            .observe(key, 1, &committed)
            .expect("advance to committed");
        assert_eq!(committed.revision(), 2);
        assert!(matches!(
            journal.observe(key, 2, &reserved),
            Err(ExecutionJournalError::InvalidRecord(
                ExecutionJournalRecordError::StatusRegression
            ))
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
