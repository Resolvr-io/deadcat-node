//! Persistent-identity native Iroh client for Deadcat RFQ RPC.

use std::sync::Arc;
use std::time::Duration;

use deadcat_iroh::wire::{
    DEFAULT_INBOUND_BUDGET_BYTES, InboundBudget, MAX_FRAME_BYTES, WireError, read_message,
    write_message,
};
use deadcat_rfq_rpc::{
    FirmQuoteValidationError, Request, RequestEnvelope, RequestId, Response, RpcError, RpcOutcome,
    SCHEMA_VERSION, ServerEnvelope,
};
use iroh::endpoint::{Connection, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::ALPN;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub max_in_flight_requests: usize,
    pub inbound_budget_bytes: usize,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 32,
            inbound_budget_bytes: DEFAULT_INBOUND_BUDGET_BYTES,
            connect_timeout: Duration::from_secs(20),
            request_timeout: Duration::from_secs(30),
        }
    }
}

impl ClientConfig {
    fn validate(&self) -> Result<(), ClientError> {
        if self.max_in_flight_requests == 0 {
            return Err(ClientError::InvalidConfig(
                "max_in_flight_requests must be nonzero",
            ));
        }
        if self.inbound_budget_bytes < MAX_FRAME_BYTES
            || self.inbound_budget_bytes > usize::try_from(u32::MAX).expect("u32 fits usize")
        {
            return Err(ClientError::InvalidConfig(
                "inbound_budget_bytes must fit at least one maximum frame and be <= u32::MAX",
            ));
        }
        if self.connect_timeout == Duration::ZERO || self.request_timeout == Duration::ZERO {
            return Err(ClientError::InvalidConfig("timeouts must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid client configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("Iroh connect error: {0}")]
    Connect(#[from] iroh::endpoint::ConnectError),
    #[error("Iroh connection error: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    #[error("wire error: {0}")]
    Wire(#[from] WireError),
    #[error("server returned RFQ error: {0:?}")]
    Rpc(RpcError),
    #[error("invalid RFQ request: {0}")]
    InvalidRequest(#[source] FirmQuoteValidationError),
    #[error("invalid RFQ response: {0}")]
    InvalidResponse(#[source] FirmQuoteValidationError),
    #[error("request timed out")]
    Timeout,
    #[error("response schema {actual} does not match expected schema {expected}")]
    SchemaMismatch { expected: u32, actual: u32 },
    #[error("response request id {actual:?} does not match request id {expected:?}")]
    RequestIdMismatch {
        expected: RequestId,
        actual: RequestId,
    },
    #[error("response stream contained trailing data")]
    TrailingData,
    #[error("wrong response shape for request")]
    WrongResponseShape,
    #[error("response identifiers do not match the request")]
    ResponseRequestMismatch,
    #[error("response provider identity does not match the authenticated Iroh peer")]
    ProviderIdentityMismatch,
    #[error("Iroh endpoint error: {0}")]
    Iroh(String),
}

/// Connected RFQ client whose identity comes from a caller-owned persistent key.
pub struct Client {
    endpoint: Endpoint,
    connection: Connection,
    config: ClientConfig,
    inbound_budget: InboundBudget,
    in_flight: Arc<Semaphore>,
}

impl Client {
    /// Connect using normal Iroh discovery and relay configuration.
    ///
    /// There is intentionally no overload that generates an ephemeral key:
    /// the authenticated endpoint ID is part of durable reservation ownership.
    pub async fn connect(
        target: impl Into<EndpointAddr>,
        secret_key: SecretKey,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        Self::connect_endpoint(endpoint, target.into(), config).await
    }

    /// Connect directly with relay and discovery disabled.
    pub async fn dial_direct(
        target: EndpointAddr,
        secret_key: SecretKey,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        config.validate()?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(secret_key)
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .map_err(|error| ClientError::Iroh(error.to_string()))?;
        Self::connect_endpoint(endpoint, target, config).await
    }

    async fn connect_endpoint(
        endpoint: Endpoint,
        target: EndpointAddr,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let connection =
            tokio::time::timeout(config.connect_timeout, endpoint.connect(target, ALPN))
                .await
                .map_err(|_| ClientError::Timeout)??;
        Ok(Self {
            endpoint,
            connection,
            inbound_budget: InboundBudget::new(config.inbound_budget_bytes),
            in_flight: Arc::new(Semaphore::new(config.max_in_flight_requests)),
            config,
        })
    }

    /// Execute one low-level RFQ protocol request.
    ///
    /// Transport and structure validation do not make a returned
    /// [`deadcat_rfq_rpc::SignedFirmQuote`] trusted trading authority. Call
    /// `SignedFirmQuote::verify_at` with the authenticated endpoint IDs,
    /// original request, idempotency key, and current time before using it.
    pub async fn call(&self, envelope: RequestEnvelope) -> Result<Response, ClientError> {
        let deadline = tokio::time::Instant::now() + self.config.request_timeout;
        envelope.validate_version().map_err(ClientError::Rpc)?;
        envelope
            .request
            .validate()
            .map_err(ClientError::InvalidRequest)?;
        let permit = acquire_request_permit(Arc::clone(&self.in_flight), deadline).await?;
        tokio::time::timeout_at(deadline, async {
            let _permit = permit;
            let (mut send, mut recv) = self.connection.open_bi().await?;
            write_message(&mut send, &envelope).await?;
            send.finish()
                .map_err(|error| ClientError::Iroh(error.to_string()))?;

            let response: ServerEnvelope = read_message(&mut recv, &self.inbound_budget).await?;
            let mut trailing = [0_u8; 1];
            if recv
                .read(&mut trailing)
                .await
                .map_err(|error| ClientError::Iroh(error.to_string()))?
                .is_some()
            {
                return Err(ClientError::TrailingData);
            }
            validate_response(&response, envelope.request_id)?;
            let value = outcome_value(response.outcome)?;
            validate_response_value(&envelope.request, &value)?;
            validate_provider_identity(self.provider_endpoint_id(), &value)?;
            Ok(value)
        })
        .await
        .map_err(|_| ClientError::Timeout)?
    }

    #[must_use]
    pub fn endpoint_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Authenticated endpoint identity of the connected RFQ provider.
    ///
    /// Callers use this value when verifying quote attestations, avoiding a
    /// second identity source outside the transport connection.
    #[must_use]
    pub fn provider_endpoint_id(&self) -> EndpointId {
        self.connection.remote_id()
    }

    pub async fn close(self) {
        self.connection.close(0_u32.into(), b"client closed");
        self.endpoint.close().await;
    }
}

async fn acquire_request_permit(
    in_flight: Arc<Semaphore>,
    deadline: tokio::time::Instant,
) -> Result<OwnedSemaphorePermit, ClientError> {
    tokio::time::timeout_at(deadline, in_flight.acquire_owned())
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|_| ClientError::Iroh("client request semaphore closed".into()))
}

fn outcome_value(outcome: RpcOutcome<Response>) -> Result<Response, ClientError> {
    match outcome {
        RpcOutcome::Success { value } => Ok(value),
        RpcOutcome::Error { error } => Err(ClientError::Rpc(error)),
    }
}

fn validate_response(response: &ServerEnvelope, request_id: RequestId) -> Result<(), ClientError> {
    if response.schema_version != SCHEMA_VERSION {
        return Err(ClientError::SchemaMismatch {
            expected: SCHEMA_VERSION,
            actual: response.schema_version,
        });
    }
    if response.request_id != request_id {
        return Err(ClientError::RequestIdMismatch {
            expected: request_id,
            actual: response.request_id,
        });
    }
    Ok(())
}

fn validate_response_shape(request: &Request, response: &Response) -> Result<(), ClientError> {
    if matches!(
        (request, response),
        (Request::GetInfo, Response::Info { .. })
            | (Request::RequestFirmQuote { .. }, Response::FirmQuote { .. })
            | (
                Request::CancelReservation { .. },
                Response::ReservationCancelled { .. }
            )
            | (Request::BlindPset { .. }, Response::BlindedPset { .. })
            | (Request::Execute { .. }, Response::ExecutionAccepted { .. })
            | (
                Request::GetReservationStatus { .. },
                Response::ReservationStatus { .. }
            )
    ) {
        Ok(())
    } else {
        Err(ClientError::WrongResponseShape)
    }
}

fn validate_response_value(request: &Request, response: &Response) -> Result<(), ClientError> {
    validate_response_shape(request, response)?;
    validate_response_request_binding(request, response)?;
    response.validate().map_err(ClientError::InvalidResponse)
}

fn validate_response_request_binding(
    request: &Request,
    response: &Response,
) -> Result<(), ClientError> {
    let matches = match (request, response) {
        (
            Request::RequestFirmQuote {
                idempotency_key,
                request,
            },
            Response::FirmQuote { quote, .. },
        ) => firm_quote_binding_matches(
            *idempotency_key,
            request,
            quote.attestation.idempotency_key,
            &quote.quote.request,
        ),
        (
            Request::CancelReservation { reservation_id },
            Response::ReservationCancelled { status },
        )
        | (Request::Execute { reservation_id, .. }, Response::ExecutionAccepted { status })
        | (
            Request::GetReservationStatus { reservation_id },
            Response::ReservationStatus { status },
        ) => status.reservation_id == *reservation_id,
        (
            Request::BlindPset { reservation_id, .. },
            Response::BlindedPset {
                reservation_id: returned,
                ..
            },
        ) => returned == reservation_id,
        (Request::GetInfo, Response::Info { .. }) => true,
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(ClientError::ResponseRequestMismatch)
    }
}

fn firm_quote_binding_matches(
    expected_idempotency_key: deadcat_rfq_rpc::IdempotencyKeyDto,
    expected_request: &deadcat_rfq_rpc::FirmQuoteRequestDto,
    actual_idempotency_key: deadcat_rfq_rpc::IdempotencyKeyDto,
    actual_request: &deadcat_rfq_rpc::FirmQuoteRequestDto,
) -> bool {
    actual_idempotency_key == expected_idempotency_key && actual_request == expected_request
}

fn validate_provider_identity(
    provider_endpoint: EndpointId,
    response: &Response,
) -> Result<(), ClientError> {
    let expected = *provider_endpoint.as_bytes();
    let matches = match response {
        Response::Info { info } => info.provider_endpoint.to_bytes() == expected,
        Response::FirmQuote { quote, .. } => {
            quote.quote.provider_endpoint.to_bytes() == expected
                && quote.attestation.provider_endpoint.to_bytes() == expected
        }
        Response::ReservationCancelled { .. }
        | Response::BlindedPset { .. }
        | Response::ExecutionAccepted { .. }
        | Response::ReservationStatus { .. } => true,
    };
    if matches {
        Ok(())
    } else {
        Err(ClientError::ProviderIdentityMismatch)
    }
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_rpc::{
        AssetAmountDto, FirmQuoteRequestDto, FixedBytes32, FixedBytes33, InputPlacementDto,
        OutputPlacementDto, ProviderCapability, ProviderInfo, QuoteContextDto, QuoteKindDto,
        QuoteRecipientDto, ReservationStateDto, ReservationStatusDto, RpcErrorCode, RpcOutcome,
        SettlementLayoutDto, SettlementPset,
    };
    use deadcat_types::{ContractId, LiquidNetwork};
    use elements::hashes::Hash as _;
    use elements::pset::PartiallySignedTransaction;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey as SecpSecretKey};
    use elements::{AssetId, BlockHash, OutPoint, Txid};

    use super::*;

    fn error_response(request_id: RequestId) -> ServerEnvelope {
        ServerEnvelope::new(
            request_id,
            RpcOutcome::Error {
                error: RpcError::new(RpcErrorCode::InternalError, "test")
                    .expect("bounded test error"),
            },
        )
    }

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("test asset")
    }

    fn quote_request(marker: u8) -> FirmQuoteRequestDto {
        let blinding_secret = SecpSecretKey::from_slice(&[marker; 32]).expect("test secret");
        let blinding_public_key = PublicKey::from_secret_key(&Secp256k1::new(), &blinding_secret);
        FirmQuoteRequestDto {
            context: QuoteContextDto {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_byte_array([marker.wrapping_add(1); 32]),
                market: ContractId::new(OutPoint::new(
                    Txid::from_byte_array([marker.wrapping_add(2); 32]),
                    0,
                )),
                policy_asset: asset(marker.wrapping_add(3)),
            },
            kind: QuoteKindDto::ExactIn {
                input: AssetAmountDto {
                    asset: asset(marker.wrapping_add(4)),
                    amount: 100,
                },
                output_asset: asset(marker.wrapping_add(5)),
                minimum_output: 90,
            },
            recipient: QuoteRecipientDto {
                script_pubkey: vec![0x51],
                blinding_public_key: FixedBytes33::new(blinding_public_key.serialize()),
            },
            maximum_input_asset_venue_fee: 10,
        }
    }

    fn status(reservation_id: FixedBytes32) -> ReservationStatusDto {
        ReservationStatusDto {
            reservation_id,
            quote_commitment: FixedBytes32::new([0x77; 32]),
            created_at_millis: 1,
            accept_before_millis: 2,
            state: ReservationStateDto::Reserved,
        }
    }

    #[test]
    fn response_schema_and_request_id_must_match() {
        let expected = RequestId(41);
        let mut wrong_schema = error_response(expected);
        wrong_schema.schema_version += 1;
        assert!(matches!(
            validate_response(&wrong_schema, expected),
            Err(ClientError::SchemaMismatch { .. })
        ));

        let wrong_id = error_response(RequestId(42));
        assert!(matches!(
            validate_response(&wrong_id, expected),
            Err(ClientError::RequestIdMismatch { .. })
        ));
    }

    #[test]
    fn response_variant_must_match_request_method() {
        let request = Request::CancelReservation {
            reservation_id: FixedBytes32::new([0x11; 32]),
        };
        let response = Response::Info {
            info: ProviderInfo {
                provider_endpoint: FixedBytes32::new([0x22; 32]),
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .expect("test block hash"),
                policy_asset: "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .expect("test asset id"),
                capabilities: vec![ProviderCapability::FirmQuotes],
            },
        };
        assert!(matches!(
            validate_response_shape(&request, &response),
            Err(ClientError::WrongResponseShape)
        ));
    }

    #[test]
    fn method_matching_response_must_pass_semantic_validation() {
        let reservation_id = FixedBytes32::new([0x33; 32]);
        let request = Request::GetReservationStatus { reservation_id };
        let response = Response::ReservationStatus {
            status: ReservationStatusDto {
                reservation_id,
                quote_commitment: FixedBytes32::new([0x44; 32]),
                created_at_millis: 2,
                accept_before_millis: 1,
                state: ReservationStateDto::Reserved,
            },
        };
        assert!(matches!(
            validate_response_value(&request, &response),
            Err(ClientError::InvalidResponse(_))
        ));
    }

    #[test]
    fn response_provider_must_match_authenticated_connection_peer() {
        let provider_key = SecretKey::generate();
        let wrong_provider = Response::Info {
            info: ProviderInfo {
                provider_endpoint: FixedBytes32::new([0x66; 32]),
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .expect("test block hash"),
                policy_asset: "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .expect("test asset id"),
                capabilities: vec![ProviderCapability::FirmQuotes],
            },
        };
        assert!(matches!(
            validate_provider_identity(provider_key.public(), &wrong_provider),
            Err(ClientError::ProviderIdentityMismatch)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_permit_obeys_the_single_operation_deadline() {
        let semaphore = Arc::new(Semaphore::new(1));
        let _held = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("test semaphore open");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let waiting = tokio::spawn(acquire_request_permit(semaphore, deadline));
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;

        assert!(matches!(
            waiting.await.expect("permit task"),
            Err(ClientError::Timeout)
        ));
    }

    #[test]
    fn reservation_responses_cannot_be_replayed_across_requests() {
        let requested = FixedBytes32::new([0x81; 32]);
        let returned = FixedBytes32::new([0x82; 32]);
        let layout = SettlementLayoutDto {
            taker_payment_input: 0,
            provider_inputs: vec![InputPlacementDto {
                quote_input_id: 0,
                transaction_index: 1,
            }],
            quote_outputs: vec![OutputPlacementDto {
                quote_output_id: 0,
                transaction_index: 0,
            }],
        };
        let pset = SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
            .expect("valid test PSET");
        let cases = [
            (
                Request::CancelReservation {
                    reservation_id: requested,
                },
                Response::ReservationCancelled {
                    status: status(returned),
                },
            ),
            (
                Request::BlindPset {
                    reservation_id: requested,
                    layout: layout.clone(),
                    pset: pset.clone(),
                },
                Response::BlindedPset {
                    reservation_id: returned,
                    pset: pset.clone(),
                },
            ),
            (
                Request::Execute {
                    reservation_id: requested,
                    layout,
                    pset,
                },
                Response::ExecutionAccepted {
                    status: status(returned),
                },
            ),
            (
                Request::GetReservationStatus {
                    reservation_id: requested,
                },
                Response::ReservationStatus {
                    status: status(returned),
                },
            ),
        ];

        for (request, response) in cases {
            assert!(matches!(
                validate_response_request_binding(&request, &response),
                Err(ClientError::ResponseRequestMismatch)
            ));
        }
    }

    #[test]
    fn firm_quote_binding_requires_idempotency_key_and_exact_request() {
        let expected_key = FixedBytes32::new([0x91; 32]);
        let expected_request = quote_request(9);
        assert!(!firm_quote_binding_matches(
            expected_key,
            &expected_request,
            FixedBytes32::new([0x92; 32]),
            &expected_request,
        ));

        let mut changed_request = expected_request.clone();
        changed_request.maximum_input_asset_venue_fee += 1;
        assert!(!firm_quote_binding_matches(
            expected_key,
            &expected_request,
            expected_key,
            &changed_request,
        ));
        assert!(firm_quote_binding_matches(
            expected_key,
            &expected_request,
            expected_key,
            &expected_request,
        ));
    }
}
