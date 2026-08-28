//! Strict v1 wire schema and Iroh-identity attestations for a noncustodial RFQ
//! provider.
//!
//! The transport authenticates both Iroh endpoints. This schema deliberately
//! never accepts a provider-domain `OwnerId`; the server derives it from the
//! authenticated endpoint pair with [`owner_id_from_endpoints`]. Firm quotes
//! additionally carry an application signature by the provider's stable Iroh
//! identity so they can be retained and independently verified after a stream
//! closes or their acceptance window expires. Authenticity and current quote
//! liveness are represented by distinct capability types.

mod codec;
mod quote;

pub use codec::{FixedBytes32, FixedBytes33, FixedBytes64};
pub use quote::{
    AssetAmountDto, AttestationError, BlinderRoleDto, FeePolicyDto, FeeSizeMetricDto, FirmQuoteDto,
    FirmQuoteRequestDto, FirmQuoteValidationError, IdempotencyKeyDto, InputPlacementDto,
    LiveFirmQuote, MAX_RECIPIENT_SCRIPT_BYTES, MAX_SETTLEMENT_BYTES, MAX_SETTLEMENT_INPUTS,
    MAX_SETTLEMENT_OUTPUTS, OutputPlacementDto, PricingDecisionDto, PsetError, QuoteAttestation,
    QuoteContextDto, QuoteExecutionDto, QuoteInputDto, QuoteKindDto, QuoteOutputDto,
    QuoteOutputRoleDto, QuoteRecipientDto, RationalRateDto, ReleaseReasonDto, ReservationIdDto,
    ReservationStateDto, ReservationStatusDto, SettlementLayoutDto, SettlementPset,
    SignedFirmQuote, SnapshotEvidenceDto, TxOutDto, VerifiedFirmQuote, owner_id_from_endpoints,
};

use serde::{Deserialize, Serialize};

/// Iroh application protocol dedicated to RFQ traffic.
pub const ALPN: &[u8] = b"deadcat-rfq/1";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(#[serde(with = "codec::u64_string")] pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub request: Request,
}

impl RequestEnvelope {
    #[must_use]
    pub const fn new(request_id: RequestId, request: Request) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            request_id,
            request,
        }
    }

    pub fn validate_version(&self) -> Result<(), RpcError> {
        validate_version(self.schema_version)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerEnvelope {
    pub schema_version: u32,
    pub request_id: RequestId,
    pub outcome: RpcOutcome<Response>,
}

impl ServerEnvelope {
    #[must_use]
    pub const fn new(request_id: RequestId, outcome: RpcOutcome<Response>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            request_id,
            outcome,
        }
    }

    pub fn validate_version(&self) -> Result<(), RpcError> {
        validate_version(self.schema_version)
    }
}

fn validate_version(actual: u32) -> Result<(), RpcError> {
    if actual == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(RpcError::from_static(
            RpcErrorCode::UnsupportedVersion,
            "unsupported RFQ schema version",
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum Request {
    GetInfo,
    RequestFirmQuote {
        idempotency_key: IdempotencyKeyDto,
        request: FirmQuoteRequestDto,
    },
    CancelReservation {
        reservation_id: ReservationIdDto,
    },
    BlindPset {
        reservation_id: ReservationIdDto,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    },
    Execute {
        reservation_id: ReservationIdDto,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    },
    GetReservationStatus {
        reservation_id: ReservationIdDto,
    },
}

impl Request {
    /// Perform method-local semantic checks after bounded deserialization and
    /// before the runtime touches provider state or proof verification.
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        match self {
            Self::GetInfo | Self::CancelReservation { .. } | Self::GetReservationStatus { .. } => {
                Ok(())
            }
            Self::RequestFirmQuote { request, .. } => request.validate(),
            Self::BlindPset { layout, .. } | Self::Execute { layout, .. } => layout.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum Response {
    Info {
        info: ProviderInfo,
    },
    FirmQuote {
        quote: SignedFirmQuote,
        status: ReservationStatusDto,
    },
    ReservationCancelled {
        status: ReservationStatusDto,
    },
    BlindedPset {
        reservation_id: ReservationIdDto,
        pset: SettlementPset,
    },
    ExecutionAccepted {
        status: ReservationStatusDto,
    },
    ReservationStatus {
        status: ReservationStatusDto,
    },
}

impl Response {
    /// Check all semantics that need no pinned peer, request context, clock,
    /// chain source, or provider database.
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        match self {
            Self::Info { .. } | Self::BlindedPset { .. } => Ok(()),
            Self::FirmQuote { quote, status } => {
                quote.quote.validate_structure()?;
                if quote.attestation.provider_endpoint != quote.quote.provider_endpoint {
                    return Err(FirmQuoteValidationError::ProviderAttestationMismatch);
                }
                status.validate()?;
                if status.reservation_id != quote.quote.reservation_id
                    || status.quote_commitment != quote.quote.quote_commitment
                    || status.created_at_millis != quote.quote.created_at_millis
                    || status.accept_before_millis != quote.quote.accept_before_millis
                {
                    return Err(FirmQuoteValidationError::QuoteStatusMismatch);
                }
                Ok(())
            }
            Self::ReservationCancelled { status } => {
                status.validate()?;
                if !matches!(
                    &status.state,
                    ReservationStateDto::Released {
                        reason: ReleaseReasonDto::ClientCancelled | ReleaseReasonDto::Expired,
                        ..
                    }
                ) {
                    return Err(FirmQuoteValidationError::InvalidCancellationState);
                }
                Ok(())
            }
            Self::ExecutionAccepted { status } => {
                status.validate()?;
                if !matches!(
                    &status.state,
                    ReservationStateDto::Committed { .. } | ReservationStateDto::Signed { .. }
                ) {
                    return Err(FirmQuoteValidationError::InvalidExecutionState);
                }
                Ok(())
            }
            Self::ReservationStatus { status } => status.validate(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInfo {
    pub provider_endpoint: FixedBytes32,
    pub network: deadcat_types::LiquidNetwork,
    pub genesis_hash: elements::BlockHash,
    pub policy_asset: elements::AssetId,
    pub capabilities: Vec<ProviderCapability>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    FirmQuotes,
    ProviderBlinding,
    SettlementExecution,
    DurableStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RpcOutcome<T> {
    Success { value: T },
    Error { error: RpcError },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RpcError {
    code: RpcErrorCode,
    message: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_u64_string"
    )]
    retry_after_millis: Option<u64>,
}

impl RpcError {
    pub fn new(
        code: RpcErrorCode,
        message: impl Into<String>,
    ) -> Result<Self, RpcErrorValidationError> {
        Self::with_retry_after(code, message, None)
    }

    pub fn with_retry_after(
        code: RpcErrorCode,
        message: impl Into<String>,
        retry_after_millis: Option<u64>,
    ) -> Result<Self, RpcErrorValidationError> {
        let value = Self {
            code,
            message: message.into(),
            retry_after_millis,
        };
        value.validate()?;
        Ok(value)
    }

    fn from_static(code: RpcErrorCode, message: &'static str) -> Self {
        debug_assert!(message.chars().count() <= MAX_ERROR_MESSAGE_CHARS);
        Self {
            code,
            message: message.to_owned(),
            retry_after_millis: None,
        }
    }

    pub fn validate(&self) -> Result<(), RpcErrorValidationError> {
        if self.message.chars().count() > MAX_ERROR_MESSAGE_CHARS {
            return Err(RpcErrorValidationError::MessageTooLong);
        }
        if self.retry_after_millis.is_some()
            && !matches!(
                self.code,
                RpcErrorCode::RateLimited | RpcErrorCode::BackendUnavailable
            )
        {
            return Err(RpcErrorValidationError::RetryAfterNotAllowed);
        }
        if self.retry_after_millis == Some(0) {
            return Err(RpcErrorValidationError::ZeroRetryAfter);
        }
        Ok(())
    }

    #[must_use]
    pub const fn code(&self) -> RpcErrorCode {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn retry_after_millis(&self) -> Option<u64> {
        self.retry_after_millis
    }
}

impl<'de> Deserialize<'de> for RpcError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            code: RpcErrorCode,
            message: String,
            #[serde(default, with = "optional_u64_string")]
            retry_after_millis: Option<u64>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::with_retry_after(wire.code, wire.message, wire.retry_after_millis)
            .map_err(serde::de::Error::custom)
    }
}

mod optional_u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| {
                if value.is_empty()
                    || (value.len() > 1 && value.starts_with('0'))
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(serde::de::Error::custom(
                        "expected canonical decimal u64 string",
                    ));
                }
                value.parse().map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

pub const MAX_ERROR_MESSAGE_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RpcErrorValidationError {
    #[error("public RFQ error message exceeds {MAX_ERROR_MESSAGE_CHARS} characters")]
    MessageTooLong,
    #[error("retry_after_millis is only valid for rate-limited or unavailable responses")]
    RetryAfterNotAllowed,
    #[error("retry_after_millis must be positive when present")]
    ZeroRetryAfter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    UnsupportedVersion,
    InvalidRequest,
    UnsupportedMarket,
    UnsupportedPair,
    FillOutOfRange,
    InsufficientInventory,
    QuoteExpired,
    IdempotencyConflict,
    LiveQuoteLimit,
    RateLimited,
    ReservationUnavailable,
    ReservationReleased,
    PointOfNoReturn,
    InvalidLayout,
    InvalidPset,
    FeePolicyRejected,
    BackendUnavailable,
    InternalError,
}

#[cfg(test)]
mod tests {
    use elements::pset::PartiallySignedTransaction;

    use super::*;

    #[test]
    fn envelopes_are_strict_and_u64_is_a_string() {
        let encoded =
            serde_json::to_string(&RequestEnvelope::new(RequestId(u64::MAX), Request::GetInfo))
                .expect("encode");
        assert!(encoded.contains("\"request_id\":\"18446744073709551615\""));
        assert!(serde_json::from_str::<RequestEnvelope>(&encoded).is_ok());
        let extra = encoded.replacen('{', "{\"extra\":true,", 1);
        assert!(serde_json::from_str::<RequestEnvelope>(&extra).is_err());
        assert!(
            serde_json::from_str::<RequestEnvelope>(
                r#"{"schema_version":1,"request_id":1,"request":"get_info"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn version_is_checked() {
        let mut request = RequestEnvelope::new(RequestId(1), Request::GetInfo);
        request.schema_version += 1;
        assert_eq!(
            request.validate_version().expect_err("version").code(),
            RpcErrorCode::UnsupportedVersion
        );
    }

    #[test]
    fn blinded_pset_response_carries_its_reservation_id() {
        let reservation_id = FixedBytes32::new([0x42; 32]);
        let envelope = ServerEnvelope::new(
            RequestId(2),
            RpcOutcome::Success {
                value: Response::BlindedPset {
                    reservation_id,
                    pset: SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
                        .expect("valid test PSET"),
                },
            },
        );
        let encoded = serde_json::to_string(&envelope).expect("encode");
        assert!(encoded.contains(&format!(
            "\"reservation_id\":\"{}\"",
            hex::encode(reservation_id.to_bytes())
        )));
        assert_eq!(
            serde_json::from_str::<ServerEnvelope>(&encoded).expect("decode"),
            envelope
        );
    }

    #[test]
    fn public_errors_are_bounded_and_retry_hints_are_constrained() {
        assert_eq!(
            RpcError::new(RpcErrorCode::InvalidRequest, "x".repeat(513)),
            Err(RpcErrorValidationError::MessageTooLong)
        );
        assert_eq!(
            RpcError::with_retry_after(RpcErrorCode::InvalidRequest, "bad", Some(10)),
            Err(RpcErrorValidationError::RetryAfterNotAllowed)
        );
        assert_eq!(
            RpcError::with_retry_after(RpcErrorCode::RateLimited, "later", Some(0)),
            Err(RpcErrorValidationError::ZeroRetryAfter)
        );
        let value = RpcError::with_retry_after(RpcErrorCode::RateLimited, "later", Some(250))
            .expect("error");
        let encoded = serde_json::to_string(&value).expect("encode");
        assert!(encoded.contains("\"retry_after_millis\":\"250\""));
        assert_eq!(
            serde_json::from_str::<RpcError>(&encoded).expect("decode"),
            value
        );
        let oversized = format!(
            r#"{{"code":"internal_error","message":"{}"}}"#,
            "é".repeat(513)
        );
        assert!(serde_json::from_str::<RpcError>(&oversized).is_err());
    }
}
