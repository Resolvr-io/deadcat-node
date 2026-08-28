//! Transport-facing request handler implemented by the RFQ service.

use deadcat_rfq_rpc::{Request, RequestEnvelope, Response, RpcError, RpcErrorCode};

/// Authenticated Iroh endpoint identity of the connected client.
pub type ClientId = [u8; 32];

/// Dispatch target for the RFQ Iroh server adapter.
pub trait RequestHandler: Send + Sync + 'static {
    /// Validate an envelope before dispatch.
    ///
    /// The transport always enforces schema and method-local semantic
    /// validation first. Implementations may add cheap synchronous policy
    /// checks; reservation authorization belongs in [`Self::handle`] and must
    /// be derived from `peer` rather than wire data.
    fn validate(&self, _peer: ClientId, envelope: &RequestEnvelope) -> Result<(), RpcError> {
        validate_protocol_request(envelope)
    }

    /// Handle one authenticated request.
    ///
    /// The transport cancels this future when `ServerConfig::handler_timeout`
    /// elapses. An `Execute` implementation must therefore transfer any work
    /// that follows its durable point of no return to daemon-owned recovery
    /// before crossing that boundary; signing, persistence, and relay must not
    /// depend on this future continuing to be polled.
    fn handle(
        &self,
        peer: ClientId,
        request: Request,
    ) -> impl Future<Output = Result<Response, RpcError>> + Send;
}

pub(crate) fn validate_protocol_request(envelope: &RequestEnvelope) -> Result<(), RpcError> {
    envelope.validate_version()?;
    envelope.request.validate().map_err(|_| {
        RpcError::new(RpcErrorCode::InvalidRequest, "invalid RFQ request")
            .expect("static request error satisfies public RPC bounds")
    })
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_rpc::{
        FixedBytes32, InputPlacementDto, OutputPlacementDto, RequestId, SettlementLayoutDto,
        SettlementPset,
    };
    use elements::pset::PartiallySignedTransaction;

    use super::*;

    #[test]
    fn protocol_validation_rejects_semantically_invalid_requests() {
        let envelope = RequestEnvelope::new(
            RequestId(1),
            Request::BlindPset {
                reservation_id: FixedBytes32::new([0x55; 32]),
                layout: SettlementLayoutDto {
                    taker_payment_input: 0,
                    provider_inputs: vec![InputPlacementDto {
                        quote_input_id: 0,
                        transaction_index: 0,
                    }],
                    quote_outputs: vec![OutputPlacementDto {
                        quote_output_id: 0,
                        transaction_index: 0,
                    }],
                },
                pset: SettlementPset::from_pset(&PartiallySignedTransaction::new_v2())
                    .expect("valid test PSET"),
            },
        );

        let error = validate_protocol_request(&envelope).expect_err("aliased input");
        assert_eq!(error.code(), RpcErrorCode::InvalidRequest);
    }
}
