//! Taker-side trust transitions for collaborative RFQ settlement.
//!
//! A provider-blinded PSET is authenticated transport output, not signing
//! authority. The caller-owned wallet boundary must validate the complete
//! transaction and add every required taker signature before this module will
//! produce an execution attempt. The attempt retains the exact submitted
//! layout and PSET behind a versioned, self-consistency-checked durable record.

use deadcat_rfq_rpc::{
    FirmQuoteValidationError, FixedBytes32, ReservationIdDto, SettlementLayoutDto, SettlementPset,
};
use deadcat_types::{ChainIdentity, LiquidNetwork, serde_u64_string};
use elements::AssetId;
use elements::hashes::Hash as _;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ResolvedRfqSettlement;

pub const EXECUTION_ATTEMPT_RECORD_VERSION: u32 = 1;

const EXECUTION_ATTEMPT_DOMAIN: &[u8] = b"deadcat/rfq/client-execution-attempt/v1";

/// Immutable reservation identity copied from a resolved authenticated quote.
///
/// This is journal data rather than network authorization. A recovered binding
/// must still be matched with a freshly authenticated session and reservation
/// before any request is sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    provider_endpoint: FixedBytes32,
    client_endpoint: FixedBytes32,
    chain: ChainIdentity,
    policy_asset: AssetId,
    reservation_id: ReservationIdDto,
    quote_commitment: FixedBytes32,
    #[serde(with = "serde_u64_string")]
    created_at_millis: u64,
    #[serde(with = "serde_u64_string")]
    accept_before_millis: u64,
}

impl ExecutionBinding {
    fn from_settlement(settlement: &ResolvedRfqSettlement) -> Self {
        let handle = settlement.handle();
        Self {
            provider_endpoint: FixedBytes32::new(*handle.provider_endpoint().as_bytes()),
            client_endpoint: FixedBytes32::new(*handle.client_endpoint().as_bytes()),
            chain: handle.chain(),
            policy_asset: handle.policy_asset(),
            reservation_id: handle.reservation_id(),
            quote_commitment: handle.quote_commitment(),
            created_at_millis: handle.created_at_millis(),
            accept_before_millis: handle.accept_before_millis(),
        }
    }

    #[must_use]
    pub const fn provider_endpoint(&self) -> FixedBytes32 {
        self.provider_endpoint
    }

    #[must_use]
    pub const fn client_endpoint(&self) -> FixedBytes32 {
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

    fn validate(&self) -> Result<(), ExecutionAttemptError> {
        EndpointId::from_bytes(&self.provider_endpoint.to_bytes())
            .map_err(|_| ExecutionAttemptError::InvalidProviderEndpoint)?;
        EndpointId::from_bytes(&self.client_endpoint.to_bytes())
            .map_err(|_| ExecutionAttemptError::InvalidClientEndpoint)?;
        if self.created_at_millis >= self.accept_before_millis {
            return Err(ExecutionAttemptError::InvalidReservationTimeline);
        }
        Ok(())
    }

    fn matches_settlement(&self, settlement: &ResolvedRfqSettlement) -> bool {
        self == &Self::from_settlement(settlement)
    }
}

/// Provider-returned collaborative blinding result.
///
/// The contained PSET is deliberately not a signing capability. It must cross
/// [`TakerSettlementAuthorizer`] before it can become a provider execution
/// request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderBlindedPset {
    binding: ExecutionBinding,
    layout: SettlementLayoutDto,
    pset: SettlementPset,
}

impl ProviderBlindedPset {
    /// Wrap an authenticated `BlindPset` response.
    ///
    /// This remains crate-private so only the RFQ session transport adapter can
    /// assert provider-response provenance.
    pub(crate) fn from_provider_response(
        settlement: &ResolvedRfqSettlement,
        pset: SettlementPset,
    ) -> Self {
        Self {
            binding: ExecutionBinding::from_settlement(settlement),
            layout: settlement.layout().clone(),
            pset,
        }
    }

    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn layout(&self) -> &SettlementLayoutDto {
        &self.layout
    }

    #[must_use]
    pub const fn pset(&self) -> &SettlementPset {
        &self.pset
    }

    /// Invoke the caller-owned whole-transaction validator and signer.
    ///
    /// Borrowing `self` preserves the provider response when validation or
    /// signing fails. The authorizer returns a new exact PSET after completing
    /// every wallet-specific safety check and taker signature.
    pub fn authorize_with<A>(&self, authorizer: &A) -> Result<TakerAuthorizedSettlement, A::Error>
    where
        A: TakerSettlementAuthorizer,
    {
        let pset = authorizer.validate_and_sign(&self.binding, &self.layout, &self.pset)?;
        Ok(TakerAuthorizedSettlement {
            binding: self.binding,
            layout: self.layout.clone(),
            pset,
        })
    }
}

/// Caller-owned validation and signing boundary.
///
/// Implementations must distrust the provider-returned PSET. At minimum they
/// must revalidate the frozen transaction body, authoritative prevouts,
/// confidential commitments/proofs and owned output openings, economic and fee
/// policy, every input's sighash policy, and all pre-existing signatures before
/// adding the taker's required signatures. The returned PSET is the exact value
/// that may be submitted to the provider.
pub trait TakerSettlementAuthorizer {
    type Error;

    fn validate_and_sign(
        &self,
        binding: &ExecutionBinding,
        layout: &SettlementLayoutDto,
        provider_blinded_pset: &SettlementPset,
    ) -> Result<SettlementPset, Self::Error>;
}

/// Complete settlement approved and signed by the caller-owned wallet boundary.
///
/// This point-in-process capability is intentionally not deserializable. Create
/// a validated [`ExecutionAttemptRecord`] before network dispatch when durable
/// recovery is required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakerAuthorizedSettlement {
    binding: ExecutionBinding,
    layout: SettlementLayoutDto,
    pset: SettlementPset,
}

impl TakerAuthorizedSettlement {
    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn layout(&self) -> &SettlementLayoutDto {
        &self.layout
    }

    #[must_use]
    pub const fn pset(&self) -> &SettlementPset {
        &self.pset
    }

    /// Snapshot the exact authorized payload for durable execution/recovery.
    #[must_use]
    pub fn execution_attempt(&self) -> ExecutionAttempt {
        ExecutionAttempt::new(self.binding, self.layout.clone(), self.pset.clone())
    }

    /// Move the exact authorized payload into durable execution/recovery state.
    #[must_use]
    pub fn into_execution_attempt(self) -> ExecutionAttempt {
        ExecutionAttempt::new(self.binding, self.layout, self.pset)
    }
}

/// Client-computable identifier for one exact execution attempt.
///
/// This is an unkeyed digest for equality, correlation, and accidental
/// corruption detection. It does not authenticate a journal record against a
/// caller able to rewrite the record and recompute the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionAttemptDigest(FixedBytes32);

impl ExecutionAttemptDigest {
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    #[must_use]
    pub const fn as_fixed_bytes(&self) -> &FixedBytes32 {
        &self.0
    }
}

/// Versioned journal representation of an exact taker-authorized execution.
///
/// Deserialization alone establishes neither authenticity nor
/// self-consistency. Call [`ExecutionAttempt::from_record`] before relying on a
/// recovered record. Callers that need protection from hostile journal
/// modification must authenticate the record or its storage separately.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAttemptRecord {
    version: u32,
    binding: ExecutionBinding,
    layout: SettlementLayoutDto,
    pset: SettlementPset,
    digest: ExecutionAttemptDigest,
}

impl ExecutionAttemptRecord {
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.binding
    }

    #[must_use]
    pub const fn layout(&self) -> &SettlementLayoutDto {
        &self.layout
    }

    #[must_use]
    pub const fn pset(&self) -> &SettlementPset {
        &self.pset
    }

    #[must_use]
    pub const fn digest(&self) -> ExecutionAttemptDigest {
        self.digest
    }
}

/// Self-consistency-checked exact retry material for a possibly ambiguous
/// execute.
///
/// Keep this value (or its record) until the reservation reaches a definitive
/// released, committed, or signed state. A transport error is not evidence that
/// the provider failed to cross its durable point of no return.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttempt {
    record: ExecutionAttemptRecord,
}

impl ExecutionAttempt {
    fn new(binding: ExecutionBinding, layout: SettlementLayoutDto, pset: SettlementPset) -> Self {
        let digest = execution_attempt_digest(&binding, &layout, &pset);
        Self {
            record: ExecutionAttemptRecord {
                version: EXECUTION_ATTEMPT_RECORD_VERSION,
                binding,
                layout,
                pset,
                digest,
            },
        }
    }

    /// Validate an untrusted durable record and recover the execution attempt.
    pub fn from_record(record: ExecutionAttemptRecord) -> Result<Self, ExecutionAttemptError> {
        if record.version != EXECUTION_ATTEMPT_RECORD_VERSION {
            return Err(ExecutionAttemptError::UnsupportedRecordVersion {
                actual: record.version,
            });
        }
        record.binding.validate()?;
        record.layout.validate()?;
        let expected = execution_attempt_digest(&record.binding, &record.layout, &record.pset);
        if record.digest != expected {
            return Err(ExecutionAttemptError::DigestMismatch);
        }
        Ok(Self { record })
    }

    #[must_use]
    pub const fn binding(&self) -> &ExecutionBinding {
        &self.record.binding
    }

    #[must_use]
    pub const fn layout(&self) -> &SettlementLayoutDto {
        &self.record.layout
    }

    #[must_use]
    pub const fn pset(&self) -> &SettlementPset {
        &self.record.pset
    }

    #[must_use]
    pub const fn digest(&self) -> ExecutionAttemptDigest {
        self.record.digest
    }

    #[must_use]
    pub fn to_record(&self) -> ExecutionAttemptRecord {
        self.record.clone()
    }

    #[must_use]
    pub fn into_record(self) -> ExecutionAttemptRecord {
        self.record
    }

    /// Match recovered retry material to the freshly resolved live reservation.
    pub fn validate_for_settlement(
        &self,
        settlement: &ResolvedRfqSettlement,
    ) -> Result<(), ExecutionAttemptError> {
        if !self.record.binding.matches_settlement(settlement) {
            return Err(ExecutionAttemptError::ReservationBindingMismatch);
        }
        if &self.record.layout != settlement.layout() {
            return Err(ExecutionAttemptError::SettlementLayoutMismatch);
        }
        Ok(())
    }

    /// Check whether exact returned or journaled PSET bytes match this attempt.
    #[must_use]
    pub fn matches_pset(&self, pset: &SettlementPset) -> bool {
        self.record.pset == *pset
    }
}

fn execution_attempt_digest(
    binding: &ExecutionBinding,
    layout: &SettlementLayoutDto,
    pset: &SettlementPset,
) -> ExecutionAttemptDigest {
    let mut digest = Sha256::new();
    hash_len_prefixed(&mut digest, EXECUTION_ATTEMPT_DOMAIN);
    digest.update(EXECUTION_ATTEMPT_RECORD_VERSION.to_be_bytes());
    digest.update(binding.provider_endpoint.to_bytes());
    digest.update(binding.client_endpoint.to_bytes());
    digest.update([network_tag(binding.chain.network)]);
    digest.update(binding.chain.genesis_hash.to_byte_array());
    digest.update(binding.policy_asset.into_inner().to_byte_array());
    digest.update(binding.reservation_id.to_bytes());
    digest.update(binding.quote_commitment.to_bytes());
    digest.update(binding.created_at_millis.to_be_bytes());
    digest.update(binding.accept_before_millis.to_be_bytes());
    digest.update(layout.taker_payment_input.to_be_bytes());
    digest.update(encoded_len(layout.provider_inputs.len()));
    for placement in &layout.provider_inputs {
        digest.update(placement.quote_input_id.to_be_bytes());
        digest.update(placement.transaction_index.to_be_bytes());
    }
    digest.update(encoded_len(layout.quote_outputs.len()));
    for placement in &layout.quote_outputs {
        digest.update(placement.quote_output_id.to_be_bytes());
        digest.update(placement.transaction_index.to_be_bytes());
    }
    hash_len_prefixed(&mut digest, pset.as_bytes());
    ExecutionAttemptDigest(FixedBytes32::new(digest.finalize().into()))
}

fn hash_len_prefixed(digest: &mut Sha256, bytes: &[u8]) {
    digest.update(encoded_len(bytes.len()));
    digest.update(bytes);
}

const fn network_tag(network: LiquidNetwork) -> u8 {
    match network {
        LiquidNetwork::Liquid => 0,
        LiquidNetwork::LiquidTestnet => 1,
        LiquidNetwork::ElementsRegtest => 2,
    }
}

fn encoded_len(len: usize) -> [u8; 8] {
    u64::try_from(len)
        .expect("RFQ protocol bounds fit in u64")
        .to_be_bytes()
}

#[derive(Debug, Error)]
pub enum ExecutionAttemptError {
    #[error("unsupported execution-attempt record version {actual}")]
    UnsupportedRecordVersion { actual: u32 },
    #[error("execution-attempt provider endpoint is invalid")]
    InvalidProviderEndpoint,
    #[error("execution-attempt client endpoint is invalid")]
    InvalidClientEndpoint,
    #[error("execution-attempt reservation timeline is invalid")]
    InvalidReservationTimeline,
    #[error("execution-attempt settlement layout is invalid: {0}")]
    InvalidSettlementLayout(#[from] FirmQuoteValidationError),
    #[error("execution-attempt digest does not match its exact payload")]
    DigestMismatch,
    #[error("execution attempt belongs to a different RFQ reservation")]
    ReservationBindingMismatch,
    #[error("execution attempt uses a different resolved settlement layout")]
    SettlementLayoutMismatch,
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_rpc::{InputPlacementDto, OutputPlacementDto};
    use elements::hashes::Hash as _;
    use elements::pset::{Output as PsetOutput, PartiallySignedTransaction};
    use elements::{AssetId, BlockHash, TxOut};
    use iroh::SecretKey;

    use super::*;

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("fixture asset")
    }

    fn pset() -> SettlementPset {
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(50, asset(7))));
        SettlementPset::from_pset(&pset).expect("fixture PSET")
    }

    fn other_pset() -> SettlementPset {
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(51, asset(7))));
        SettlementPset::from_pset(&pset).expect("other fixture PSET")
    }

    fn binding() -> ExecutionBinding {
        ExecutionBinding {
            provider_endpoint: FixedBytes32::new(
                *SecretKey::from_bytes(&[3; 32]).public().as_bytes(),
            ),
            client_endpoint: FixedBytes32::new(
                *SecretKey::from_bytes(&[4; 32]).public().as_bytes(),
            ),
            chain: ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::from_byte_array([11; 32]),
            },
            policy_asset: asset(7),
            reservation_id: FixedBytes32::new([5; 32]),
            quote_commitment: FixedBytes32::new([6; 32]),
            created_at_millis: 1_000,
            accept_before_millis: 31_000,
        }
    }

    fn layout() -> SettlementLayoutDto {
        SettlementLayoutDto {
            taker_payment_input: 0,
            provider_inputs: vec![InputPlacementDto {
                quote_input_id: 7,
                transaction_index: 1,
            }],
            quote_outputs: vec![OutputPlacementDto {
                quote_output_id: 8,
                transaction_index: 0,
            }],
        }
    }

    struct TestAuthorizer;

    impl TakerSettlementAuthorizer for TestAuthorizer {
        type Error = std::convert::Infallible;

        fn validate_and_sign(
            &self,
            actual_binding: &ExecutionBinding,
            actual_layout: &SettlementLayoutDto,
            provider_blinded_pset: &SettlementPset,
        ) -> Result<SettlementPset, Self::Error> {
            assert_eq!(actual_binding, &binding());
            assert_eq!(actual_layout, &layout());
            assert_eq!(provider_blinded_pset, &pset());
            Ok(other_pset())
        }
    }

    fn authorized() -> TakerAuthorizedSettlement {
        ProviderBlindedPset {
            binding: binding(),
            layout: layout(),
            pset: pset(),
        }
        .authorize_with(&TestAuthorizer)
        .expect("infallible test authorization")
    }

    #[test]
    fn provider_output_crosses_explicit_authorizer_before_execution() {
        let authorized = authorized();
        assert_eq!(authorized.binding(), &binding());
        assert_eq!(authorized.layout(), &layout());
        assert_eq!(authorized.pset(), &other_pset());

        let attempt = authorized.into_execution_attempt();
        assert_eq!(attempt.binding(), &binding());
        assert_eq!(attempt.layout(), &layout());
        assert_eq!(attempt.pset(), &other_pset());
        assert!(attempt.matches_pset(&other_pset()));
        assert!(!attempt.matches_pset(&pset()));
    }

    #[test]
    fn durable_record_round_trip_recomputes_exact_digest() {
        let attempt = authorized().into_execution_attempt();
        let encoded = serde_json::to_vec(&attempt.to_record()).expect("serialize attempt record");
        let record = serde_json::from_slice(&encoded).expect("deserialize attempt record");
        let recovered = ExecutionAttempt::from_record(record).expect("validate durable record");
        assert_eq!(recovered, attempt);
        assert_eq!(recovered.digest(), attempt.digest());
    }

    #[test]
    fn durable_record_rejects_unreconciled_field_or_digest_changes() {
        let attempt = authorized().into_execution_attempt();

        let mut tampered = attempt.to_record();
        tampered.pset = pset();
        assert!(matches!(
            ExecutionAttempt::from_record(tampered),
            Err(ExecutionAttemptError::DigestMismatch)
        ));

        let mut tampered = attempt.to_record();
        tampered.layout.taker_payment_input = 2;
        assert!(matches!(
            ExecutionAttempt::from_record(tampered),
            Err(ExecutionAttemptError::DigestMismatch)
        ));

        let mut tampered = attempt.to_record();
        tampered.binding.quote_commitment = FixedBytes32::new([9; 32]);
        assert!(matches!(
            ExecutionAttempt::from_record(tampered),
            Err(ExecutionAttemptError::DigestMismatch)
        ));

        let mut tampered = attempt.to_record();
        tampered.digest = ExecutionAttemptDigest(FixedBytes32::new([10; 32]));
        assert!(matches!(
            ExecutionAttempt::from_record(tampered),
            Err(ExecutionAttemptError::DigestMismatch)
        ));
    }

    #[test]
    fn record_version_and_binding_timeline_are_fail_closed() {
        let attempt = authorized().into_execution_attempt();
        let mut wrong_version = attempt.to_record();
        wrong_version.version += 1;
        assert!(matches!(
            ExecutionAttempt::from_record(wrong_version),
            Err(ExecutionAttemptError::UnsupportedRecordVersion { .. })
        ));

        let mut invalid_timeline = attempt.to_record();
        invalid_timeline.binding.created_at_millis = invalid_timeline.binding.accept_before_millis;
        invalid_timeline.digest = execution_attempt_digest(
            &invalid_timeline.binding,
            &invalid_timeline.layout,
            &invalid_timeline.pset,
        );
        assert!(matches!(
            ExecutionAttempt::from_record(invalid_timeline),
            Err(ExecutionAttemptError::InvalidReservationTimeline)
        ));
    }
}
