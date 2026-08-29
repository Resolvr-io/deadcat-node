//! Taker-side trust transitions for collaborative RFQ settlement.
//!
//! A provider-blinded PSET is authenticated transport output, not signing
//! authority. The caller-owned wallet boundary must validate the complete
//! transaction and add every required taker signature before this module will
//! produce an execution attempt. The attempt retains the exact submitted
//! layout and PSET behind a versioned, self-consistency-checked durable record.

use deadcat_liquid_settlement::{
    CanonicalPset, CanonicalPsetError, P2trVerificationError, verify_treeless_p2tr_explicit_all,
};
use deadcat_rfq_rpc::{
    FirmQuoteValidationError, FixedBytes32, MAX_SETTLEMENT_BYTES, ReservationIdDto,
    SettlementLayoutDto, SettlementPset,
};
use deadcat_types::{ChainIdentity, LiquidNetwork, serde_u64_string};
use elements::encode::serialize;
use elements::hashes::Hash as _;
use elements::{AssetId, SchnorrSighashType};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::ResolvedRfqSettlement;
use crate::taker_authorization::{
    PreparedTakerAuthorization, TakerAuthorizationError, TakerSettlementPlan,
};

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
    pub(crate) fn from_settlement(settlement: &ResolvedRfqSettlement) -> Self {
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
/// the standardized local-preflight, authoritative-observation, and
/// caller-wallet authorization sequence before it can become a provider
/// execution request.
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

    #[cfg(test)]
    pub(crate) const fn from_test_parts(
        binding: ExecutionBinding,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Self {
        Self {
            binding,
            layout,
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

    /// Perform every provider-response check that does not require current
    /// chain state or a caller wallet capability.
    ///
    /// Success returns a non-forgeable continuation that owns the exact
    /// snapshot request. It may await an asynchronous authoritative source
    /// without borrowing a wallet; after the source returns, the resulting
    /// observed-state capability completes validation and signing synchronously.
    pub fn preflight_with(
        &self,
        plan: TakerSettlementPlan,
    ) -> Result<PreparedTakerAuthorization, TakerAuthorizationError> {
        PreparedTakerAuthorization::new(plan, self)
    }
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
    pub(crate) fn from_preflight(
        binding: ExecutionBinding,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Self {
        Self {
            binding,
            layout,
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
    pub(crate) fn new(
        binding: ExecutionBinding,
        layout: SettlementLayoutDto,
        pset: SettlementPset,
    ) -> Self {
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
        let expected = execution_attempt_digest(&record.binding, &record.layout, &record.pset);
        if record.digest != expected {
            return Err(ExecutionAttemptError::DigestMismatch);
        }
        record.binding.validate()?;
        record.layout.validate()?;
        let canonical = CanonicalPset::decode(record.pset.as_bytes(), MAX_SETTLEMENT_BYTES)
            .map_err(ExecutionAttemptError::InvalidPset)?;
        let pset = canonical.pset();
        let input_count = pset.inputs().len();
        let output_count = pset.outputs().len();
        if usize::from(record.layout.taker_payment_input) >= input_count
            || record
                .layout
                .provider_inputs
                .iter()
                .any(|placement| usize::from(placement.transaction_index) >= input_count)
            || record
                .layout
                .quote_outputs
                .iter()
                .any(|placement| usize::from(placement.transaction_index) >= output_count)
        {
            return Err(ExecutionAttemptError::LayoutIndexOutOfPsetBounds {
                inputs: input_count,
                outputs: output_count,
            });
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

    /// Verify the provider's returned PSET as the sole allowed extension of
    /// this exact taker-authorized attempt.
    ///
    /// Every provider input must gain one valid explicit-`SIGHASH_ALL`
    /// tree-less P2TR key-path signature and its exact one-item final witness.
    /// Clearing only those two fields must reproduce the canonical attempt
    /// byte-for-byte; globals, outputs, wallet inputs, and all other metadata
    /// are therefore immutable.
    pub fn verify_signed_result(
        &self,
        signed_pset: &SettlementPset,
    ) -> Result<VerifiedSignedExecution, SignedExecutionError> {
        let original = CanonicalPset::decode(self.pset().as_bytes(), MAX_SETTLEMENT_BYTES)?;
        let signed = CanonicalPset::decode(signed_pset.as_bytes(), MAX_SETTLEMENT_BYTES)?;
        let original_pset = original.pset();
        let mut normalized = signed.pset().clone();
        let transaction = signed
            .pset()
            .extract_tx()
            .map_err(|error| SignedExecutionError::InvalidSignedPset(error.to_string()))?;
        let prevouts = original_pset
            .inputs()
            .iter()
            .enumerate()
            .map(|(index, input)| {
                input
                    .witness_utxo
                    .clone()
                    .ok_or(SignedExecutionError::MissingWitnessUtxo { index })
            })
            .collect::<Result<Vec<_>, _>>()?;

        for placement in &self.record.layout.provider_inputs {
            let index = usize::from(placement.transaction_index);
            let original_input = original_pset.inputs().get(index).ok_or(
                SignedExecutionError::ProviderInputIndex {
                    index,
                    inputs: original_pset.inputs().len(),
                },
            )?;
            if original_input.tap_merkle_root.is_some()
                || original_input.sighash_type != Some(SchnorrSighashType::All.into())
                || original_input.tap_key_sig.is_some()
                || original_input.final_script_witness.is_some()
            {
                return Err(SignedExecutionError::InvalidOriginalProviderInput { index });
            }
            let internal_key = original_input
                .tap_internal_key
                .ok_or(SignedExecutionError::InvalidOriginalProviderInput { index })?;
            let signed_input = signed.pset().inputs().get(index).ok_or(
                SignedExecutionError::ProviderInputIndex {
                    index,
                    inputs: signed.pset().inputs().len(),
                },
            )?;
            let signature = signed_input
                .tap_key_sig
                .ok_or(SignedExecutionError::MissingProviderSignature { index })?;
            if signature.hash_ty != SchnorrSighashType::All
                || signed_input.final_script_witness.as_ref() != Some(&vec![signature.to_vec()])
            {
                return Err(SignedExecutionError::InvalidProviderFinalWitness { index });
            }
            verify_treeless_p2tr_explicit_all(
                &transaction,
                &prevouts,
                index,
                signature,
                internal_key,
                self.binding().chain().genesis_hash,
            )
            .map_err(|source| SignedExecutionError::InvalidProviderSignature { index, source })?;
            let normalized_input = normalized.inputs_mut().get_mut(index).ok_or(
                SignedExecutionError::ProviderInputIndex {
                    index,
                    inputs: signed.pset().inputs().len(),
                },
            )?;
            normalized_input.tap_key_sig = None;
            normalized_input.final_script_witness = None;
        }
        if serialize(&normalized) != self.pset().as_bytes() {
            return Err(SignedExecutionError::UnexpectedPsetMutation);
        }
        Ok(VerifiedSignedExecution(signed_pset.clone()))
    }
}

/// Provider-signed settlement proven to be the exact authorized attempt plus
/// the required provider signatures and final witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSignedExecution(SettlementPset);

impl VerifiedSignedExecution {
    #[must_use]
    pub const fn pset(&self) -> &SettlementPset {
        &self.0
    }

    #[must_use]
    pub fn into_pset(self) -> SettlementPset {
        self.0
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
    #[error("execution-attempt PSET is not canonical and sane: {0}")]
    InvalidPset(#[source] CanonicalPsetError),
    #[error(
        "execution-attempt layout references outside a PSET with {inputs} inputs and {outputs} outputs"
    )]
    LayoutIndexOutOfPsetBounds { inputs: usize, outputs: usize },
    #[error("execution-attempt digest does not match its exact payload")]
    DigestMismatch,
    #[error("execution attempt belongs to a different RFQ reservation")]
    ReservationBindingMismatch,
    #[error("execution attempt uses a different resolved settlement layout")]
    SettlementLayoutMismatch,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SignedExecutionError {
    #[error("signed execution PSET is not canonical and sane: {0}")]
    InvalidCanonicalPset(#[from] CanonicalPsetError),
    #[error("signed execution PSET cannot be extracted: {0}")]
    InvalidSignedPset(String),
    #[error("attempt input {index} is missing its bound witness UTXO")]
    MissingWitnessUtxo { index: usize },
    #[error("provider input index {index} is out of range for {inputs} inputs")]
    ProviderInputIndex { index: usize, inputs: usize },
    #[error("attempt provider input {index} is not unsigned tree-less P2TR SIGHASH_ALL")]
    InvalidOriginalProviderInput { index: usize },
    #[error("signed execution is missing provider signature at input {index}")]
    MissingProviderSignature { index: usize },
    #[error("provider input {index} does not have the exact explicit-ALL final witness")]
    InvalidProviderFinalWitness { index: usize },
    #[error("provider signature at input {index} is invalid: {source}")]
    InvalidProviderSignature {
        index: usize,
        #[source]
        source: P2trVerificationError,
    },
    #[error("provider-signed PSET changed fields outside provider signatures and final witnesses")]
    UnexpectedPsetMutation,
}

#[cfg(test)]
mod tests {
    use deadcat_rfq_rpc::{InputPlacementDto, OutputPlacementDto};
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
    use elements::schnorr::TapTweak as _;
    use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey as SecpSecretKey};
    use elements::sighash::{Prevouts, SighashCache};
    use elements::{AssetId, BlockHash, OutPoint, SchnorrSig, Script, TxOut, TxOutWitness, Txid};
    use iroh::SecretKey;

    use super::*;

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("fixture asset")
    }

    fn pset() -> SettlementPset {
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(PsetInput::from_prevout(OutPoint::new(
            Txid::from_byte_array([1; 32]),
            0,
        )));
        pset.add_input(PsetInput::from_prevout(OutPoint::new(
            Txid::from_byte_array([2; 32]),
            0,
        )));
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(50, asset(7))));
        SettlementPset::from_pset(&pset).expect("fixture PSET")
    }

    fn other_pset() -> SettlementPset {
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(PsetInput::from_prevout(OutPoint::new(
            Txid::from_byte_array([1; 32]),
            0,
        )));
        pset.add_input(PsetInput::from_prevout(OutPoint::new(
            Txid::from_byte_array([2; 32]),
            0,
        )));
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

    fn authorized() -> TakerAuthorizedSettlement {
        TakerAuthorizedSettlement::from_preflight(binding(), layout(), other_pset())
    }

    fn signed_attempt() -> (ExecutionAttempt, SettlementPset) {
        let secp = Secp256k1::new();
        let provider_keypair = Keypair::from_secret_key(
            &secp,
            &SecpSecretKey::from_slice(&[0x31; 32]).expect("provider key"),
        );
        let (provider_internal_key, _) = provider_keypair.x_only_public_key();
        let wallet_keypair = Keypair::from_secret_key(
            &secp,
            &SecpSecretKey::from_slice(&[0x32; 32]).expect("wallet key"),
        );
        let (wallet_internal_key, _) = wallet_keypair.x_only_public_key();
        let provider_prevout = TxOut {
            asset: Asset::Explicit(asset(7)),
            value: Value::Explicit(5),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(&secp, provider_internal_key, None),
            witness: TxOutWitness::default(),
        };
        let wallet_prevout = TxOut {
            asset: Asset::Explicit(asset(7)),
            value: Value::Explicit(5),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(&secp, wallet_internal_key, None),
            witness: TxOutWitness::default(),
        };
        let mut provider_input =
            PsetInput::from_prevout(OutPoint::new(Txid::from_byte_array([0x33; 32]), 0));
        provider_input.witness_utxo = Some(provider_prevout.clone());
        provider_input.tap_internal_key = Some(provider_internal_key);
        provider_input.sighash_type = Some(SchnorrSighashType::All.into());
        let mut wallet_input =
            PsetInput::from_prevout(OutPoint::new(Txid::from_byte_array([0x34; 32]), 0));
        wallet_input.witness_utxo = Some(wallet_prevout.clone());
        let mut original = PartiallySignedTransaction::new_v2();
        original.add_input(provider_input);
        original.add_input(wallet_input);
        original.add_output(PsetOutput::from_txout(TxOut::new_fee(10, asset(7))));
        let original = SettlementPset::from_pset(&original).expect("canonical original PSET");
        let layout = SettlementLayoutDto {
            taker_payment_input: 1,
            provider_inputs: vec![InputPlacementDto {
                quote_input_id: 7,
                transaction_index: 0,
            }],
            quote_outputs: vec![OutputPlacementDto {
                quote_output_id: 8,
                transaction_index: 0,
            }],
        };
        let attempt = ExecutionAttempt::new(binding(), layout, original.clone());

        let mut signed = original.to_pset().expect("decode original PSET");
        let transaction = signed.extract_tx().expect("extract transaction");
        let prevouts = [provider_prevout, wallet_prevout];
        let sighash = SighashCache::new(&transaction)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(&prevouts),
                SchnorrSighashType::All,
                binding().chain().genesis_hash,
            )
            .expect("provider sighash");
        let signature = SchnorrSig {
            sig: secp.sign_schnorr(
                &Message::from_digest(sighash.to_byte_array()),
                &provider_keypair.tap_tweak(&secp, None).to_inner(),
            ),
            hash_ty: SchnorrSighashType::All,
        };
        signed.inputs_mut()[0].tap_key_sig = Some(signature);
        signed.inputs_mut()[0].final_script_witness = Some(vec![signature.to_vec()]);
        let signed = SettlementPset::from_pset(&signed).expect("canonical signed PSET");
        (attempt, signed)
    }

    fn reorder_first_two_global_pairs(canonical: &[u8]) -> Vec<u8> {
        const HEADER_BYTES: usize = 5;
        let mut cursor = HEADER_BYTES;
        let mut pairs = Vec::new();
        while canonical[cursor] != 0 {
            let start = cursor;
            let key_length = usize::from(canonical[cursor]);
            cursor += 1 + key_length;
            let value_length = usize::from(canonical[cursor]);
            cursor += 1 + value_length;
            pairs.push(canonical[start..cursor].to_vec());
        }
        pairs.swap(0, 1);
        let mut reordered = canonical[..HEADER_BYTES].to_vec();
        for pair in pairs {
            reordered.extend(pair);
        }
        reordered.extend_from_slice(&canonical[cursor..]);
        reordered
    }

    #[test]
    fn authorized_capability_is_required_for_execution() {
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
    fn recovered_attempt_requires_a_canonical_sane_pset() {
        let attempt = authorized().into_execution_attempt();
        let reordered = reorder_first_two_global_pairs(attempt.pset().as_bytes());
        let mut record = attempt.to_record();
        record.pset = SettlementPset::from_bytes(reordered).expect("decodable reordered PSET");
        record.digest = execution_attempt_digest(&record.binding, &record.layout, &record.pset);
        assert!(matches!(
            ExecutionAttempt::from_record(record),
            Err(ExecutionAttemptError::InvalidPset(
                CanonicalPsetError::NonCanonicalEncoding
            ))
        ));
    }

    #[test]
    fn signed_result_allows_only_verified_provider_signature_fields() {
        let (attempt, signed) = signed_attempt();
        let verified = attempt
            .verify_signed_result(&signed)
            .expect("exact provider signature extension");
        assert_eq!(verified.pset(), &signed);

        let mut missing = signed.to_pset().expect("signed PSET");
        missing.inputs_mut()[0].tap_key_sig = None;
        let missing = SettlementPset::from_pset(&missing).expect("canonical mutation");
        assert!(matches!(
            attempt.verify_signed_result(&missing),
            Err(SignedExecutionError::MissingProviderSignature { index: 0 })
        ));

        let mut wallet_metadata = signed.to_pset().expect("signed PSET");
        wallet_metadata.inputs_mut()[1].sighash_type = Some(SchnorrSighashType::Single.into());
        let wallet_metadata =
            SettlementPset::from_pset(&wallet_metadata).expect("canonical mutation");
        assert!(matches!(
            attempt.verify_signed_result(&wallet_metadata),
            Err(SignedExecutionError::UnexpectedPsetMutation)
        ));

        let mut wrong_witness = signed.to_pset().expect("signed PSET");
        wrong_witness.inputs_mut()[0].final_script_witness = Some(vec![vec![0x01]]);
        let wrong_witness = SettlementPset::from_pset(&wrong_witness).expect("canonical mutation");
        assert!(matches!(
            attempt.verify_signed_result(&wrong_witness),
            Err(SignedExecutionError::InvalidProviderFinalWitness { index: 0 })
        ));
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

        let mut out_of_range = attempt.to_record();
        out_of_range.layout.provider_inputs[0].transaction_index = 2;
        out_of_range.digest = execution_attempt_digest(
            &out_of_range.binding,
            &out_of_range.layout,
            &out_of_range.pset,
        );
        assert!(matches!(
            ExecutionAttempt::from_record(out_of_range),
            Err(ExecutionAttemptError::LayoutIndexOutOfPsetBounds {
                inputs: 2,
                outputs: 1
            })
        ));
    }
}
