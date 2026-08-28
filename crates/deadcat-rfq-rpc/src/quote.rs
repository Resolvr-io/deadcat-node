use std::collections::BTreeSet;

use deadcat_types::{ContractId, LiquidNetwork, serde_u64_string};
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::{PublicKey, RangeProof, SurjectionProof};
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut, TxOutWitness};
use iroh::{EndpointId, SecretKey, Signature};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::codec::{FixedBytes32, FixedBytes33, FixedBytes64, bytes_hex, option_bytes_hex};
use crate::{ALPN, SCHEMA_VERSION};

/// Protocol resource bounds. Runtime/domain adapters must reject any stricter
/// provider limit before doing expensive settlement work.
pub const MAX_SETTLEMENT_BYTES: usize = 1_000_000;
pub const MAX_SETTLEMENT_INPUTS: usize = 32;
pub const MAX_SETTLEMENT_OUTPUTS: usize = 32;
pub const MAX_RECIPIENT_SCRIPT_BYTES: usize = 10_000;

const OWNER_ID_DOMAIN: &[u8] = b"deadcat/rfq/owner-id/v1";
const QUOTE_ATTESTATION_DOMAIN: &[u8] = b"deadcat/rfq/network-firm-quote/v1";
const SIGNED_ARTIFACT_DOMAIN: &[u8] = b"deadcat/rfq/signed-artifact/v1";

pub type IdempotencyKeyDto = FixedBytes32;
pub type ReservationIdDto = FixedBytes32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteContextDto {
    pub network: LiquidNetwork,
    pub genesis_hash: BlockHash,
    pub market: ContractId,
    pub policy_asset: AssetId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetAmountDto {
    pub asset: AssetId,
    #[serde(with = "serde_u64_string")]
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteRecipientDto {
    #[serde(with = "bytes_hex")]
    pub script_pubkey: Vec<u8>,
    pub blinding_public_key: FixedBytes33,
}

impl QuoteRecipientDto {
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        let script = Script::from(self.script_pubkey.clone());
        if script.is_empty()
            || script.is_provably_unspendable()
            || script.len() > MAX_RECIPIENT_SCRIPT_BYTES
        {
            return Err(FirmQuoteValidationError::InvalidRecipient);
        }
        PublicKey::from_slice(&self.blinding_public_key.to_bytes())
            .map_err(|_| FirmQuoteValidationError::InvalidBlindingKey)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QuoteKindDto {
    ExactIn {
        input: AssetAmountDto,
        output_asset: AssetId,
        #[serde(with = "serde_u64_string")]
        minimum_output: u64,
    },
    ExactOut {
        input_asset: AssetId,
        #[serde(with = "serde_u64_string")]
        maximum_input: u64,
        output: AssetAmountDto,
    },
}

impl QuoteKindDto {
    fn validate(self) -> Result<(), FirmQuoteValidationError> {
        let (input, input_amount, output, output_amount) = match self {
            Self::ExactIn {
                input,
                output_asset,
                minimum_output,
            } => (input.asset, input.amount, output_asset, minimum_output),
            Self::ExactOut {
                input_asset,
                maximum_input,
                output,
            } => (input_asset, maximum_input, output.asset, output.amount),
        };
        if input == output {
            return Err(FirmQuoteValidationError::SameAssetPair);
        }
        if input_amount == 0 || output_amount == 0 {
            return Err(FirmQuoteValidationError::ZeroAmount);
        }
        Ok(())
    }

    fn pair(self) -> (AssetId, AssetId) {
        match self {
            Self::ExactIn {
                input,
                output_asset,
                ..
            } => (input.asset, output_asset),
            Self::ExactOut {
                input_asset,
                output,
                ..
            } => (input_asset, output.asset),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmQuoteRequestDto {
    pub context: QuoteContextDto,
    pub kind: QuoteKindDto,
    pub recipient: QuoteRecipientDto,
    #[serde(with = "serde_u64_string")]
    pub maximum_input_asset_venue_fee: u64,
}

impl FirmQuoteRequestDto {
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        let market = self.context.market.creation_anchor();
        if market.is_null() || market.vout & 0xc000_0000 != 0 {
            return Err(FirmQuoteValidationError::InvalidMarket);
        }
        self.kind.validate()?;
        self.recipient.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteExecutionDto {
    pub input: AssetAmountDto,
    pub output: AssetAmountDto,
    #[serde(with = "serde_u64_string")]
    pub input_asset_venue_fee: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RationalRateDto {
    #[serde(with = "serde_u64_string")]
    pub numerator: u64,
    #[serde(with = "serde_u64_string")]
    pub denominator: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PricingDecisionDto {
    pub rate: RationalRateDto,
    #[serde(with = "serde_u64_string")]
    pub input_asset_venue_fee: u64,
    pub policy_id: FixedBytes32,
    #[serde(with = "serde_u64_string")]
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BlinderRoleDto {
    TakerPaymentInput,
    ProviderInput { quote_input_id: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteOutputRoleDto {
    ProviderPayment,
    TakerReceive,
    ProviderChange,
}

/// Consensus `TxOut` base fields plus both confidential proof witnesses.
/// Elements consensus encoding omits the `TxOutWitness`, so carrying only the
/// base bytes would silently lose the rangeproof needed by settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TxOutDto {
    #[serde(with = "bytes_hex")]
    pub base: Vec<u8>,
    #[serde(default, with = "option_bytes_hex")]
    pub surjection_proof: Option<Vec<u8>>,
    #[serde(default, with = "option_bytes_hex")]
    pub rangeproof: Option<Vec<u8>>,
}

impl TxOutDto {
    #[must_use]
    pub fn from_txout(txout: &TxOut) -> Self {
        Self {
            base: serialize(txout),
            surjection_proof: txout
                .witness
                .surjection_proof
                .as_deref()
                .map(SurjectionProof::serialize),
            rangeproof: txout
                .witness
                .rangeproof
                .as_deref()
                .map(RangeProof::serialize),
        }
    }

    pub fn to_txout(&self) -> Result<TxOut, FirmQuoteValidationError> {
        let total = self
            .base
            .len()
            .checked_add(self.surjection_proof.as_ref().map_or(0, Vec::len))
            .and_then(|length| length.checked_add(self.rangeproof.as_ref().map_or(0, Vec::len)))
            .ok_or(FirmQuoteValidationError::TxOutTooLarge)?;
        if total > MAX_SETTLEMENT_BYTES {
            return Err(FirmQuoteValidationError::TxOutTooLarge);
        }
        let mut txout =
            deserialize::<TxOut>(&self.base).map_err(|_| FirmQuoteValidationError::InvalidTxOut)?;
        txout.witness = TxOutWitness {
            surjection_proof: self
                .surjection_proof
                .as_deref()
                .map(|proof| SurjectionProof::from_slice(proof).map(Box::new))
                .transpose()
                .map_err(|_| FirmQuoteValidationError::InvalidSurjectionProof)?,
            rangeproof: self
                .rangeproof
                .as_deref()
                .map(|proof| RangeProof::from_slice(proof).map(Box::new))
                .transpose()
                .map_err(|_| FirmQuoteValidationError::InvalidRangeproof)?,
        };
        Ok(txout)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteInputDto {
    pub id: u16,
    pub outpoint: OutPoint,
    pub witness_utxo: TxOutDto,
    pub inventory_binding: FixedBytes32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteOutputDto {
    pub id: u16,
    pub role: QuoteOutputRoleDto,
    pub asset: AssetId,
    #[serde(with = "serde_u64_string")]
    pub amount: u64,
    pub destination: QuoteRecipientDto,
    pub blinder: BlinderRoleDto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEvidenceDto {
    pub block_hash: BlockHash,
    pub block_height: u32,
    pub snapshot_commitment: FixedBytes32,
    #[serde(with = "serde_u64_string")]
    pub allocation_revision: u64,
    pub eligible_commitment: FixedBytes32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeeSizeMetricDto {
    RegularVbytes,
    DiscountVbytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeePolicyDto {
    pub policy_asset: AssetId,
    #[serde(with = "serde_u64_string")]
    pub minimum_sats_per_kvb: u64,
    #[serde(with = "serde_u64_string")]
    pub minimum_absolute_fee: u64,
    #[serde(with = "serde_u64_string")]
    pub maximum_transaction_weight: u64,
    pub size_metric: FeeSizeMetricDto,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirmQuoteDto {
    pub reservation_id: ReservationIdDto,
    /// Must equal the stable Iroh endpoint signing this quote.
    pub provider_endpoint: FixedBytes32,
    pub network: LiquidNetwork,
    pub genesis_hash: BlockHash,
    pub policy_asset: AssetId,
    pub request: FirmQuoteRequestDto,
    pub execution: QuoteExecutionDto,
    pub pricing: PricingDecisionDto,
    pub snapshot: SnapshotEvidenceDto,
    pub inputs: Vec<QuoteInputDto>,
    pub outputs: Vec<QuoteOutputDto>,
    #[serde(with = "serde_u64_string")]
    pub created_at_millis: u64,
    #[serde(with = "serde_u64_string")]
    pub accept_before_millis: u64,
    pub fee_policy: FeePolicyDto,
    pub recovery_metadata_commitment: FixedBytes32,
    pub quote_commitment: FixedBytes32,
}

impl FirmQuoteDto {
    pub fn validate_structure(&self) -> Result<(), FirmQuoteValidationError> {
        self.request.validate()?;
        if self.network != self.request.context.network
            || self.genesis_hash != self.request.context.genesis_hash
            || self.policy_asset != self.request.context.policy_asset
            || self.fee_policy.policy_asset != self.policy_asset
        {
            return Err(FirmQuoteValidationError::ContextMismatch);
        }
        if self.created_at_millis >= self.accept_before_millis {
            return Err(FirmQuoteValidationError::InvalidValidityWindow);
        }
        if self.fee_policy.minimum_sats_per_kvb == 0
            || self.fee_policy.maximum_transaction_weight == 0
        {
            return Err(FirmQuoteValidationError::InvalidFeePolicy);
        }
        let pair = self.request.kind.pair();
        if self.execution.input.asset != pair.0
            || self.execution.output.asset != pair.1
            || self.execution.input.amount == 0
            || self.execution.output.amount == 0
            || self.execution.input_asset_venue_fee != self.pricing.input_asset_venue_fee
            || self.execution.input_asset_venue_fee > self.request.maximum_input_asset_venue_fee
        {
            return Err(FirmQuoteValidationError::ExecutionMismatch);
        }
        match self.request.kind {
            QuoteKindDto::ExactIn {
                input,
                minimum_output,
                ..
            } if self.execution.input != input || self.execution.output.amount < minimum_output => {
                return Err(FirmQuoteValidationError::ExecutionMismatch);
            }
            QuoteKindDto::ExactOut {
                maximum_input,
                output,
                ..
            } if self.execution.output != output || self.execution.input.amount > maximum_input => {
                return Err(FirmQuoteValidationError::ExecutionMismatch);
            }
            _ => {}
        }
        if self.pricing.rate.numerator == 0
            || self.pricing.rate.denominator == 0
            || gcd(self.pricing.rate.numerator, self.pricing.rate.denominator) != 1
        {
            return Err(FirmQuoteValidationError::InvalidRate);
        }
        let fee = self.execution.input_asset_venue_fee;
        let expected = match self.request.kind {
            QuoteKindDto::ExactIn { .. } => {
                let priced_input = self
                    .execution
                    .input
                    .amount
                    .checked_sub(fee)
                    .filter(|amount| *amount != 0)
                    .ok_or(FirmQuoteValidationError::ExecutionMismatch)?;
                u128::from(priced_input)
                    .checked_mul(u128::from(self.pricing.rate.numerator))
                    .ok_or(FirmQuoteValidationError::ExecutionMismatch)?
                    / u128::from(self.pricing.rate.denominator)
            }
            QuoteKindDto::ExactOut { .. } => {
                let numerator = u128::from(self.execution.output.amount)
                    .checked_mul(u128::from(self.pricing.rate.denominator))
                    .ok_or(FirmQuoteValidationError::ExecutionMismatch)?;
                let divisor = u128::from(self.pricing.rate.numerator);
                let priced_input = numerator
                    .checked_add(divisor - 1)
                    .ok_or(FirmQuoteValidationError::ExecutionMismatch)?
                    / divisor;
                priced_input
                    .checked_add(u128::from(fee))
                    .ok_or(FirmQuoteValidationError::ExecutionMismatch)?
            }
        };
        let actual = match self.request.kind {
            QuoteKindDto::ExactIn { .. } => u128::from(self.execution.output.amount),
            QuoteKindDto::ExactOut { .. } => u128::from(self.execution.input.amount),
        };
        if expected == 0 || expected != actual {
            return Err(FirmQuoteValidationError::ExecutionMismatch);
        }
        if self.inputs.is_empty() || self.inputs.len() > MAX_SETTLEMENT_INPUTS {
            return Err(FirmQuoteValidationError::InvalidInputCount);
        }
        if self.outputs.len() < 2 || self.outputs.len() > MAX_SETTLEMENT_OUTPUTS {
            return Err(FirmQuoteValidationError::InvalidOutputCount);
        }
        let mut input_ids = BTreeSet::new();
        let mut outpoints = BTreeSet::new();
        for input in &self.inputs {
            if !input_ids.insert(input.id)
                || !outpoints.insert(input.outpoint)
                || input.outpoint.is_null()
                || input.outpoint.vout & 0xc000_0000 != 0
            {
                return Err(FirmQuoteValidationError::InvalidInput);
            }
            let prevout = input.witness_utxo.to_txout()?;
            if !prevout.asset.is_confidential()
                || !prevout.value.is_confidential()
                || !prevout.nonce.is_confidential()
            {
                return Err(FirmQuoteValidationError::NonConfidentialProviderPrevout);
            }
            if prevout.witness.surjection_proof.is_none() {
                return Err(FirmQuoteValidationError::MissingProviderSurjectionProof);
            }
            let rangeproof = prevout
                .witness
                .rangeproof
                .as_deref()
                .ok_or(FirmQuoteValidationError::MissingProviderRangeproof)?;
            if !prevout.script_pubkey.is_v1_p2tr() {
                return Err(FirmQuoteValidationError::NonP2trProviderPrevout);
            }
            let value_commitment = prevout
                .value
                .commitment()
                .ok_or(FirmQuoteValidationError::NonConfidentialProviderPrevout)?;
            let asset_generator = prevout
                .asset
                .commitment()
                .ok_or(FirmQuoteValidationError::NonConfidentialProviderPrevout)?;
            rangeproof
                .verify(
                    &elements::secp256k1_zkp::Secp256k1::new(),
                    value_commitment,
                    prevout.script_pubkey.as_bytes(),
                    asset_generator,
                )
                .map_err(|_| FirmQuoteValidationError::InvalidProviderRangeproof)?;
        }
        let mut output_ids = BTreeSet::new();
        let mut provider_payment = 0;
        let mut taker_receive = 0;
        let mut provider_change = 0;
        for output in &self.outputs {
            if !output_ids.insert(output.id) || output.amount == 0 {
                return Err(FirmQuoteValidationError::InvalidOutput);
            }
            output.destination.validate()?;
            match output.role {
                QuoteOutputRoleDto::ProviderPayment => {
                    provider_payment += 1;
                    if output.asset != self.execution.input.asset
                        || output.amount != self.execution.input.amount
                        || output.blinder != BlinderRoleDto::TakerPaymentInput
                    {
                        return Err(FirmQuoteValidationError::ExecutionMismatch);
                    }
                }
                QuoteOutputRoleDto::TakerReceive => {
                    taker_receive += 1;
                    if output.asset != self.execution.output.asset
                        || output.amount != self.execution.output.amount
                        || output.destination != self.request.recipient
                    {
                        return Err(FirmQuoteValidationError::ExecutionMismatch);
                    }
                    if matches!(output.blinder, BlinderRoleDto::TakerPaymentInput) {
                        return Err(FirmQuoteValidationError::InvalidOutputBlinder);
                    }
                }
                QuoteOutputRoleDto::ProviderChange => {
                    provider_change += 1;
                    if output.asset != self.execution.output.asset {
                        return Err(FirmQuoteValidationError::ExecutionMismatch);
                    }
                    if matches!(output.blinder, BlinderRoleDto::TakerPaymentInput) {
                        return Err(FirmQuoteValidationError::InvalidOutputBlinder);
                    }
                }
            }
            if let BlinderRoleDto::ProviderInput { quote_input_id } = output.blinder
                && !input_ids.contains(&quote_input_id)
            {
                return Err(FirmQuoteValidationError::UnknownBlinderInput);
            }
        }
        if provider_payment != 1 || taker_receive != 1 || provider_change > 1 {
            return Err(FirmQuoteValidationError::InvalidOutputRoles);
        }
        Ok(())
    }
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputPlacementDto {
    pub quote_input_id: u16,
    pub transaction_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPlacementDto {
    pub quote_output_id: u16,
    pub transaction_index: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementLayoutDto {
    pub taker_payment_input: u16,
    pub provider_inputs: Vec<InputPlacementDto>,
    pub quote_outputs: Vec<OutputPlacementDto>,
}

impl SettlementLayoutDto {
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        if self.provider_inputs.is_empty()
            || self.provider_inputs.len() > MAX_SETTLEMENT_INPUTS
            || self.quote_outputs.is_empty()
            || self.quote_outputs.len() > MAX_SETTLEMENT_OUTPUTS
        {
            return Err(FirmQuoteValidationError::InvalidLayoutSize);
        }
        if usize::from(self.taker_payment_input) >= MAX_SETTLEMENT_INPUTS {
            return Err(FirmQuoteValidationError::InvalidLayoutIndex);
        }
        let mut quote_inputs = BTreeSet::new();
        let mut transaction_inputs = BTreeSet::from([self.taker_payment_input]);
        for placement in &self.provider_inputs {
            if usize::from(placement.transaction_index) >= MAX_SETTLEMENT_INPUTS {
                return Err(FirmQuoteValidationError::InvalidLayoutIndex);
            }
            if !quote_inputs.insert(placement.quote_input_id)
                || !transaction_inputs.insert(placement.transaction_index)
            {
                return Err(FirmQuoteValidationError::AliasedLayoutInput);
            }
        }
        let mut quote_outputs = BTreeSet::new();
        let mut transaction_outputs = BTreeSet::new();
        for placement in &self.quote_outputs {
            if usize::from(placement.transaction_index) >= MAX_SETTLEMENT_OUTPUTS {
                return Err(FirmQuoteValidationError::InvalidLayoutIndex);
            }
            if !quote_outputs.insert(placement.quote_output_id)
                || !transaction_outputs.insert(placement.transaction_index)
            {
                return Err(FirmQuoteValidationError::AliasedLayoutOutput);
            }
        }
        Ok(())
    }

    pub fn validate_for_quote(&self, quote: &FirmQuoteDto) -> Result<(), FirmQuoteValidationError> {
        self.validate()?;
        let expected_inputs = quote
            .inputs
            .iter()
            .map(|input| input.id)
            .collect::<BTreeSet<_>>();
        let actual_inputs = self
            .provider_inputs
            .iter()
            .map(|input| input.quote_input_id)
            .collect::<BTreeSet<_>>();
        let expected_outputs = quote
            .outputs
            .iter()
            .map(|output| output.id)
            .collect::<BTreeSet<_>>();
        let actual_outputs = self
            .quote_outputs
            .iter()
            .map(|output| output.quote_output_id)
            .collect::<BTreeSet<_>>();
        if expected_inputs != actual_inputs || expected_outputs != actual_outputs {
            return Err(FirmQuoteValidationError::IncompleteLayout);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementPset(Vec<u8>);

impl SettlementPset {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, PsetError> {
        if bytes.is_empty() || bytes.len() > MAX_SETTLEMENT_BYTES {
            return Err(PsetError::InvalidLength);
        }
        deserialize::<PartiallySignedTransaction>(&bytes).map_err(|_| PsetError::InvalidPset)?;
        Ok(Self(bytes))
    }

    pub fn from_pset(pset: &PartiallySignedTransaction) -> Result<Self, PsetError> {
        Self::from_bytes(serialize(pset))
    }

    pub fn to_pset(&self) -> Result<PartiallySignedTransaction, PsetError> {
        deserialize(&self.0).map_err(|_| PsetError::InvalidPset)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for SettlementPset {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(&self.0))
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for SettlementPset {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            if value.len() > MAX_SETTLEMENT_BYTES * 2
                || value.len() % 2 != 0
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(D::Error::custom(
                    "PSET must be bounded canonical lowercase hex",
                ));
            }
            hex::decode(value).map_err(D::Error::custom)?
        } else {
            Vec::<u8>::deserialize(deserializer)?
        };
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReasonDto {
    Expired,
    ClientCancelled,
    ProviderRejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReservationStateDto {
    Reserved,
    Released {
        reason: ReleaseReasonDto,
        #[serde(with = "serde_u64_string")]
        at_millis: u64,
    },
    Committed {
        signing_commitment: FixedBytes32,
        #[serde(with = "serde_u64_string")]
        committed_at_millis: u64,
    },
    Signed {
        signing_commitment: FixedBytes32,
        artifact_digest: FixedBytes32,
        #[serde(with = "serde_u64_string")]
        committed_at_millis: u64,
        #[serde(with = "serde_u64_string")]
        signed_at_millis: u64,
        signed_pset: SettlementPset,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservationStatusDto {
    pub reservation_id: ReservationIdDto,
    pub quote_commitment: FixedBytes32,
    #[serde(with = "serde_u64_string")]
    pub created_at_millis: u64,
    #[serde(with = "serde_u64_string")]
    pub accept_before_millis: u64,
    pub state: ReservationStateDto,
}

impl ReservationStatusDto {
    pub fn validate(&self) -> Result<(), FirmQuoteValidationError> {
        if self.created_at_millis >= self.accept_before_millis {
            return Err(FirmQuoteValidationError::InvalidValidityWindow);
        }
        match &self.state {
            ReservationStateDto::Reserved => {}
            ReservationStateDto::Released { reason, at_millis } => {
                let release_window_invalid = match reason {
                    ReleaseReasonDto::Expired => *at_millis < self.accept_before_millis,
                    ReleaseReasonDto::ClientCancelled | ReleaseReasonDto::ProviderRejected => {
                        *at_millis >= self.accept_before_millis
                    }
                };
                if *at_millis < self.created_at_millis || release_window_invalid {
                    return Err(FirmQuoteValidationError::InvalidStatusTimeline);
                }
            }
            ReservationStateDto::Committed {
                committed_at_millis,
                ..
            } if *committed_at_millis < self.created_at_millis
                || *committed_at_millis >= self.accept_before_millis =>
            {
                return Err(FirmQuoteValidationError::InvalidStatusTimeline);
            }
            ReservationStateDto::Signed {
                committed_at_millis,
                signed_at_millis,
                ..
            } if *committed_at_millis < self.created_at_millis
                || *committed_at_millis >= self.accept_before_millis
                || *signed_at_millis < *committed_at_millis =>
            {
                return Err(FirmQuoteValidationError::InvalidStatusTimeline);
            }
            _ => {}
        }
        if let ReservationStateDto::Signed {
            signing_commitment,
            artifact_digest,
            signed_pset,
            ..
        } = &self.state
        {
            let bytes = signed_pset.as_bytes();
            let mut hasher = Sha256::new();
            hasher.update(SIGNED_ARTIFACT_DOMAIN);
            hasher.update(signing_commitment.to_bytes());
            hasher.update(
                u64::try_from(bytes.len())
                    .map_err(|_| FirmQuoteValidationError::ArtifactDigestMismatch)?
                    .to_be_bytes(),
            );
            hasher.update(bytes);
            let expected = FixedBytes32::new(hasher.finalize().into());
            if *artifact_digest != expected {
                return Err(FirmQuoteValidationError::ArtifactDigestMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteAttestation {
    pub provider_endpoint: FixedBytes32,
    pub client_endpoint: FixedBytes32,
    pub idempotency_key: IdempotencyKeyDto,
    pub signature: FixedBytes64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFirmQuote {
    pub quote: FirmQuoteDto,
    pub attestation: QuoteAttestation,
}

#[derive(Serialize)]
struct QuoteAttestationTranscript<'a> {
    schema_version: u32,
    alpn: &'a [u8],
    provider_endpoint: [u8; 32],
    client_endpoint: [u8; 32],
    idempotency_key: [u8; 32],
    quote: CanonicalFirmQuoteV1,
}

/// Frozen primitive-only normalization. Adding a field to the JSON DTO cannot
/// silently change an existing attestation: protocol evolution must explicitly
/// change this encoder and its domain/version.
#[derive(Serialize)]
struct CanonicalFirmQuoteV1 {
    fields: Vec<u8>,
}

struct CanonicalWriter(Vec<u8>);

impl CanonicalWriter {
    fn bytes(&mut self, value: &[u8]) -> Result<(), AttestationError> {
        self.u64(u64::try_from(value.len()).map_err(|_| AttestationError::TranscriptEncoding)?);
        self.0.extend_from_slice(value);
        Ok(())
    }

    fn fixed(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }

    fn option_bytes(&mut self, value: Option<&[u8]>) -> Result<(), AttestationError> {
        match value {
            Some(value) => {
                self.u8(1);
                self.bytes(value)
            }
            None => {
                self.u8(0);
                Ok(())
            }
        }
    }
}

fn canonical_quote(quote: &FirmQuoteDto) -> Result<CanonicalFirmQuoteV1, AttestationError> {
    fn asset(writer: &mut CanonicalWriter, value: AssetId) {
        writer.fixed(&value.into_inner().to_byte_array());
    }
    fn outpoint(writer: &mut CanonicalWriter, value: OutPoint) {
        writer.fixed(&value.txid.to_byte_array());
        writer.u32(value.vout);
    }
    fn recipient(
        writer: &mut CanonicalWriter,
        value: &QuoteRecipientDto,
    ) -> Result<(), AttestationError> {
        writer.bytes(&value.script_pubkey)?;
        writer.fixed(&value.blinding_public_key.to_bytes());
        Ok(())
    }
    fn network(value: LiquidNetwork) -> u8 {
        match value {
            LiquidNetwork::Liquid => 0,
            LiquidNetwork::LiquidTestnet => 1,
            LiquidNetwork::ElementsRegtest => 2,
        }
    }

    let mut writer = CanonicalWriter(Vec::new());
    writer.fixed(&quote.reservation_id.to_bytes());
    writer.fixed(&quote.provider_endpoint.to_bytes());
    writer.u8(network(quote.network));
    writer.fixed(&quote.genesis_hash.to_byte_array());
    asset(&mut writer, quote.policy_asset);
    writer.u8(network(quote.request.context.network));
    writer.fixed(&quote.request.context.genesis_hash.to_byte_array());
    outpoint(&mut writer, quote.request.context.market.creation_anchor());
    asset(&mut writer, quote.request.context.policy_asset);
    match quote.request.kind {
        QuoteKindDto::ExactIn {
            input,
            output_asset,
            minimum_output,
        } => {
            writer.u8(0);
            asset(&mut writer, input.asset);
            writer.u64(input.amount);
            asset(&mut writer, output_asset);
            writer.u64(minimum_output);
        }
        QuoteKindDto::ExactOut {
            input_asset,
            maximum_input,
            output,
        } => {
            writer.u8(1);
            asset(&mut writer, input_asset);
            writer.u64(maximum_input);
            asset(&mut writer, output.asset);
            writer.u64(output.amount);
        }
    }
    recipient(&mut writer, &quote.request.recipient)?;
    writer.u64(quote.request.maximum_input_asset_venue_fee);
    asset(&mut writer, quote.execution.input.asset);
    writer.u64(quote.execution.input.amount);
    asset(&mut writer, quote.execution.output.asset);
    writer.u64(quote.execution.output.amount);
    writer.u64(quote.execution.input_asset_venue_fee);
    writer.u64(quote.pricing.rate.numerator);
    writer.u64(quote.pricing.rate.denominator);
    writer.u64(quote.pricing.input_asset_venue_fee);
    writer.fixed(&quote.pricing.policy_id.to_bytes());
    writer.u64(quote.pricing.revision);
    writer.fixed(&quote.snapshot.block_hash.to_byte_array());
    writer.u32(quote.snapshot.block_height);
    writer.fixed(&quote.snapshot.snapshot_commitment.to_bytes());
    writer.u64(quote.snapshot.allocation_revision);
    writer.fixed(&quote.snapshot.eligible_commitment.to_bytes());
    writer
        .u64(u64::try_from(quote.inputs.len()).map_err(|_| AttestationError::TranscriptEncoding)?);
    for input in &quote.inputs {
        writer.u16(input.id);
        outpoint(&mut writer, input.outpoint);
        writer.bytes(&input.witness_utxo.base)?;
        writer.option_bytes(input.witness_utxo.surjection_proof.as_deref())?;
        writer.option_bytes(input.witness_utxo.rangeproof.as_deref())?;
        writer.fixed(&input.inventory_binding.to_bytes());
    }
    writer
        .u64(u64::try_from(quote.outputs.len()).map_err(|_| AttestationError::TranscriptEncoding)?);
    for output in &quote.outputs {
        writer.u16(output.id);
        writer.u8(match output.role {
            QuoteOutputRoleDto::ProviderPayment => 0,
            QuoteOutputRoleDto::TakerReceive => 1,
            QuoteOutputRoleDto::ProviderChange => 2,
        });
        asset(&mut writer, output.asset);
        writer.u64(output.amount);
        recipient(&mut writer, &output.destination)?;
        match output.blinder {
            BlinderRoleDto::TakerPaymentInput => writer.u8(0),
            BlinderRoleDto::ProviderInput { quote_input_id } => {
                writer.u8(1);
                writer.u16(quote_input_id);
            }
        }
    }
    writer.u64(quote.created_at_millis);
    writer.u64(quote.accept_before_millis);
    asset(&mut writer, quote.fee_policy.policy_asset);
    writer.u64(quote.fee_policy.minimum_sats_per_kvb);
    writer.u64(quote.fee_policy.minimum_absolute_fee);
    writer.u64(quote.fee_policy.maximum_transaction_weight);
    writer.u8(match quote.fee_policy.size_metric {
        FeeSizeMetricDto::RegularVbytes => 0,
        FeeSizeMetricDto::DiscountVbytes => 1,
    });
    writer.fixed(&quote.recovery_metadata_commitment.to_bytes());
    writer.fixed(&quote.quote_commitment.to_bytes());
    Ok(CanonicalFirmQuoteV1 { fields: writer.0 })
}

fn attestation_digest(
    quote: &FirmQuoteDto,
    provider_endpoint: FixedBytes32,
    client_endpoint: FixedBytes32,
    idempotency_key: IdempotencyKeyDto,
) -> Result<[u8; 32], AttestationError> {
    let transcript = postcard::to_allocvec(&QuoteAttestationTranscript {
        schema_version: SCHEMA_VERSION,
        alpn: ALPN,
        provider_endpoint: provider_endpoint.to_bytes(),
        client_endpoint: client_endpoint.to_bytes(),
        idempotency_key: idempotency_key.to_bytes(),
        quote: canonical_quote(quote)?,
    })
    .map_err(|_| AttestationError::TranscriptEncoding)?;
    let mut digest = Sha256::new();
    digest.update(QUOTE_ATTESTATION_DOMAIN);
    digest.update(
        u64::try_from(transcript.len())
            .map_err(|_| AttestationError::TranscriptEncoding)?
            .to_be_bytes(),
    );
    digest.update(transcript);
    Ok(digest.finalize().into())
}

impl SignedFirmQuote {
    pub fn sign(
        quote: FirmQuoteDto,
        provider_key: &SecretKey,
        client_endpoint: EndpointId,
        idempotency_key: IdempotencyKeyDto,
    ) -> Result<Self, AttestationError> {
        quote.validate_structure()?;
        let provider_endpoint = FixedBytes32::new(*provider_key.public().as_bytes());
        if quote.provider_endpoint != provider_endpoint {
            return Err(AttestationError::ProviderIdentityMismatch);
        }
        let client_endpoint = FixedBytes32::new(*client_endpoint.as_bytes());
        let digest =
            attestation_digest(&quote, provider_endpoint, client_endpoint, idempotency_key)?;
        let signature = provider_key.sign(&digest);
        Ok(Self {
            quote,
            attestation: QuoteAttestation {
                provider_endpoint,
                client_endpoint,
                idempotency_key,
                signature: FixedBytes64::new(signature.to_bytes()),
            },
        })
    }

    /// Authenticate this retained quote without making a claim about whether
    /// its acceptance window is still open.
    ///
    /// This is the appropriate verification step for durable recovery: an
    /// expired quote must remain independently attributable to the pinned
    /// provider and bound to the authenticated client, idempotency key, and
    /// original request. Call [`VerifiedFirmQuote::live_at`] immediately
    /// before using the quote to construct or authorize a new settlement.
    pub fn verify(
        self,
        pinned_provider: EndpointId,
        authenticated_client: EndpointId,
        idempotency_key: IdempotencyKeyDto,
        requested: &FirmQuoteRequestDto,
    ) -> Result<VerifiedFirmQuote, AttestationError> {
        self.quote.validate_structure()?;
        let provider = FixedBytes32::new(*pinned_provider.as_bytes());
        let client = FixedBytes32::new(*authenticated_client.as_bytes());
        if self.quote.provider_endpoint != provider
            || self.attestation.provider_endpoint != provider
            || self.attestation.client_endpoint != client
            || self.attestation.idempotency_key != idempotency_key
        {
            return Err(AttestationError::ContextMismatch);
        }
        if &self.quote.request != requested {
            return Err(AttestationError::RequestMismatch);
        }
        let digest = attestation_digest(&self.quote, provider, client, idempotency_key)?;
        let signature = Signature::from_bytes(&self.attestation.signature.to_bytes());
        pinned_provider
            .verify(&digest, &signature)
            .map_err(|_| AttestationError::InvalidSignature)?;
        Ok(VerifiedFirmQuote(self))
    }

    /// Authenticate the retained quote and prove its acceptance window is
    /// still open at the caller's trusted wall time.
    ///
    /// This convenience method preserves the original `verify_at` flow while
    /// returning the distinct capability settlement code should require.
    pub fn verify_at(
        self,
        pinned_provider: EndpointId,
        authenticated_client: EndpointId,
        idempotency_key: IdempotencyKeyDto,
        requested: &FirmQuoteRequestDto,
        now_millis: u64,
    ) -> Result<LiveFirmQuote, AttestationError> {
        let verified = self.verify(
            pinned_provider,
            authenticated_client,
            idempotency_key,
            requested,
        )?;
        verified.live_at(now_millis)
    }
}

/// Capability produced only after provider pin, authenticated client context,
/// request equality, structural checks and signature verification all pass.
/// It is intentionally not deserializable or directly constructible. This
/// capability proves identity, request binding and structure even after the
/// quote expires, but does not prove current liveness. Settlement callers must
/// first obtain a [`LiveFirmQuote`] through [`Self::live_at`].
#[derive(Clone, Debug)]
pub struct VerifiedFirmQuote(SignedFirmQuote);

impl VerifiedFirmQuote {
    #[must_use]
    pub const fn signed(&self) -> &SignedFirmQuote {
        &self.0
    }

    #[must_use]
    pub const fn quote(&self) -> &FirmQuoteDto {
        &self.0.quote
    }

    /// Prove this authenticated quote is still live at the caller's trusted
    /// wall time.
    pub fn live_at(&self, now_millis: u64) -> Result<LiveFirmQuote, AttestationError> {
        if now_millis >= self.quote().accept_before_millis {
            return Err(AttestationError::Expired);
        }
        Ok(LiveFirmQuote {
            verified: self.clone(),
            checked_at_millis: now_millis,
        })
    }
}

/// Settlement capability proving a firm quote was authenticated and its
/// acceptance window was open at `checked_at_millis`.
///
/// It is intentionally not deserializable or directly constructible. Code
/// beginning or authorizing settlement should require this type rather than a
/// [`SignedFirmQuote`] or [`VerifiedFirmQuote`], and should create it using a
/// fresh trusted wall-clock reading immediately before that work.
#[derive(Clone, Debug)]
pub struct LiveFirmQuote {
    verified: VerifiedFirmQuote,
    checked_at_millis: u64,
}

impl LiveFirmQuote {
    #[must_use]
    pub const fn verified(&self) -> &VerifiedFirmQuote {
        &self.verified
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFirmQuote {
        self.verified.signed()
    }

    #[must_use]
    pub const fn quote(&self) -> &FirmQuoteDto {
        self.verified.quote()
    }

    /// Trusted wall time at which the acceptance-window check was performed.
    #[must_use]
    pub const fn checked_at_millis(&self) -> u64 {
        self.checked_at_millis
    }

    /// Discard the liveness claim while retaining authenticated recovery
    /// evidence.
    #[must_use]
    pub fn into_verified(self) -> VerifiedFirmQuote {
        self.verified
    }
}

#[must_use]
pub fn owner_id_from_endpoints(
    provider_endpoint: EndpointId,
    client_endpoint: EndpointId,
) -> FixedBytes32 {
    let mut digest = Sha256::new();
    digest.update(OWNER_ID_DOMAIN);
    digest.update(provider_endpoint.as_bytes());
    digest.update(client_endpoint.as_bytes());
    FixedBytes32::new(digest.finalize().into())
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum PsetError {
    #[error("settlement PSET must be nonempty and no larger than {MAX_SETTLEMENT_BYTES} bytes")]
    InvalidLength,
    #[error("invalid PSET encoding")]
    InvalidPset,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum FirmQuoteValidationError {
    #[error("invalid market outpoint")]
    InvalidMarket,
    #[error("trade assets must be distinct")]
    SameAssetPair,
    #[error("trade amounts must be nonzero")]
    ZeroAmount,
    #[error("invalid confidential recipient")]
    InvalidRecipient,
    #[error("invalid recipient blinding public key")]
    InvalidBlindingKey,
    #[error("quote chain or policy context mismatch")]
    ContextMismatch,
    #[error("invalid quote validity window")]
    InvalidValidityWindow,
    #[error("invalid fee policy")]
    InvalidFeePolicy,
    #[error("execution does not satisfy the request or contribution")]
    ExecutionMismatch,
    #[error("invalid normalized rational rate")]
    InvalidRate,
    #[error("invalid provider input count")]
    InvalidInputCount,
    #[error("invalid quote output count")]
    InvalidOutputCount,
    #[error("invalid or duplicate provider input")]
    InvalidInput,
    #[error("invalid or duplicate quote output")]
    InvalidOutput,
    #[error("invalid quote output roles")]
    InvalidOutputRoles,
    #[error("quote output refers to an unknown provider blinder input")]
    UnknownBlinderInput,
    #[error("provider-funded output must use a provider input blinder")]
    InvalidOutputBlinder,
    #[error("serialized TxOut exceeds the settlement bound")]
    TxOutTooLarge,
    #[error("invalid TxOut base encoding")]
    InvalidTxOut,
    #[error("invalid surjection proof")]
    InvalidSurjectionProof,
    #[error("invalid rangeproof")]
    InvalidRangeproof,
    #[error("provider prevout asset, value, and nonce must all be confidential")]
    NonConfidentialProviderPrevout,
    #[error("provider prevout is missing its surjection proof")]
    MissingProviderSurjectionProof,
    #[error("provider prevout is missing its rangeproof")]
    MissingProviderRangeproof,
    #[error("provider prevout must use a v1 P2TR script")]
    NonP2trProviderPrevout,
    #[error("provider prevout rangeproof does not verify against its commitments and script")]
    InvalidProviderRangeproof,
    #[error("invalid settlement layout size")]
    InvalidLayoutSize,
    #[error("settlement placement index exceeds the v1 resource limit")]
    InvalidLayoutIndex,
    #[error("settlement input placement aliases or repeats an input")]
    AliasedLayoutInput,
    #[error("settlement output placement aliases or repeats an output")]
    AliasedLayoutOutput,
    #[error("settlement layout does not cover every quote object exactly once")]
    IncompleteLayout,
    #[error("signed settlement bytes do not match their durable artifact digest")]
    ArtifactDigestMismatch,
    #[error("firm quote provider does not match its attestation signer")]
    ProviderAttestationMismatch,
    #[error("firm quote and reservation status describe different durable records")]
    QuoteStatusMismatch,
    #[error("cancellation response did not release the reservation by cancellation or expiry")]
    InvalidCancellationState,
    #[error("execution response did not commit or sign the reservation")]
    InvalidExecutionState,
    #[error("reservation status timestamps are not monotonic or violate the acceptance window")]
    InvalidStatusTimeline,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("firm quote is structurally invalid: {0}")]
    InvalidQuote(#[from] FirmQuoteValidationError),
    #[error("provider endpoint does not match the signing identity")]
    ProviderIdentityMismatch,
    #[error("attestation endpoint or idempotency context mismatch")]
    ContextMismatch,
    #[error("attested quote does not match the requested terms")]
    RequestMismatch,
    #[error("could not encode canonical quote attestation transcript")]
    TranscriptEncoding,
    #[error("invalid provider quote signature")]
    InvalidSignature,
    #[error("firm quote acceptance window has elapsed")]
    Expired,
}

#[cfg(test)]
mod tests {
    use deadcat_types::ContractId;
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{Keypair, Secp256k1, SecretKey as SecpSecretKey};
    use elements::{RangeProofMessage, TxOut, TxOutSecrets, Txid};
    use rand::SeedableRng as _;
    use rand::rngs::StdRng;

    use super::*;
    use crate::{Request, Response};

    fn asset(marker: u8) -> AssetId {
        AssetId::from_slice(&[marker; 32]).expect("asset")
    }

    fn outpoint(marker: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([marker; 32]), vout)
    }

    fn recipient(marker: u8) -> QuoteRecipientDto {
        let secret = SecpSecretKey::from_slice(&[marker; 32]).expect("secret");
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        QuoteRecipientDto {
            script_pubkey: vec![0x51, marker],
            blinding_public_key: FixedBytes33::new(public.serialize()),
        }
    }

    fn confidential_p2tr_txout(asset: AssetId, amount: u64) -> TxOut {
        let secp = Secp256k1::new();
        let spend_secret = SecpSecretKey::from_slice(&[101; 32]).expect("spend secret");
        let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
        let (internal_key, _) = spend_keypair.x_only_public_key();
        let blinding_secret = SecpSecretKey::from_slice(&[102; 32]).expect("blinding secret");
        let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(&secp, internal_key, None),
            witness: TxOutWitness::empty(),
        };
        let mut rng = StdRng::from_seed([103; 32]);
        explicit
            .to_non_last_confidential(
                &mut rng,
                &secp,
                blinding_public_key,
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

    fn quote(provider: EndpointId) -> FirmQuoteDto {
        let input_asset = asset(1);
        let output_asset = asset(2);
        let taker = recipient(3);
        let provider_recipient = recipient(4);
        let genesis = BlockHash::from_byte_array([9; 32]);
        let request = FirmQuoteRequestDto {
            context: QuoteContextDto {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: genesis,
                market: ContractId::new(outpoint(5, 0)),
                policy_asset: input_asset,
            },
            kind: QuoteKindDto::ExactIn {
                input: AssetAmountDto {
                    asset: input_asset,
                    amount: 100,
                },
                output_asset,
                minimum_output: 170,
            },
            recipient: taker.clone(),
            maximum_input_asset_venue_fee: 10,
        };
        FirmQuoteDto {
            reservation_id: FixedBytes32::new([6; 32]),
            provider_endpoint: FixedBytes32::new(*provider.as_bytes()),
            network: LiquidNetwork::ElementsRegtest,
            genesis_hash: genesis,
            policy_asset: input_asset,
            request,
            execution: QuoteExecutionDto {
                input: AssetAmountDto {
                    asset: input_asset,
                    amount: 100,
                },
                output: AssetAmountDto {
                    asset: output_asset,
                    amount: 180,
                },
                input_asset_venue_fee: 10,
            },
            pricing: PricingDecisionDto {
                rate: RationalRateDto {
                    numerator: 2,
                    denominator: 1,
                },
                input_asset_venue_fee: 10,
                policy_id: FixedBytes32::new([7; 32]),
                revision: 1,
            },
            snapshot: SnapshotEvidenceDto {
                block_hash: BlockHash::from_byte_array([8; 32]),
                block_height: 10,
                snapshot_commitment: FixedBytes32::new([9; 32]),
                allocation_revision: 2,
                eligible_commitment: FixedBytes32::new([10; 32]),
            },
            inputs: vec![QuoteInputDto {
                id: 1,
                outpoint: outpoint(11, 0),
                witness_utxo: TxOutDto::from_txout(&confidential_p2tr_txout(output_asset, 200)),
                inventory_binding: FixedBytes32::new([12; 32]),
            }],
            outputs: vec![
                QuoteOutputDto {
                    id: 1,
                    role: QuoteOutputRoleDto::ProviderPayment,
                    asset: input_asset,
                    amount: 100,
                    destination: provider_recipient.clone(),
                    blinder: BlinderRoleDto::TakerPaymentInput,
                },
                QuoteOutputDto {
                    id: 2,
                    role: QuoteOutputRoleDto::TakerReceive,
                    asset: output_asset,
                    amount: 180,
                    destination: taker,
                    blinder: BlinderRoleDto::ProviderInput { quote_input_id: 1 },
                },
                QuoteOutputDto {
                    id: 3,
                    role: QuoteOutputRoleDto::ProviderChange,
                    asset: output_asset,
                    amount: 20,
                    destination: provider_recipient,
                    blinder: BlinderRoleDto::ProviderInput { quote_input_id: 1 },
                },
            ],
            created_at_millis: 1_000,
            accept_before_millis: 31_000,
            fee_policy: FeePolicyDto {
                policy_asset: input_asset,
                minimum_sats_per_kvb: 100,
                minimum_absolute_fee: 10,
                maximum_transaction_weight: 100_000,
                size_metric: FeeSizeMetricDto::DiscountVbytes,
            },
            recovery_metadata_commitment: FixedBytes32::new([13; 32]),
            quote_commitment: FixedBytes32::new([14; 32]),
        }
    }

    #[test]
    fn fixed_key_attestation_rejects_tampering_and_wrong_context() {
        let provider_key = SecretKey::from_bytes(&[21; 32]);
        let client_key = SecretKey::from_bytes(&[22; 32]);
        let wrong_client = SecretKey::from_bytes(&[23; 32]);
        let idempotency = FixedBytes32::new([24; 32]);
        let request = quote(provider_key.public()).request;
        let signed = SignedFirmQuote::sign(
            quote(provider_key.public()),
            &provider_key,
            client_key.public(),
            idempotency,
        )
        .expect("sign");
        assert_eq!(
            hex::encode(signed.attestation.signature.to_bytes()),
            "9f7255b6022ba758f6fd90038b4d0f7fadff6aa3de8dd26decc990650f51883ba55033bf383ca08d97115290fe3aef2fcc6a6de09f760534458a38ce8b00750f"
        );
        assert!(
            signed
                .clone()
                .verify_at(
                    provider_key.public(),
                    client_key.public(),
                    idempotency,
                    &request,
                    30_999,
                )
                .is_ok()
        );
        assert_eq!(
            signed
                .clone()
                .verify_at(
                    provider_key.public(),
                    wrong_client.public(),
                    idempotency,
                    &request,
                    2_000,
                )
                .expect_err("wrong client"),
            AttestationError::ContextMismatch
        );
        assert_eq!(
            signed
                .clone()
                .verify_at(
                    SecretKey::from_bytes(&[25; 32]).public(),
                    client_key.public(),
                    idempotency,
                    &request,
                    2_000,
                )
                .expect_err("wrong provider"),
            AttestationError::ContextMismatch
        );
        assert_eq!(
            signed
                .clone()
                .verify_at(
                    provider_key.public(),
                    client_key.public(),
                    FixedBytes32::new([26; 32]),
                    &request,
                    2_000,
                )
                .expect_err("wrong idempotency key"),
            AttestationError::ContextMismatch
        );
        let mut changed_request = request.clone();
        changed_request.maximum_input_asset_venue_fee += 1;
        assert_eq!(
            signed
                .clone()
                .verify_at(
                    provider_key.public(),
                    client_key.public(),
                    idempotency,
                    &changed_request,
                    2_000,
                )
                .expect_err("changed request"),
            AttestationError::RequestMismatch
        );
        assert_eq!(
            signed
                .clone()
                .verify_at(
                    provider_key.public(),
                    client_key.public(),
                    idempotency,
                    &request,
                    31_000,
                )
                .expect_err("expired"),
            AttestationError::Expired
        );
        let mut tampered = signed;
        tampered.quote.accept_before_millis += 1;
        assert_eq!(
            tampered
                .verify_at(
                    provider_key.public(),
                    client_key.public(),
                    idempotency,
                    &request,
                    2_000,
                )
                .expect_err("tampered"),
            AttestationError::InvalidSignature
        );
    }

    #[test]
    fn authenticity_survives_expiry_but_live_capability_does_not() {
        let provider_key = SecretKey::from_bytes(&[41; 32]);
        let client_key = SecretKey::from_bytes(&[42; 32]);
        let idempotency = FixedBytes32::new([43; 32]);
        let quote = quote(provider_key.public());
        let request = quote.request.clone();
        let accept_before = quote.accept_before_millis;
        let signed = SignedFirmQuote::sign(quote, &provider_key, client_key.public(), idempotency)
            .expect("sign");

        // Authentication is deliberately independent of wall time so this
        // retained artifact remains useful for recovery after expiry.
        let verified = signed
            .clone()
            .verify(
                provider_key.public(),
                client_key.public(),
                idempotency,
                &request,
            )
            .expect("authenticate expired retained quote");
        assert_eq!(verified.quote().accept_before_millis, accept_before);
        assert_eq!(
            verified
                .live_at(accept_before)
                .expect_err("expiry boundary is not live"),
            AttestationError::Expired
        );
        // Recovery code can retain the authenticated artifact independently
        // of a settlement capability.
        assert_eq!(verified.quote().request, request);

        let checked_at = accept_before - 1;
        let live = verified
            .live_at(checked_at)
            .expect("quote is live before boundary");
        assert_eq!(live.checked_at_millis(), checked_at);
        assert_eq!(live.quote(), verified.quote());
        assert_eq!(live.signed(), verified.signed());
        assert_eq!(live.verified().quote(), verified.quote());
        assert_eq!(live.into_verified().quote(), verified.quote());

        // The original convenience API now produces the same settlement-only
        // capability while retaining its established boundary behavior.
        let live = signed
            .verify_at(
                provider_key.public(),
                client_key.public(),
                idempotency,
                &request,
                checked_at,
            )
            .expect("authenticate and check liveness");
        assert_eq!(live.checked_at_millis(), checked_at);
    }

    #[test]
    fn owner_ids_are_scoped_to_both_endpoints() {
        let provider = SecretKey::from_bytes(&[31; 32]).public();
        let other_provider = SecretKey::from_bytes(&[32; 32]).public();
        let client = SecretKey::from_bytes(&[33; 32]).public();
        assert_ne!(
            owner_id_from_endpoints(provider, client),
            owner_id_from_endpoints(other_provider, client)
        );
    }

    #[test]
    fn dto_json_is_strict_and_uses_canonical_strings() {
        let provider = SecretKey::from_bytes(&[41; 32]).public();
        let encoded = serde_json::to_string(&quote(provider).request).expect("encode");
        assert!(encoded.contains("\"amount\":\"100\""));
        assert!(serde_json::from_str::<FirmQuoteRequestDto>(&encoded).is_ok());
        let extra = encoded.replacen('{', "{\"extra\":0,", 1);
        assert!(serde_json::from_str::<FirmQuoteRequestDto>(&extra).is_err());
        let numeric = encoded.replacen("\"100\"", "100", 1);
        assert!(serde_json::from_str::<FirmQuoteRequestDto>(&numeric).is_err());
        let fixed = serde_json::to_string(&FixedBytes32::new([0xab; 32])).expect("fixed");
        assert!(serde_json::from_str::<FixedBytes32>(&fixed.to_uppercase()).is_err());
    }

    #[test]
    fn txout_roundtrip_preserves_rangeproof_witness() {
        let asset_id = asset(51);
        let script = Script::from(vec![0x51]);
        let secp = Secp256k1::new();
        let abf = AssetBlindingFactor::from_slice(&[1; 32]).expect("abf");
        let vbf = ValueBlindingFactor::from_slice(&[2; 32]).expect("vbf");
        let rewind = SecpSecretKey::from_slice(&[3; 32]).expect("rewind");
        let message = RangeProofMessage {
            asset: asset_id,
            bf: abf,
        };
        let (value, proof) = Value::Explicit(42)
            .blind_with_shared_secret(&secp, vbf, rewind, &script, &message)
            .expect("rangeproof");
        let txout = TxOut {
            asset: Asset::Explicit(asset_id),
            value,
            nonce: Nonce::Null,
            script_pubkey: script,
            witness: TxOutWitness {
                surjection_proof: None,
                rangeproof: Some(Box::new(proof)),
            },
        };
        let dto = TxOutDto::from_txout(&txout);
        let json = serde_json::to_string(&dto).expect("encode");
        let decoded: TxOutDto = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded.to_txout().expect("txout"), txout);
    }

    #[test]
    fn pset_hex_is_canonical_bounded_and_checked() {
        let pset =
            SettlementPset::from_pset(&PartiallySignedTransaction::new_v2()).expect("valid PSET");
        let json = serde_json::to_string(&pset).expect("encode");
        assert!(serde_json::from_str::<SettlementPset>(&json).is_ok());
        assert!(serde_json::from_str::<SettlementPset>(&json.to_uppercase()).is_err());
        let oversized = format!("\"{}\"", "00".repeat(MAX_SETTLEMENT_BYTES + 1));
        assert!(serde_json::from_str::<SettlementPset>(&oversized).is_err());
        assert_eq!(
            SettlementPset::from_bytes(vec![1, 2, 3]),
            Err(PsetError::InvalidPset)
        );
    }

    #[test]
    fn layout_is_injective_and_complete_for_quote() {
        let provider = SecretKey::from_bytes(&[61; 32]).public();
        let quote = quote(provider);
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
                OutputPlacementDto {
                    quote_output_id: 3,
                    transaction_index: 2,
                },
            ],
        };
        assert!(layout.validate_for_quote(&quote).is_ok());
        let mut aliased = layout.clone();
        aliased.provider_inputs[0].transaction_index = 0;
        assert_eq!(
            aliased.validate().expect_err("alias"),
            FirmQuoteValidationError::AliasedLayoutInput
        );
        let mut incomplete = layout;
        incomplete.quote_outputs.pop();
        assert_eq!(
            incomplete
                .validate_for_quote(&quote)
                .expect_err("incomplete"),
            FirmQuoteValidationError::IncompleteLayout
        );
    }

    #[test]
    fn structure_checks_rate_and_blinder_semantics() {
        let provider = SecretKey::from_bytes(&[71; 32]).public();
        let mut value = quote(provider);
        assert!(value.validate_structure().is_ok());
        value.execution.output.amount += 1;
        assert_eq!(
            value.validate_structure().expect_err("rounding"),
            FirmQuoteValidationError::ExecutionMismatch
        );
        let mut value = quote(provider);
        value.outputs[1].blinder = BlinderRoleDto::TakerPaymentInput;
        assert_eq!(
            value.validate_structure().expect_err("blinder"),
            FirmQuoteValidationError::InvalidOutputBlinder
        );
    }

    #[test]
    fn provider_prevouts_require_the_confidential_p2tr_proof_profile() {
        let provider = SecretKey::from_bytes(&[72; 32]).public();
        let valid = quote(provider);
        assert!(valid.validate_structure().is_ok());

        let mut explicit = valid.clone();
        let mut prevout = explicit.inputs[0]
            .witness_utxo
            .to_txout()
            .expect("fixture prevout");
        prevout.asset = Asset::Explicit(valid.execution.output.asset);
        explicit.inputs[0].witness_utxo = TxOutDto::from_txout(&prevout);
        assert_eq!(
            explicit.validate_structure().expect_err("explicit asset"),
            FirmQuoteValidationError::NonConfidentialProviderPrevout
        );

        let mut missing_surjection = valid.clone();
        missing_surjection.inputs[0].witness_utxo.surjection_proof = None;
        assert_eq!(
            missing_surjection
                .validate_structure()
                .expect_err("missing surjection proof"),
            FirmQuoteValidationError::MissingProviderSurjectionProof
        );

        let mut missing_rangeproof = valid.clone();
        missing_rangeproof.inputs[0].witness_utxo.rangeproof = None;
        assert_eq!(
            missing_rangeproof
                .validate_structure()
                .expect_err("missing rangeproof"),
            FirmQuoteValidationError::MissingProviderRangeproof
        );

        let mut non_p2tr = valid.clone();
        let mut prevout = non_p2tr.inputs[0]
            .witness_utxo
            .to_txout()
            .expect("fixture prevout");
        prevout.script_pubkey = Script::from(vec![0x51]);
        non_p2tr.inputs[0].witness_utxo = TxOutDto::from_txout(&prevout);
        assert_eq!(
            non_p2tr.validate_structure().expect_err("non-P2TR"),
            FirmQuoteValidationError::NonP2trProviderPrevout
        );

        let mut wrong_p2tr = valid;
        let mut prevout = wrong_p2tr.inputs[0]
            .witness_utxo
            .to_txout()
            .expect("fixture prevout");
        let secp = Secp256k1::new();
        let replacement_secret = SecpSecretKey::from_slice(&[104; 32]).expect("replacement key");
        let replacement_pair = Keypair::from_secret_key(&secp, &replacement_secret);
        prevout.script_pubkey =
            Script::new_v1_p2tr(&secp, replacement_pair.x_only_public_key().0, None);
        wrong_p2tr.inputs[0].witness_utxo = TxOutDto::from_txout(&prevout);
        assert_eq!(
            wrong_p2tr
                .validate_structure()
                .expect_err("rangeproof script binding"),
            FirmQuoteValidationError::InvalidProviderRangeproof
        );
    }

    #[test]
    fn signed_status_recomputes_the_provider_artifact_digest() {
        let pset =
            SettlementPset::from_pset(&PartiallySignedTransaction::new_v2()).expect("valid PSET");
        let signing_commitment = FixedBytes32::new([81; 32]);
        let mut hasher = Sha256::new();
        hasher.update(SIGNED_ARTIFACT_DOMAIN);
        hasher.update(signing_commitment.to_bytes());
        hasher.update((pset.as_bytes().len() as u64).to_be_bytes());
        hasher.update(pset.as_bytes());
        let artifact_digest = FixedBytes32::new(hasher.finalize().into());
        let status = ReservationStatusDto {
            reservation_id: FixedBytes32::new([82; 32]),
            quote_commitment: FixedBytes32::new([83; 32]),
            created_at_millis: 1_000,
            accept_before_millis: 2_000,
            state: ReservationStateDto::Signed {
                signing_commitment,
                artifact_digest,
                committed_at_millis: 1_500,
                signed_at_millis: 1_600,
                signed_pset: pset,
            },
        };
        assert!(status.validate().is_ok());
        let mut tampered = status.clone();
        let ReservationStateDto::Signed {
            artifact_digest, ..
        } = &mut tampered.state
        else {
            unreachable!("signed fixture")
        };
        *artifact_digest = FixedBytes32::new([84; 32]);
        assert_eq!(
            tampered.validate().expect_err("digest mismatch"),
            FirmQuoteValidationError::ArtifactDigestMismatch
        );
        let mut invalid_time = status;
        let ReservationStateDto::Signed {
            signed_at_millis, ..
        } = &mut invalid_time.state
        else {
            unreachable!("signed fixture")
        };
        *signed_at_millis = 1_499;
        assert_eq!(
            invalid_time.validate().expect_err("time regression"),
            FirmQuoteValidationError::InvalidStatusTimeline
        );
    }

    #[test]
    fn released_status_enforces_reason_specific_acceptance_window() {
        let status = |reason, at_millis| ReservationStatusDto {
            reservation_id: FixedBytes32::new([85; 32]),
            quote_commitment: FixedBytes32::new([86; 32]),
            created_at_millis: 1_000,
            accept_before_millis: 2_000,
            state: ReservationStateDto::Released { reason, at_millis },
        };

        assert!(status(ReleaseReasonDto::Expired, 2_000).validate().is_ok());
        assert_eq!(
            status(ReleaseReasonDto::Expired, 1_999)
                .validate()
                .expect_err("early expiry"),
            FirmQuoteValidationError::InvalidStatusTimeline
        );
        assert!(
            status(ReleaseReasonDto::ClientCancelled, 1_999)
                .validate()
                .is_ok()
        );
        assert_eq!(
            status(ReleaseReasonDto::ClientCancelled, 2_000)
                .validate()
                .expect_err("late cancellation"),
            FirmQuoteValidationError::InvalidStatusTimeline
        );
        assert_eq!(
            status(ReleaseReasonDto::ProviderRejected, 2_000)
                .validate()
                .expect_err("late provider rejection"),
            FirmQuoteValidationError::InvalidStatusTimeline
        );
        assert_eq!(
            status(ReleaseReasonDto::ProviderRejected, 999)
                .validate()
                .expect_err("release before creation"),
            FirmQuoteValidationError::InvalidStatusTimeline
        );
    }

    #[test]
    fn cancellation_response_requires_a_cancelled_or_expired_release() {
        let status = |state| ReservationStatusDto {
            reservation_id: FixedBytes32::new([87; 32]),
            quote_commitment: FixedBytes32::new([88; 32]),
            created_at_millis: 1_000,
            accept_before_millis: 2_000,
            state,
        };

        for state in [
            ReservationStateDto::Released {
                reason: ReleaseReasonDto::ClientCancelled,
                at_millis: 1_500,
            },
            ReservationStateDto::Released {
                reason: ReleaseReasonDto::Expired,
                at_millis: 2_000,
            },
        ] {
            assert!(
                Response::ReservationCancelled {
                    status: status(state)
                }
                .validate()
                .is_ok()
            );
        }

        for state in [
            ReservationStateDto::Reserved,
            ReservationStateDto::Released {
                reason: ReleaseReasonDto::ProviderRejected,
                at_millis: 1_500,
            },
            ReservationStateDto::Committed {
                signing_commitment: FixedBytes32::new([89; 32]),
                committed_at_millis: 1_500,
            },
        ] {
            assert_eq!(
                Response::ReservationCancelled {
                    status: status(state)
                }
                .validate()
                .expect_err("method-specific cancellation state"),
                FirmQuoteValidationError::InvalidCancellationState
            );
        }
    }

    #[test]
    fn execution_response_requires_a_committed_or_signed_reservation() {
        let status = |state| ReservationStatusDto {
            reservation_id: FixedBytes32::new([90; 32]),
            quote_commitment: FixedBytes32::new([91; 32]),
            created_at_millis: 1_000,
            accept_before_millis: 2_000,
            state,
        };
        assert!(
            Response::ExecutionAccepted {
                status: status(ReservationStateDto::Committed {
                    signing_commitment: FixedBytes32::new([92; 32]),
                    committed_at_millis: 1_500,
                })
            }
            .validate()
            .is_ok()
        );

        let pset =
            SettlementPset::from_pset(&PartiallySignedTransaction::new_v2()).expect("valid PSET");
        let signing_commitment = FixedBytes32::new([93; 32]);
        let mut hasher = Sha256::new();
        hasher.update(SIGNED_ARTIFACT_DOMAIN);
        hasher.update(signing_commitment.to_bytes());
        hasher.update((pset.as_bytes().len() as u64).to_be_bytes());
        hasher.update(pset.as_bytes());
        let artifact_digest = FixedBytes32::new(hasher.finalize().into());
        assert!(
            Response::ExecutionAccepted {
                status: status(ReservationStateDto::Signed {
                    signing_commitment,
                    artifact_digest,
                    committed_at_millis: 1_500,
                    signed_at_millis: 1_600,
                    signed_pset: pset,
                })
            }
            .validate()
            .is_ok()
        );

        for state in [
            ReservationStateDto::Reserved,
            ReservationStateDto::Released {
                reason: ReleaseReasonDto::ClientCancelled,
                at_millis: 1_500,
            },
        ] {
            assert_eq!(
                Response::ExecutionAccepted {
                    status: status(state)
                }
                .validate()
                .expect_err("method-specific execution state"),
                FirmQuoteValidationError::InvalidExecutionState
            );
        }
    }

    #[test]
    fn top_level_semantic_hooks_reject_inconsistent_payloads() {
        let provider_key = SecretKey::from_bytes(&[91; 32]);
        let client = SecretKey::from_bytes(&[92; 32]).public();
        let idempotency = FixedBytes32::new([93; 32]);
        let quote = quote(provider_key.public());
        assert!(
            Request::RequestFirmQuote {
                idempotency_key: idempotency,
                request: quote.request.clone(),
            }
            .validate()
            .is_ok()
        );
        let signed =
            SignedFirmQuote::sign(quote.clone(), &provider_key, client, idempotency).expect("sign");
        let status = ReservationStatusDto {
            reservation_id: quote.reservation_id,
            quote_commitment: quote.quote_commitment,
            created_at_millis: quote.created_at_millis,
            accept_before_millis: quote.accept_before_millis,
            state: ReservationStateDto::Reserved,
        };
        let response = Response::FirmQuote {
            quote: signed,
            status,
        };
        assert!(response.validate().is_ok());
        let Response::FirmQuote { mut quote, status } = response else {
            unreachable!("firm quote fixture")
        };
        quote.attestation.provider_endpoint = FixedBytes32::new([94; 32]);
        assert_eq!(
            Response::FirmQuote { quote, status }
                .validate()
                .expect_err("attestation provider mismatch"),
            FirmQuoteValidationError::ProviderAttestationMismatch
        );
    }
}
