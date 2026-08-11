use core::fmt;

use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, OutPoint};
use thiserror::Error;

/// Maximum number of provider inventory inputs one reservation may claim.
pub const MAX_RESERVATION_INPUTS: usize = 64;
/// Maximum exact pre-sign or signed settlement retained for recovery.
pub const MAX_SETTLEMENT_BYTES: usize = 1_000_000;

macro_rules! fixed_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }
        }
    };
}

fixed_id!(
    /// Stable identity of one independently operated RFQ provider.
    ProviderId
);
fixed_id!(
    /// Authenticated reservation owner, normally derived from a transport principal.
    OwnerId
);
fixed_id!(
    /// Client-chosen retry key. Reusing it with different terms is rejected.
    IdempotencyKey
);
fixed_id!(
    /// Provider-issued identifier for one durable reservation.
    ReservationId
);
fixed_id!(
    /// Commitment to the exact authenticated quote and leg economics.
    QuoteCommitment
);
fixed_id!(
    /// Domain-separated commitment to the exact durable pre-sign transcript.
    SigningCommitment
);
fixed_id!(
    /// Domain-separated commitment to the exact persisted signed response.
    SignedArtifactDigest
);
fixed_id!(
    /// Commitment to the wallet-authenticated public and durable metadata for one output.
    InventoryBinding
);

/// Stable, non-secret handle used by the provider wallet or HSM to recover a key.
///
/// The bytes are deliberately opaque to the state machine. They must not be a
/// private key, blinding factor, seed, or derivation path containing secrets.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WalletKeyLocator([u8; 32]);

impl WalletKeyLocator {
    pub fn new(bytes: [u8; 32]) -> Result<Self, ModelError> {
        if bytes == [0; 32] {
            return Err(ModelError::InvalidWalletKeyLocator);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for WalletKeyLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WalletKeyLocator([opaque])")
    }
}

/// Absolute Unix time in milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixMillis(u64);

impl UnixMillis {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Time source sampled exactly once after the durable writer is acquired.
///
/// Implementations used by the service should return wall-clock Unix time.
/// Tests may pass a [`UnixMillis`] directly as a fixed clock.
pub trait Clock {
    fn now(&self) -> UnixMillis;
}

impl Clock for UnixMillis {
    fn now(&self) -> UnixMillis {
        *self
    }
}

/// Immutable identity binding for one provider database.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderIdentity {
    provider: ProviderId,
    genesis_hash: BlockHash,
    policy_asset: AssetId,
}

impl ProviderIdentity {
    #[must_use]
    pub const fn new(provider: ProviderId, genesis_hash: BlockHash, policy_asset: AssetId) -> Self {
        Self {
            provider,
            genesis_hash,
            policy_asset,
        }
    }

    #[must_use]
    pub const fn provider(self) -> ProviderId {
        self.provider
    }

    #[must_use]
    pub const fn genesis_hash(self) -> BlockHash {
        self.genesis_hash
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }
}

/// Provider-owned spendable output metadata. Wallet secrets live elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryItem {
    outpoint: OutPoint,
    asset: AssetId,
    amount: u64,
    wallet_locator: WalletKeyLocator,
    internal_key: XOnlyPublicKey,
    binding: InventoryBinding,
}

impl InventoryItem {
    pub(crate) fn new(
        outpoint: OutPoint,
        asset: AssetId,
        amount: u64,
        wallet_locator: WalletKeyLocator,
        internal_key: XOnlyPublicKey,
        binding: InventoryBinding,
    ) -> Result<Self, ModelError> {
        if outpoint.is_null() || outpoint.vout & 0xc000_0000 != 0 {
            return Err(ModelError::InvalidInventoryOutpoint(outpoint));
        }
        if amount == 0 {
            return Err(ModelError::ZeroInventoryAmount);
        }
        Ok(Self {
            outpoint,
            asset,
            amount,
            wallet_locator,
            internal_key,
            binding,
        })
    }

    #[must_use]
    pub const fn outpoint(self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn asset(self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(self) -> u64 {
        self.amount
    }

    /// Opaque, non-secret handle required to recover the provider signing key.
    #[must_use]
    pub const fn wallet_locator(self) -> WalletKeyLocator {
        self.wallet_locator
    }

    /// Untweaked key committed by the tree-less P2TR output.
    #[must_use]
    pub const fn internal_key(self) -> XOnlyPublicKey {
        self.internal_key
    }

    /// Commitment to the wallet-authenticated public prevout and durable metadata.
    #[must_use]
    pub const fn binding(self) -> InventoryBinding {
        self.binding
    }
}

/// Transaction size measure used by the provider's broadcasting node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeSizeMetric {
    RegularVbytes,
    DiscountVbytes,
}

/// Immutable fee and resource floor attached to a firm reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    policy_asset: AssetId,
    minimum_sats_per_kvb: u64,
    minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
    size_metric: FeeSizeMetric,
}

impl FeePolicy {
    pub fn new(
        policy_asset: AssetId,
        minimum_sats_per_kvb: u64,
        minimum_absolute_fee: u64,
        maximum_transaction_weight: u64,
        size_metric: FeeSizeMetric,
    ) -> Result<Self, ModelError> {
        if minimum_sats_per_kvb == 0 {
            return Err(ModelError::ZeroMinimumFeeRate);
        }
        if maximum_transaction_weight == 0 {
            return Err(ModelError::ZeroMaximumTransactionWeight);
        }
        Ok(Self {
            policy_asset,
            minimum_sats_per_kvb,
            minimum_absolute_fee,
            maximum_transaction_weight,
            size_metric,
        })
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }

    #[must_use]
    pub const fn minimum_sats_per_kvb(self) -> u64 {
        self.minimum_sats_per_kvb
    }

    #[must_use]
    pub const fn minimum_absolute_fee(self) -> u64 {
        self.minimum_absolute_fee
    }

    #[must_use]
    pub const fn maximum_transaction_weight(self) -> u64 {
        self.maximum_transaction_weight
    }

    #[must_use]
    pub const fn size_metric(self) -> FeeSizeMetric {
        self.size_metric
    }

    pub fn required_fee(self, transaction: TransactionFee) -> Result<u64, FeePolicyViolation> {
        if transaction.policy_asset != self.policy_asset {
            return Err(FeePolicyViolation::WrongPolicyAsset {
                expected: self.policy_asset,
                actual: transaction.policy_asset,
            });
        }
        if transaction.weight > self.maximum_transaction_weight {
            return Err(FeePolicyViolation::TransactionOverweight {
                maximum: self.maximum_transaction_weight,
                actual: transaction.weight,
            });
        }
        let policy_vsize = match self.size_metric {
            FeeSizeMetric::RegularVbytes => transaction.regular_vsize,
            FeeSizeMetric::DiscountVbytes => transaction.discount_vsize,
        };
        let numerator = u128::from(self.minimum_sats_per_kvb)
            .checked_mul(u128::from(policy_vsize))
            .ok_or(FeePolicyViolation::RequiredFeeOverflow)?;
        let rate_fee = numerator
            .checked_add(999)
            .ok_or(FeePolicyViolation::RequiredFeeOverflow)?
            / 1_000;
        let rate_fee =
            u64::try_from(rate_fee).map_err(|_| FeePolicyViolation::RequiredFeeOverflow)?;
        Ok(self.minimum_absolute_fee.max(rate_fee))
    }

    pub fn validate(self, transaction: TransactionFee) -> Result<(), FeePolicyViolation> {
        let required = self.required_fee(transaction)?;
        if transaction.amount < required {
            return Err(FeePolicyViolation::FeeBelowMinimum {
                required,
                actual: transaction.amount,
            });
        }
        Ok(())
    }
}

/// Fee facts computed from the fully blinded transaction, including the
/// provider's projected final witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactionFee {
    policy_asset: AssetId,
    amount: u64,
    weight: u64,
    regular_vsize: u64,
    discount_vsize: u64,
}

impl TransactionFee {
    pub fn new(
        policy_asset: AssetId,
        amount: u64,
        weight: u64,
        regular_vsize: u64,
        discount_vsize: u64,
    ) -> Result<Self, ModelError> {
        if weight == 0 || regular_vsize == 0 || discount_vsize == 0 {
            return Err(ModelError::ZeroTransactionSize);
        }
        let expected_regular_vsize = weight / 4 + u64::from(!weight.is_multiple_of(4));
        if regular_vsize != expected_regular_vsize || discount_vsize > regular_vsize {
            return Err(ModelError::InconsistentTransactionSize {
                weight,
                regular_vsize,
                discount_vsize,
            });
        }
        Ok(Self {
            policy_asset,
            amount,
            weight,
            regular_vsize,
            discount_vsize,
        })
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }

    #[must_use]
    pub const fn amount(self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn weight(self) -> u64 {
        self.weight
    }

    #[must_use]
    pub const fn regular_vsize(self) -> u64 {
        self.regular_vsize
    }

    #[must_use]
    pub const fn discount_vsize(self) -> u64 {
        self.discount_vsize
    }
}

/// Exact inventory allocation requested by one authenticated client operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationPlan {
    owner: OwnerId,
    idempotency_key: IdempotencyKey,
    quote_commitment: QuoteCommitment,
    outpoints: Vec<OutPoint>,
    accept_before: UnixMillis,
    fee_policy: FeePolicy,
}

impl ReservationPlan {
    pub fn new(
        owner: OwnerId,
        idempotency_key: IdempotencyKey,
        quote_commitment: QuoteCommitment,
        mut outpoints: Vec<OutPoint>,
        accept_before: UnixMillis,
        fee_policy: FeePolicy,
    ) -> Result<Self, ModelError> {
        if outpoints.is_empty() {
            return Err(ModelError::EmptyReservation);
        }
        if outpoints.len() > MAX_RESERVATION_INPUTS {
            return Err(ModelError::TooManyReservationInputs {
                maximum: MAX_RESERVATION_INPUTS,
                actual: outpoints.len(),
            });
        }
        outpoints.sort_unstable();
        if let Some(duplicate) = outpoints
            .windows(2)
            .find_map(|pair| (pair[0] == pair[1]).then_some(pair[0]))
        {
            return Err(ModelError::DuplicateReservationOutpoint(duplicate));
        }
        Ok(Self {
            owner,
            idempotency_key,
            quote_commitment,
            outpoints,
            accept_before,
            fee_policy,
        })
    }

    #[must_use]
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> IdempotencyKey {
        self.idempotency_key
    }

    #[must_use]
    pub const fn quote_commitment(&self) -> QuoteCommitment {
        self.quote_commitment
    }

    #[must_use]
    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }

    #[must_use]
    pub const fn accept_before(&self) -> UnixMillis {
        self.accept_before
    }

    #[must_use]
    pub const fn fee_policy(&self) -> FeePolicy {
        self.fee_policy
    }
}

/// Authenticated access to an existing reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservationAccess {
    reservation_id: ReservationId,
    owner: OwnerId,
}

impl ReservationAccess {
    #[must_use]
    pub const fn new(reservation_id: ReservationId, owner: OwnerId) -> Self {
        Self {
            reservation_id,
            owner,
        }
    }

    #[must_use]
    pub const fn reservation_id(self) -> ReservationId {
        self.reservation_id
    }

    #[must_use]
    pub const fn owner(self) -> OwnerId {
        self.owner
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseReason {
    Expired,
    ClientCancelled,
    ProviderRejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservationState {
    Reserved,
    Released {
        reason: ReleaseReason,
        at: UnixMillis,
    },
    Committed {
        commitment: SigningCommitment,
        committed_at: UnixMillis,
    },
    Signed {
        commitment: SigningCommitment,
        artifact: SignedArtifactDigest,
        committed_at: UnixMillis,
        signed_at: UnixMillis,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationView {
    pub(crate) id: ReservationId,
    pub(crate) owner: OwnerId,
    pub(crate) quote_commitment: QuoteCommitment,
    pub(crate) outpoints: Vec<OutPoint>,
    pub(crate) created_at: UnixMillis,
    pub(crate) accept_before: UnixMillis,
    pub(crate) fee_policy: FeePolicy,
    pub(crate) state: ReservationState,
}

impl ReservationView {
    #[must_use]
    pub const fn id(&self) -> ReservationId {
        self.id
    }

    #[must_use]
    pub const fn owner(&self) -> OwnerId {
        self.owner
    }

    #[must_use]
    pub const fn quote_commitment(&self) -> QuoteCommitment {
        self.quote_commitment
    }

    #[must_use]
    pub fn outpoints(&self) -> &[OutPoint] {
        &self.outpoints
    }

    #[must_use]
    pub const fn created_at(&self) -> UnixMillis {
        self.created_at
    }

    #[must_use]
    pub const fn accept_before(&self) -> UnixMillis {
        self.accept_before
    }

    #[must_use]
    pub const fn fee_policy(&self) -> FeePolicy {
        self.fee_policy
    }

    #[must_use]
    pub const fn state(&self) -> ReservationState {
        self.state
    }
}

/// Durable allocation state only.
///
/// `Available` means that no reservation owns the outpoint in redb. It does
/// not prove that the wallet still reports the output as unspent or that a
/// sufficiently fresh discovery snapshot exists. Quote construction must use
/// the wallet coordinator's eligible-inventory view instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryState {
    Available,
    Reserved {
        reservation_id: ReservationId,
    },
    Committed {
        reservation_id: ReservationId,
        commitment: SigningCommitment,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InventoryView {
    item: InventoryItem,
    state: InventoryState,
}

impl InventoryView {
    pub(crate) const fn new(item: InventoryItem, state: InventoryState) -> Self {
        Self { item, state }
    }

    #[must_use]
    pub const fn item(self) -> InventoryItem {
        self.item
    }

    #[must_use]
    pub const fn state(self) -> InventoryState {
        self.state
    }
}

/// Exact durable work item that a signer may consume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningJob {
    pub(crate) reservation_id: ReservationId,
    pub(crate) commitment: SigningCommitment,
    pub(crate) pre_sign_payload: Vec<u8>,
    pub(crate) fee: TransactionFee,
    pub(crate) targets: Vec<SigningTarget>,
}

impl SigningJob {
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    #[must_use]
    pub const fn commitment(&self) -> SigningCommitment {
        self.commitment
    }

    #[must_use]
    pub fn pre_sign_payload(&self) -> &[u8] {
        &self.pre_sign_payload
    }

    #[must_use]
    pub const fn fee(&self) -> TransactionFee {
        self.fee
    }

    /// Exact provider-owned inputs authorized by this durable signing job.
    #[must_use]
    pub fn targets(&self) -> &[SigningTarget] {
        &self.targets
    }
}

/// Non-secret wallet authorization for one provider input in a durable job.
///
/// The signing policy is fixed by the wallet boundary to tree-less P2TR key
/// path with explicit `SIGHASH_ALL`; it is intentionally not caller-selectable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningTarget {
    pub(crate) outpoint: OutPoint,
    pub(crate) wallet_locator: WalletKeyLocator,
    pub(crate) internal_key: XOnlyPublicKey,
    pub(crate) inventory_binding: InventoryBinding,
}

impl SigningTarget {
    #[must_use]
    pub const fn outpoint(self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn wallet_locator(self) -> WalletKeyLocator {
        self.wallet_locator
    }

    #[must_use]
    pub const fn internal_key(self) -> XOnlyPublicKey {
        self.internal_key
    }

    /// Commitment to the wallet-authenticated public prevout and durable metadata.
    #[must_use]
    pub const fn inventory_binding(self) -> InventoryBinding {
        self.inventory_binding
    }
}

/// Exact signed bytes persisted before any response or relay attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedArtifact {
    pub(crate) reservation_id: ReservationId,
    pub(crate) commitment: SigningCommitment,
    pub(crate) digest: SignedArtifactDigest,
    pub(crate) bytes: Vec<u8>,
}

impl SignedArtifact {
    #[must_use]
    pub const fn reservation_id(&self) -> ReservationId {
        self.reservation_id
    }

    #[must_use]
    pub const fn commitment(&self) -> SigningCommitment {
        self.commitment
    }

    #[must_use]
    pub const fn digest(&self) -> SignedArtifactDigest {
        self.digest
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    SignCommittedExact(SigningJob),
    ReplaySignedExact(SignedArtifact),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    pub(crate) sequence: u64,
    pub(crate) at: UnixMillis,
    pub(crate) event: AuditEvent,
}

impl AuditEntry {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn at(&self) -> UnixMillis {
        self.at
    }

    #[must_use]
    pub const fn event(&self) -> &AuditEvent {
        &self.event
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    InventoryImported {
        outpoint: OutPoint,
    },
    ReservationCreated {
        reservation_id: ReservationId,
        outpoints: Vec<OutPoint>,
    },
    ReservationReleased {
        reservation_id: ReservationId,
        reason: ReleaseReason,
    },
    SigningCommitted {
        reservation_id: ReservationId,
        commitment: SigningCommitment,
    },
    SignedArtifactStored {
        reservation_id: ReservationId,
        artifact: SignedArtifactDigest,
    },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModelError {
    #[error("inventory outpoint is null or contains issuance flags: {0:?}")]
    InvalidInventoryOutpoint(OutPoint),
    #[error("inventory amount must be nonzero")]
    ZeroInventoryAmount,
    #[error("wallet key locator must not be the all-zero reserved value")]
    InvalidWalletKeyLocator,
    #[error("minimum fee rate must be nonzero")]
    ZeroMinimumFeeRate,
    #[error("maximum transaction weight must be nonzero")]
    ZeroMaximumTransactionWeight,
    #[error("transaction weight and virtual sizes must be nonzero")]
    ZeroTransactionSize,
    #[error(
        "transaction size metrics disagree: weight={weight}, regular_vsize={regular_vsize}, discount_vsize={discount_vsize}"
    )]
    InconsistentTransactionSize {
        weight: u64,
        regular_vsize: u64,
        discount_vsize: u64,
    },
    #[error("a reservation must contain at least one outpoint")]
    EmptyReservation,
    #[error("a reservation contains {actual} inputs; maximum is {maximum}")]
    TooManyReservationInputs { maximum: usize, actual: usize },
    #[error("reservation contains duplicate outpoint {0:?}")]
    DuplicateReservationOutpoint(OutPoint),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FeePolicyViolation {
    #[error("fee uses asset {actual}, expected policy asset {expected}")]
    WrongPolicyAsset { expected: AssetId, actual: AssetId },
    #[error("transaction weight {actual} exceeds provider maximum {maximum}")]
    TransactionOverweight { maximum: u64, actual: u64 },
    #[error("required fee calculation overflowed")]
    RequiredFeeOverflow,
    #[error("network fee {actual} is below required minimum {required}")]
    FeeBelowMinimum { required: u64, actual: u64 },
}
