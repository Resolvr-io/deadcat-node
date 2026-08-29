//! Process-local, wallet-bound funding leases for taker settlements.
//!
//! A lease fixes and exclusively holds the complete worst-case funding input
//! set before a quote is requested. That gives fee selection a stable input
//! and maximum-change shape. A crash before the execute attempt is durably
//! armed is safe because no execute request may have been sent; after arming,
//! the embedding runtime must restore exclusions from its execution journal
//! before admitting new funding work.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use deadcat_client::composition::{
    BlinderRef, CompositionLayout, CompositionLimits, InputId, InputSequence, InputSpec,
    LockTimeConstraint, OutputId, OutputSpec, TransactionContribution,
};
use deadcat_client::venue::{
    ComposedRoute, ConfidentialRecipient, ExecutionError, ExecutionKind, ExecutionRequest,
    RouteAuthorization, RouteCompositionError, ValidatedRoute,
};
use deadcat_rfq_client::{
    JournaledExecution, OwnedOutputKind, OwnedOutputValidation, TakerWalletBlindingJob,
    TakerWalletFinalizer, TakerWalletSigningJob,
};
use deadcat_rfq_provider::{
    ConfidentialDestination, DestinationPurpose, DestinationSource as _, ProviderId,
    ProviderIdentity, WalletKeyLocator, WalletOwnedOutput,
};
use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::encode::serialize;
use elements::pset::PartiallySignedTransaction;
use elements::secp256k1_zkp::XOnlyPublicKey;
use elements::{AssetId, BlockHash, OutPoint, Script, TxOut};
use rand::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::persistent::TakerFundingAuthority;
use crate::{PersistentRfqWallet, PersistentWalletError};

/// Taker-facing identity binding for one encrypted RFQ wallet.
///
/// `owner` is a stable, non-secret application identity (for example the
/// client's long-lived RFQ transport public key), not a private key. The
/// existing wallet envelope stores the same 96-byte owner/chain/policy tuple
/// used by provider wallets. The owner is domain-separated before it enters
/// that envelope, so equal application identities cannot make provider and
/// taker wallets share keys or accept one another's storage. Treat `owner` as
/// immutable wallet-recovery material: opening or restoring the wallet always
/// requires the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakerWalletIdentity {
    owner: [u8; 32],
    genesis_hash: BlockHash,
    policy_asset: AssetId,
}

impl TakerWalletIdentity {
    pub fn new(
        owner: [u8; 32],
        genesis_hash: BlockHash,
        policy_asset: AssetId,
    ) -> Result<Self, TakerWalletIdentityError> {
        if owner == [0; 32] {
            return Err(TakerWalletIdentityError::ZeroOwner);
        }
        Ok(Self {
            owner,
            genesis_hash,
            policy_asset,
        })
    }

    #[must_use]
    pub const fn owner(self) -> [u8; 32] {
        self.owner
    }

    #[must_use]
    pub const fn genesis_hash(self) -> BlockHash {
        self.genesis_hash
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }

    pub(crate) fn wallet_identity(self) -> ProviderIdentity {
        let mut hasher = Sha256::new();
        hasher.update(b"deadcat/rfq/taker-wallet-owner/v1");
        hasher.update(self.owner);
        ProviderIdentity::new(
            ProviderId::new(hasher.finalize().into()),
            self.genesis_hash,
            self.policy_asset,
        )
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum TakerWalletIdentityError {
    #[error("taker wallet owner identity must be nonzero")]
    ZeroOwner,
}

/// Wallet-authenticated, currently spendable confidential output.
///
/// Clear asset and amount are retained for selection. Confidential opening
/// factors are deliberately discarded after recovery and re-derived behind
/// the wallet boundary only for the final balancing blinding turn.
#[derive(Clone, PartialEq, Eq)]
pub struct TakerWalletUtxo {
    outpoint: OutPoint,
    txout: TxOut,
    asset: AssetId,
    amount: u64,
    locator: WalletKeyLocator,
    internal_key: XOnlyPublicKey,
}

impl TakerWalletUtxo {
    pub(crate) fn from_owned(owned: &WalletOwnedOutput) -> Self {
        Self {
            outpoint: owned.outpoint(),
            txout: owned.txout().clone(),
            asset: owned.asset(),
            amount: owned.amount(),
            locator: owned.wallet_locator(),
            internal_key: owned.internal_key(),
        }
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn asset(&self) -> AssetId {
        self.asset
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.txout
    }

    pub(crate) const fn locator(&self) -> WalletKeyLocator {
        self.locator
    }

    pub(crate) const fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }
}

impl fmt::Debug for TakerWalletUtxo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerWalletUtxo")
            .field("outpoint", &self.outpoint)
            .field("asset", &self.asset)
            .field("amount", &self.amount)
            .field("recovery", &"[opaque]")
            .finish()
    }
}

/// Fresh confidential receive address consumed by exactly one funding lease.
pub struct TakerReceiveDestination(ConfidentialDestination);

impl TakerReceiveDestination {
    pub(crate) const fn new(destination: ConfidentialDestination) -> Self {
        Self(destination)
    }

    pub fn recipient(&self) -> Result<ConfidentialRecipient, TakerFundingError> {
        ConfidentialRecipient::new(
            self.0.script_pubkey().clone(),
            BitcoinPublicKey::new(self.0.blinding_public_key()),
        )
        .map_err(TakerFundingError::Execution)
    }
}

impl fmt::Debug for TakerReceiveDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerReceiveDestination")
            .field("script_pubkey", self.0.script_pubkey())
            .field("recovery", &"[opaque]")
            .finish()
    }
}

/// Hard wallet-side funding-selection limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakerFundingLimits {
    pub max_wallet_inputs: usize,
}

impl Default for TakerFundingLimits {
    fn default() -> Self {
        Self {
            max_wallet_inputs: 16,
        }
    }
}

struct FundingState {
    inventory: BTreeMap<OutPoint, TakerWalletUtxo>,
    locks: BTreeMap<OutPoint, u64>,
    durable_exclusions: BTreeSet<OutPoint>,
    exclusion_revision: u64,
    exclusion_refresh_disabled: bool,
    next_lease: u64,
}

/// Optimistic token binding one inventory refresh to the exclusion state that
/// existed before its chain and execution-journal reads began.
#[derive(Clone)]
pub struct TakerInventoryRefreshToken {
    pool_marker: Arc<()>,
    revision: u64,
}

impl fmt::Debug for TakerInventoryRefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerInventoryRefreshToken")
            .field("pool", &"[process-local and opaque]")
            .field("revision", &self.revision)
            .finish()
    }
}

impl PartialEq for TakerInventoryRefreshToken {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool_marker, &other.pool_marker) && self.revision == other.revision
    }
}

impl Eq for TakerInventoryRefreshToken {}

#[derive(Clone)]
pub(crate) struct TakerInputBinding {
    pub(crate) outpoint: OutPoint,
    pub(crate) txout: TxOut,
    pub(crate) locator: WalletKeyLocator,
    pub(crate) internal_key: XOnlyPublicKey,
}

#[derive(Clone)]
pub(crate) struct TakerOutputBinding {
    pub(crate) script_pubkey: Script,
    pub(crate) locator: WalletKeyLocator,
    pub(crate) internal_key: XOnlyPublicKey,
    pub(crate) kind: OwnedOutputKind,
}

/// Shared funding inventory with exclusive process-local input leases.
pub struct TakerFundingPool<R> {
    wallet: Arc<PersistentRfqWallet<R>>,
    state: Arc<Mutex<FundingState>>,
    marker: Arc<()>,
    authority: Arc<TakerFundingAuthority<R>>,
}

/// Exclusive wallet-wide claim held while startup funding state is rebuilt.
///
/// Acquire this before reading external inventory or execution-journal state.
/// Converting it into a [`TakerFundingPool`] transfers the same authority into
/// every pool clone and outstanding lease, closing the handoff window in which
/// a prior runtime could mutate exclusions between recovery reads and pool
/// construction.
pub struct TakerFundingPoolClaim<R> {
    wallet: Arc<PersistentRfqWallet<R>>,
    authority: Arc<TakerFundingAuthority<R>>,
}

impl<R: RngCore + CryptoRng + Send> TakerFundingPoolClaim<R> {
    /// Validate the completed authoritative snapshot and transfer this claim
    /// into a live funding pool.
    pub fn initialize(
        self,
        inventory: Vec<TakerWalletUtxo>,
        durable_exclusions: BTreeSet<OutPoint>,
    ) -> Result<TakerFundingPool<R>, TakerFundingError> {
        let inventory = validate_inventory(&self.wallet, inventory)?;
        Ok(TakerFundingPool {
            wallet: self.wallet,
            state: Arc::new(Mutex::new(FundingState {
                inventory,
                locks: BTreeMap::new(),
                durable_exclusions,
                exclusion_revision: 0,
                exclusion_refresh_disabled: false,
                next_lease: 1,
            })),
            marker: Arc::new(()),
            authority: self.authority,
        })
    }
}

impl<R> fmt::Debug for TakerFundingPoolClaim<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerFundingPoolClaim")
            .field("wallet", &"[shared and redacted]")
            .finish_non_exhaustive()
    }
}

impl<R> Clone for TakerFundingPool<R> {
    fn clone(&self) -> Self {
        Self {
            wallet: Arc::clone(&self.wallet),
            state: Arc::clone(&self.state),
            marker: Arc::clone(&self.marker),
            authority: Arc::clone(&self.authority),
        }
    }
}

impl<R: RngCore + CryptoRng + Send> TakerFundingPool<R> {
    /// Claim the wallet-wide funding authority before reading recovery state.
    pub fn claim(
        wallet: Arc<PersistentRfqWallet<R>>,
        identity: TakerWalletIdentity,
    ) -> Result<TakerFundingPoolClaim<R>, TakerFundingError> {
        if wallet.identity() != identity.wallet_identity() {
            return Err(TakerFundingError::TakerWalletIdentityMismatch);
        }
        let authority = Arc::new(
            wallet
                .try_acquire_taker_funding_authority()
                .ok_or(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)?,
        );
        Ok(TakerFundingPoolClaim { wallet, authority })
    }

    /// Create a pool from one complete authoritative wallet scan.
    ///
    /// A runtime that reads inventory or journal state during startup should
    /// call [`Self::claim`] before those reads and then
    /// [`TakerFundingPoolClaim::initialize`]. This convenience constructor is
    /// for snapshots whose coherence is already protected by the caller.
    ///
    /// `durable_exclusions` must contain the wallet outpoints referenced by
    /// every execution-journal observation except an authenticated `Released`
    /// record restored at startup. An excluded outpoint need not remain in
    /// `inventory`: our exact transaction may already spend it in the mempool.
    ///
    /// Only one funding-pool authority may exist for an open wallet at a time.
    /// Pool clones and outstanding leases retain that authority; a subsequent
    /// call returns [`TakerFundingError::FundingPoolAuthorityAlreadyClaimed`]
    /// until all of them are dropped.
    pub fn new(
        wallet: Arc<PersistentRfqWallet<R>>,
        identity: TakerWalletIdentity,
        inventory: Vec<TakerWalletUtxo>,
        durable_exclusions: BTreeSet<OutPoint>,
    ) -> Result<Self, TakerFundingError> {
        Self::claim(wallet, identity)?.initialize(inventory, durable_exclusions)
    }

    #[must_use]
    pub fn wallet(&self) -> &PersistentRfqWallet<R> {
        self.wallet.as_ref()
    }

    pub fn fresh_receive_destination(&self) -> Result<TakerReceiveDestination, TakerFundingError> {
        self.wallet
            .fresh_taker_receive_destination()
            .map(TakerReceiveDestination::new)
            .map_err(TakerFundingError::from)
    }

    /// Begin an optimistic authoritative inventory/journal refresh.
    ///
    /// Obtain this token before reading either external source. A concurrent
    /// durable arm invalidates it, preventing a stale journal snapshot from
    /// erasing the newly armed outpoints.
    pub fn begin_inventory_refresh(&self) -> Result<TakerInventoryRefreshToken, TakerFundingError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TakerFundingError::FundingLockPoisoned)?;
        if state.exclusion_refresh_disabled {
            return Err(TakerFundingError::ExclusionRevisionExhausted);
        }
        Ok(TakerInventoryRefreshToken {
            pool_marker: Arc::clone(&self.marker),
            revision: state.exclusion_revision,
        })
    }

    /// Replace the authoritative inventory while preserving every live lease
    /// and rejecting a stale execution-journal exclusion snapshot.
    pub fn replace_inventory(
        &self,
        token: &TakerInventoryRefreshToken,
        inventory: Vec<TakerWalletUtxo>,
        durable_exclusions: BTreeSet<OutPoint>,
    ) -> Result<(), TakerFundingError> {
        let inventory = validate_inventory(&self.wallet, inventory)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| TakerFundingError::FundingLockPoisoned)?;
        if !Arc::ptr_eq(&token.pool_marker, &self.marker) {
            return Err(TakerFundingError::ForeignInventoryRefreshToken);
        }
        if state.exclusion_refresh_disabled {
            return Err(TakerFundingError::ExclusionRevisionExhausted);
        }
        if token.revision != state.exclusion_revision {
            return Err(TakerFundingError::StaleInventoryRefresh);
        }
        if state
            .locks
            .keys()
            .any(|outpoint| !inventory.contains_key(outpoint))
        {
            return Err(TakerFundingError::LeasedInputMissingFromSnapshot);
        }
        let next_revision = state.exclusion_revision.checked_add(1).ok_or_else(|| {
            state.exclusion_refresh_disabled = true;
            TakerFundingError::ExclusionRevisionExhausted
        })?;
        state.inventory = inventory;
        state.durable_exclusions = durable_exclusions;
        state.exclusion_revision = next_revision;
        Ok(())
    }

    /// Exclusively select the complete worst-case request funding before any
    /// venue quote fixes a fee policy or settlement shape.
    pub fn reserve_request(
        &self,
        request: &ExecutionRequest,
        receive: TakerReceiveDestination,
        limits: TakerFundingLimits,
    ) -> Result<TakerFundingLease<R>, TakerFundingError> {
        let wallet_identity = self.wallet.identity();
        if request.context().chain.genesis_hash != wallet_identity.genesis_hash()
            || request.context().policy_asset != wallet_identity.policy_asset()
        {
            return Err(TakerFundingError::RequestWalletIdentityMismatch);
        }
        if limits.max_wallet_inputs == 0 {
            return Err(TakerFundingError::InvalidFundingLimits);
        }
        if request.recipient() != &receive.recipient()? {
            return Err(TakerFundingError::ReceiveDestinationMismatch);
        }
        let input_asset = match request.kind() {
            ExecutionKind::ExactIn { input, .. } => input.asset(),
            ExecutionKind::ExactOut { input_asset, .. } => input_asset,
        };
        let maximum_input = match request.kind() {
            ExecutionKind::ExactIn { input, .. } => input.amount(),
            ExecutionKind::ExactOut { maximum_input, .. } => maximum_input,
        };
        let mut maximums = BTreeMap::new();
        add_required(&mut maximums, input_asset, maximum_input)?;
        add_required(
            &mut maximums,
            request.context().policy_asset,
            request.max_network_fee(),
        )?;

        let mut state = self
            .state
            .lock()
            .map_err(|_| TakerFundingError::FundingLockPoisoned)?;
        let mut selected = BTreeSet::new();
        for (&asset, &required) in &maximums {
            let mut candidates = state
                .inventory
                .values()
                .filter(|candidate| {
                    candidate.asset == asset
                        && !state.locks.contains_key(&candidate.outpoint)
                        && !state.durable_exclusions.contains(&candidate.outpoint)
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| {
                right
                    .amount
                    .cmp(&left.amount)
                    .then_with(|| left.outpoint.cmp(&right.outpoint))
            });
            let mut total = 0_u64;
            for candidate in candidates {
                total = total
                    .checked_add(candidate.amount)
                    .ok_or(TakerFundingError::AmountOverflow)?;
                selected.insert(candidate.outpoint);
                if selected.len() > limits.max_wallet_inputs {
                    return Err(TakerFundingError::TooManyWalletInputs {
                        maximum: limits.max_wallet_inputs,
                    });
                }
                if total >= required {
                    break;
                }
            }
            if total < required {
                return Err(TakerFundingError::InsufficientFunds { asset });
            }
        }
        let payer_blinder = selected
            .iter()
            .filter_map(|outpoint| state.inventory.get(outpoint))
            .filter(|candidate| candidate.asset == input_asset)
            .max_by(|left, right| {
                left.amount
                    .cmp(&right.amount)
                    .then_with(|| right.outpoint.cmp(&left.outpoint))
            })
            .map(|candidate| candidate.outpoint)
            .ok_or(TakerFundingError::MissingPayerInput)?;
        let lease_id = state.next_lease;
        state.next_lease = state
            .next_lease
            .checked_add(1)
            .ok_or(TakerFundingError::LeaseIdExhausted)?;
        for &outpoint in &selected {
            if state.locks.insert(outpoint, lease_id).is_some() {
                return Err(TakerFundingError::InputAlreadyLeased(outpoint));
            }
        }
        Ok(TakerFundingLease {
            wallet: Arc::clone(&self.wallet),
            state: Arc::clone(&self.state),
            lease_id,
            request: request.clone(),
            maximums,
            payer_blinder,
            selected,
            receive,
            _authority: Arc::clone(&self.authority),
        })
    }
}

impl<R> fmt::Debug for TakerFundingPool<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerFundingPool")
            .field("wallet", &"[shared and redacted]")
            .field("inventory", &"[wallet-authenticated]")
            .finish_non_exhaustive()
    }
}

/// Exclusive worst-case selection retained until execution is durably armed.
pub struct TakerFundingLease<R> {
    wallet: Arc<PersistentRfqWallet<R>>,
    state: Arc<Mutex<FundingState>>,
    lease_id: u64,
    request: ExecutionRequest,
    maximums: BTreeMap<AssetId, u64>,
    payer_blinder: OutPoint,
    selected: BTreeSet<OutPoint>,
    receive: TakerReceiveDestination,
    // Retain the wallet-wide authority even if every pool handle is dropped
    // while this pre-arm reservation remains live.
    _authority: Arc<TakerFundingAuthority<R>>,
}

impl<R: RngCore + CryptoRng + Send> TakerFundingLease<R> {
    #[must_use]
    pub const fn payer_blinder(&self) -> OutPoint {
        self.payer_blinder
    }

    #[must_use]
    pub fn selected_outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.selected
    }

    #[must_use]
    pub fn projected_wallet_input_count(&self) -> usize {
        self.selected.len()
    }

    #[must_use]
    pub fn maximum_change_output_count(&self) -> usize {
        self.maximums.len()
    }

    /// Compute exact change and compose without changing the pre-quoted input
    /// set, preserving the transaction shape used for fee selection.
    pub fn fund_route(
        self,
        route: ValidatedRoute,
        limits: CompositionLimits,
    ) -> Result<FundedTakerRoute<R>, TakerFundingError> {
        if route.request() != &self.request {
            return Err(TakerFundingError::RouteRequestMismatch);
        }
        let mut required = BTreeMap::<AssetId, u64>::new();
        let execution = route.summary().execution();
        add_required(
            &mut required,
            execution.input().asset(),
            execution.input().amount(),
        )?;
        let network_fee = route.summary().network_fee();
        add_required(
            &mut required,
            network_fee.policy_asset(),
            network_fee.amount(),
        )?;
        if required
            .iter()
            .any(|(asset, actual)| *actual > self.maximums.get(asset).copied().unwrap_or_default())
        {
            return Err(TakerFundingError::RouteExceedsReservedMaximum);
        }

        let selected_outputs = {
            let state = self
                .state
                .lock()
                .map_err(|_| TakerFundingError::FundingLockPoisoned)?;
            self.selected
                .iter()
                .map(|outpoint| {
                    if state.locks.get(outpoint) != Some(&self.lease_id) {
                        return Err(TakerFundingError::InputLeaseLost(*outpoint));
                    }
                    state
                        .inventory
                        .get(outpoint)
                        .cloned()
                        .ok_or(TakerFundingError::LeasedInputMissingFromSnapshot)
                })
                .collect::<Result<Vec<_>, _>>()?
        };

        let mut first_input_for_asset = BTreeMap::<AssetId, InputId>::new();
        let mut local_inputs = Vec::with_capacity(selected_outputs.len());
        for (position, utxo) in selected_outputs.iter().enumerate() {
            let id = InputId::new(
                u64::try_from(position + 1).map_err(|_| TakerFundingError::AmountOverflow)?,
            );
            first_input_for_asset.entry(utxo.asset).or_insert(id);
            local_inputs.push((
                id,
                InputSpec::tree_less_p2tr_sighash_all(
                    id,
                    utxo.outpoint,
                    utxo.txout.clone(),
                    InputSequence::Final,
                    utxo.internal_key,
                ),
                TakerInputBinding {
                    outpoint: utxo.outpoint,
                    txout: utxo.txout.clone(),
                    locator: utxo.locator,
                    internal_key: utxo.internal_key,
                },
            ));
        }

        let mut local_outputs = Vec::new();
        for (&asset, &maximum) in &self.maximums {
            let actual = required.get(&asset).copied().unwrap_or_default();
            let selected_total = selected_outputs
                .iter()
                .filter(|utxo| utxo.asset == asset)
                .try_fold(0_u64, |sum, utxo| {
                    sum.checked_add(utxo.amount)
                        .ok_or(TakerFundingError::AmountOverflow)
                })?;
            if selected_total < maximum || actual > selected_total {
                return Err(TakerFundingError::FundingInvariant);
            }
            let change = selected_total - actual;
            if change == 0 {
                continue;
            }
            let destination = self
                .wallet
                .fresh_confidential_destination(DestinationPurpose::SettlementChange)?;
            let id = OutputId::new(
                u64::try_from(local_outputs.len() + 1)
                    .map_err(|_| TakerFundingError::AmountOverflow)?,
            );
            let binding = TakerOutputBinding {
                script_pubkey: destination.script_pubkey().clone(),
                locator: destination.wallet_locator(),
                internal_key: destination.internal_key(),
                kind: OwnedOutputKind::WalletContribution,
            };
            let output = OutputSpec::confidential(
                id,
                asset,
                change,
                destination.script_pubkey().clone(),
                BitcoinPublicKey::new(destination.blinding_public_key()),
                BlinderRef::Local(
                    *first_input_for_asset
                        .get(&asset)
                        .ok_or(TakerFundingError::MissingChangeBlinder(asset))?,
                ),
            );
            local_outputs.push((id, output, binding));
        }
        let contribution = TransactionContribution::new(
            local_inputs
                .iter()
                .map(|(_, input, _)| input.clone())
                .collect(),
            local_outputs
                .iter()
                .map(|(_, output, _)| output.clone())
                .collect(),
            LockTimeConstraint::Unconstrained,
        );
        let route = route.compose(limits, contribution)?;
        let wallet_handle = route.layout().wallet();
        let composition_layout = route.transaction().layout().clone();
        let input_bindings = local_inputs
            .into_iter()
            .map(|(id, _, binding)| {
                composition_layout
                    .input_index(wallet_handle, id)
                    .map(|index| (index, binding))
                    .ok_or(TakerFundingError::CompositionBindingMissing)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut output_bindings = local_outputs
            .into_iter()
            .map(|(id, _, binding)| {
                composition_layout
                    .output_index(wallet_handle, id)
                    .map(|index| (index, binding))
                    .ok_or(TakerFundingError::CompositionBindingMissing)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        for leg in route.authorization().legs() {
            let handle = route
                .layout()
                .leg(leg.id())
                .ok_or(TakerFundingError::CompositionBindingMissing)?;
            let receive_index = composition_layout
                .output_index(handle, leg.receive_output())
                .ok_or(TakerFundingError::CompositionBindingMissing)?;
            let receive_output = route
                .transaction()
                .pset()
                .outputs()
                .get(receive_index)
                .ok_or(TakerFundingError::CompositionBindingMissing)?;
            if receive_output.script_pubkey != *self.receive.0.script_pubkey() {
                return Err(TakerFundingError::ReceiveOutputMismatch);
            }
            if output_bindings
                .insert(
                    receive_index,
                    TakerOutputBinding {
                        script_pubkey: self.receive.0.script_pubkey().clone(),
                        locator: self.receive.0.wallet_locator(),
                        internal_key: self.receive.0.internal_key(),
                        kind: OwnedOutputKind::RfqReceive,
                    },
                )
                .is_some()
            {
                return Err(TakerFundingError::CompositionBindingAliased);
            }
        }
        let authorization = route.authorization().clone();
        Ok(FundedTakerRoute {
            route,
            wallet: TakerSettlementWallet {
                wallet: Arc::clone(&self.wallet),
                lease: self,
                route: authorization,
                layout: composition_layout,
                input_bindings,
                output_bindings,
                signed_pset: Mutex::new(None),
            },
        })
    }
}

impl<R> Drop for TakerFundingLease<R> {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.locks.retain(|_, owner| *owner != self.lease_id);
    }
}

impl<R> fmt::Debug for TakerFundingLease<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerFundingLease")
            .field("payer_blinder", &self.payer_blinder)
            .field("selected", &self.selected)
            .field("receive", &self.receive)
            .finish_non_exhaustive()
    }
}

/// Fully composed route plus its exact, least-authority wallet finalizer.
pub struct FundedTakerRoute<R> {
    route: ComposedRoute,
    wallet: TakerSettlementWallet<R>,
}

impl<R> FundedTakerRoute<R> {
    #[must_use]
    pub const fn route(&self) -> &ComposedRoute {
        &self.route
    }

    #[must_use]
    pub const fn wallet(&self) -> &TakerSettlementWallet<R> {
        &self.wallet
    }

    #[must_use]
    pub fn into_parts(self) -> (ComposedRoute, TakerSettlementWallet<R>) {
        (self.route, self.wallet)
    }
}

impl<R> fmt::Debug for FundedTakerRoute<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FundedTakerRoute")
            .field("route", &self.route)
            .field("wallet", &self.wallet)
            .finish()
    }
}

/// Wallet authority scoped to one exact funded route and no other catalog
/// inputs or destinations.
pub struct TakerSettlementWallet<R> {
    wallet: Arc<PersistentRfqWallet<R>>,
    lease: TakerFundingLease<R>,
    route: RouteAuthorization,
    layout: CompositionLayout,
    input_bindings: BTreeMap<usize, TakerInputBinding>,
    output_bindings: BTreeMap<usize, TakerOutputBinding>,
    signed_pset: Mutex<Option<Vec<u8>>>,
}

impl<R> TakerSettlementWallet<R> {
    #[must_use]
    pub const fn lease(&self) -> &TakerFundingLease<R> {
        &self.lease
    }

    /// Transfer the process-local lease into the durable exclusion set only
    /// after the exact wallet-signed attempt has been committed to the client
    /// execution journal.
    ///
    /// Production orchestration must call this before the first Execute
    /// dispatch. `RfqSession` intentionally remains a lower-level transport
    /// API and does not itself own or enforce this wallet inventory state.
    pub fn mark_durably_armed(
        &self,
        journaled: &JournaledExecution,
    ) -> Result<DurablyArmedTakerFunding, TakerFundingError> {
        // `journaled` is already durable and therefore may be retried even if
        // any local consistency check below fails. Promote the lease first so
        // every error path remains fail-closed for input reuse.
        let outpoints = self.promote_durable_exclusions()?;
        let signed = self
            .signed_pset
            .lock()
            .map_err(|_| TakerFundingError::SignedPsetLockPoisoned)?;
        let expected = signed
            .as_ref()
            .ok_or(TakerFundingError::SettlementNotSigned)?;
        if journaled.attempt().pset().as_bytes() != expected {
            return Err(TakerFundingError::JournalAttemptMismatch);
        }
        let pset = journaled
            .attempt()
            .pset()
            .to_pset()
            .map_err(|_| TakerFundingError::JournalAttemptMismatch)?;
        for (&index, binding) in &self.input_bindings {
            let input = pset
                .inputs()
                .get(index)
                .ok_or(TakerFundingError::JournalAttemptMismatch)?;
            if OutPoint::new(input.previous_txid, input.previous_output_index) != binding.outpoint
                || input.tap_key_sig.is_none()
                || input.final_script_witness.is_none()
            {
                return Err(TakerFundingError::JournalAttemptMismatch);
            }
        }
        drop(signed);
        Ok(DurablyArmedTakerFunding { outpoints })
    }

    fn promote_durable_exclusions(&self) -> Result<BTreeSet<OutPoint>, TakerFundingError> {
        let outpoints = self.lease.selected.clone();
        let mut state = self
            .lease
            .state
            .lock()
            .map_err(|_| TakerFundingError::FundingLockPoisoned)?;
        for &outpoint in &outpoints {
            if state.locks.get(&outpoint) != Some(&self.lease.lease_id) {
                return Err(TakerFundingError::InputLeaseLost(outpoint));
            }
        }
        state.durable_exclusions.extend(outpoints.iter().copied());
        let Some(next_revision) = state.exclusion_revision.checked_add(1) else {
            state.exclusion_refresh_disabled = true;
            return Err(TakerFundingError::ExclusionRevisionExhausted);
        };
        state.exclusion_revision = next_revision;
        Ok(outpoints)
    }
}

impl<R: RngCore + CryptoRng + Send> TakerWalletFinalizer for TakerSettlementWallet<R> {
    type Error = PersistentWalletError;

    fn blind_last(
        &self,
        job: TakerWalletBlindingJob,
    ) -> Result<PartiallySignedTransaction, Self::Error> {
        self.wallet
            .blind_scoped_taker_job(job, &self.route, &self.layout, &self.input_bindings)
    }

    fn sign(&self, job: TakerWalletSigningJob) -> Result<PartiallySignedTransaction, Self::Error> {
        let mut signed = self
            .signed_pset
            .lock()
            .map_err(|_| PersistentWalletError::OperationLockPoisoned)?;
        if signed.is_some() {
            return Err(PersistentWalletError::TakerSettlementAlreadySigned);
        }
        let pset = self
            .wallet
            .sign_scoped_taker_job(job, &self.input_bindings)?;
        *signed = Some(serialize(&pset));
        Ok(pset)
    }

    fn validate_owned_output(&self, output: OwnedOutputValidation<'_>) -> Result<(), Self::Error> {
        let expectation = output.expectation();
        let binding = self
            .output_bindings
            .get(&expectation.index())
            .ok_or(PersistentWalletError::TakerOutputBindingMismatch)?;
        if binding.kind != expectation.kind()
            || binding.script_pubkey != *expectation.script_pubkey()
        {
            return Err(PersistentWalletError::TakerOutputBindingMismatch);
        }
        self.wallet.validate_scoped_taker_output(output, binding)
    }
}

/// Proof that the exact wallet inputs are represented in both a durable
/// execution journal record and this pool's exclusion set.
///
/// The embedding runtime must not dispatch the corresponding journaled attempt
/// until it has obtained this value, and must reconstruct the pool's durable
/// exclusions from every journal observation except authenticated `Released`
/// before serving new funding requests after restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurablyArmedTakerFunding {
    outpoints: BTreeSet<OutPoint>,
}

impl DurablyArmedTakerFunding {
    #[must_use]
    pub fn outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.outpoints
    }
}

impl<R> fmt::Debug for TakerSettlementWallet<R> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TakerSettlementWallet")
            .field("lease", &self.lease)
            .field("inputs", &self.input_bindings.len())
            .field("outputs", &self.output_bindings.len())
            .finish_non_exhaustive()
    }
}

fn validate_inventory<R: RngCore + CryptoRng + Send>(
    wallet: &PersistentRfqWallet<R>,
    inventory: Vec<TakerWalletUtxo>,
) -> Result<BTreeMap<OutPoint, TakerWalletUtxo>, TakerFundingError> {
    wallet.validate_taker_inventory(&inventory)?;
    let mut validated = BTreeMap::new();
    for utxo in inventory {
        let outpoint = utxo.outpoint;
        if validated.insert(outpoint, utxo).is_some() {
            return Err(TakerFundingError::DuplicateInventoryOutpoint(outpoint));
        }
    }
    Ok(validated)
}

fn add_required(
    required: &mut BTreeMap<AssetId, u64>,
    asset: AssetId,
    amount: u64,
) -> Result<(), TakerFundingError> {
    let entry = required.entry(asset).or_default();
    *entry = entry
        .checked_add(amount)
        .ok_or(TakerFundingError::AmountOverflow)?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum TakerFundingError {
    #[error(transparent)]
    Wallet(#[from] PersistentWalletError),
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Composition(#[from] RouteCompositionError),
    #[error("taker funding lock is poisoned")]
    FundingLockPoisoned,
    #[error("this open wallet already has a live taker funding-pool authority")]
    FundingPoolAuthorityAlreadyClaimed,
    #[error("the persistent wallet identity is not the required taker wallet identity")]
    TakerWalletIdentityMismatch,
    #[error("the inventory refresh raced a newer exclusion or refresh and must be retried")]
    StaleInventoryRefresh,
    #[error("the inventory refresh token belongs to a different funding pool")]
    ForeignInventoryRefreshToken,
    #[error("the execution request chain or policy asset differs from the taker wallet")]
    RequestWalletIdentityMismatch,
    #[error("the durable-exclusion revision space is exhausted; restart from the journal")]
    ExclusionRevisionExhausted,
    #[error("wallet inventory contains duplicate outpoint {0:?}")]
    DuplicateInventoryOutpoint(OutPoint),
    #[error("a process-leased input disappeared from the current inventory snapshot")]
    LeasedInputMissingFromSnapshot,
    #[error("taker funding lease identifiers are exhausted")]
    LeaseIdExhausted,
    #[error("insufficient available wallet funds for asset {asset}")]
    InsufficientFunds { asset: AssetId },
    #[error("funding amount arithmetic overflowed")]
    AmountOverflow,
    #[error("funding limits must permit at least one wallet input")]
    InvalidFundingLimits,
    #[error("wallet funding exceeds the configured {maximum}-input limit")]
    TooManyWalletInputs { maximum: usize },
    #[error("the execution request does not use the supplied wallet receive destination")]
    ReceiveDestinationMismatch,
    #[error("the selected funding set has no trade-asset payer input")]
    MissingPayerInput,
    #[error("wallet input {0:?} is already leased by another route")]
    InputAlreadyLeased(OutPoint),
    #[error("wallet input {0:?} lost its exclusive funding lease")]
    InputLeaseLost(OutPoint),
    #[error("the validated route is not the request bound to this funding lease")]
    RouteRequestMismatch,
    #[error("the validated route exceeds the funding lease's reserved maximum")]
    RouteExceedsReservedMaximum,
    #[error("wallet funding invariants were violated")]
    FundingInvariant,
    #[error("no selected input can blind change for asset {0}")]
    MissingChangeBlinder(AssetId),
    #[error("the composed route omitted an expected wallet binding")]
    CompositionBindingMissing,
    #[error("the composed route aliased a wallet binding")]
    CompositionBindingAliased,
    #[error("a composed venue receive output does not use the exact taker destination")]
    ReceiveOutputMismatch,
    #[error("the settlement wallet has not produced a signed PSET")]
    SettlementNotSigned,
    #[error("the wallet-signed PSET lock is poisoned")]
    SignedPsetLockPoisoned,
    #[error("the durable journal record does not contain the exact wallet-signed attempt")]
    JournalAttemptMismatch,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Barrier;
    use std::thread;

    use deadcat_client::composition::{InputSequence, NetworkFee};
    use deadcat_client::venue::{AssetAmount, ExactExecution, LegId, ProposedLeg, VenueContext};
    use deadcat_rfq_provider::{ProviderId, ProviderIdentity};
    use deadcat_types::{ChainIdentity, ContractId, LiquidNetwork};
    use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{Secp256k1, rand::thread_rng};
    use elements::{BlockHash, TxOutSecrets, TxOutWitness, Txid};
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::KdfParams;

    const PASSPHRASE: &[u8] = b"taker funding test passphrase";

    fn asset(marker: u8) -> AssetId {
        AssetId::from_byte_array([marker; 32])
    }

    fn identity(policy_asset: AssetId) -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new([0x31; 32]),
            BlockHash::from_byte_array([0x32; 32]),
            policy_asset,
        )
    }

    fn taker_identity(policy_asset: AssetId) -> TakerWalletIdentity {
        TakerWalletIdentity::new(
            [0x31; 32],
            BlockHash::from_byte_array([0x32; 32]),
            policy_asset,
        )
        .expect("taker identity")
    }

    fn wallet(policy_asset: AssetId) -> (TempDir, Arc<PersistentRfqWallet>) {
        let directory = tempdir().expect("temporary wallet directory");
        let wallet = PersistentRfqWallet::create_taker_with_kdf(
            directory.path().join("wallet.redb"),
            taker_identity(policy_asset),
            PASSPHRASE,
            KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
        )
        .expect("persistent wallet");
        (directory, Arc::new(wallet))
    }

    #[test]
    fn taker_identity_is_domain_separated_from_provider_identity() {
        let policy = asset(1);
        let taker = taker_identity(policy);
        assert_ne!(taker.wallet_identity(), identity(policy));

        let directory = tempdir().expect("temporary wallet directory");
        let path = directory.path().join("wallet.redb");
        drop(
            PersistentRfqWallet::create_taker_with_kdf(
                &path,
                taker,
                PASSPHRASE,
                KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
            )
            .expect("taker wallet"),
        );

        PersistentRfqWallet::open_taker(&path, taker, PASSPHRASE)
            .expect("same taker identity opens wallet");
        assert!(matches!(
            PersistentRfqWallet::open(&path, identity(policy), PASSPHRASE),
            Err(PersistentWalletError::IdentityMismatch)
        ));

        let provider_directory = tempdir().expect("provider wallet directory");
        let provider_wallet = Arc::new(
            PersistentRfqWallet::create_with_kdf(
                provider_directory.path().join("provider.redb"),
                identity(policy),
                PASSPHRASE,
                KdfParams::new(8 * 1_024, 1, 1).expect("test KDF"),
            )
            .expect("provider wallet"),
        );
        assert!(matches!(
            TakerFundingPool::new(provider_wallet, taker, Vec::new(), BTreeSet::new(),),
            Err(TakerFundingError::TakerWalletIdentityMismatch)
        ));
    }

    fn confidential_output(
        destination: &ConfidentialDestination,
        asset: AssetId,
        amount: u64,
    ) -> TxOut {
        let explicit = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey: destination.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        };
        explicit
            .to_non_last_confidential(
                &mut thread_rng(),
                &Secp256k1::new(),
                destination.blinding_public_key(),
                &[TxOutSecrets::new(
                    asset,
                    AssetBlindingFactor::zero(),
                    amount,
                    ValueBlindingFactor::zero(),
                )],
            )
            .expect("confidential output")
            .0
    }

    fn utxo(
        wallet: &PersistentRfqWallet,
        asset: AssetId,
        amount: u64,
        marker: u8,
    ) -> TakerWalletUtxo {
        let destination = wallet
            .fresh_inventory_destination()
            .expect("inventory destination");
        wallet
            .recover_taker_utxo(
                destination.wallet_locator(),
                OutPoint::new(Txid::from_byte_array([marker; 32]), 0),
                confidential_output(&destination, asset, amount),
            )
            .expect("wallet UTXO")
    }

    fn context(policy_asset: AssetId) -> VenueContext {
        VenueContext {
            chain: ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: identity(policy_asset).genesis_hash(),
            },
            market: ContractId::new(OutPoint::new(Txid::from_byte_array([0x44; 32]), 0)),
            policy_asset,
        }
    }

    fn exact_in_request(
        pool: &TakerFundingPool<rand::rngs::OsRng>,
        policy_asset: AssetId,
        input_asset: AssetId,
        input_amount: u64,
        maximum_fee: u64,
    ) -> (ExecutionRequest, TakerReceiveDestination) {
        let receive = pool
            .fresh_receive_destination()
            .expect("receive destination");
        let request = ExecutionRequest::exact_in(
            context(policy_asset),
            AssetAmount::new(input_asset, input_amount).expect("input amount"),
            asset(99),
            1,
            receive.recipient().expect("recipient"),
            BTreeMap::new(),
            maximum_fee,
        )
        .expect("execution request");
        (request, receive)
    }

    #[test]
    fn reserves_complete_worst_case_and_excludes_concurrent_routes() {
        let policy = asset(1);
        let input = asset(2);
        let (_directory, wallet) = wallet(policy);
        let inventory = vec![
            utxo(&wallet, input, 60, 1),
            utxo(&wallet, input, 50, 2),
            utxo(&wallet, policy, 1_000, 3),
        ];
        let pool = TakerFundingPool::new(
            Arc::clone(&wallet),
            taker_identity(policy),
            inventory,
            BTreeSet::new(),
        )
        .expect("funding pool");
        let (request, receive) = exact_in_request(&pool, policy, input, 100, 700);
        let lease = pool
            .reserve_request(&request, receive, TakerFundingLimits::default())
            .expect("funding lease");
        assert_eq!(lease.projected_wallet_input_count(), 3);
        assert_eq!(lease.maximum_change_output_count(), 2);
        assert_eq!(
            lease.payer_blinder(),
            OutPoint::new(Txid::from_byte_array([1; 32]), 0)
        );

        let (other_request, other_receive) = exact_in_request(&pool, policy, input, 100, 700);
        assert!(matches!(
            pool.reserve_request(
                &other_request,
                other_receive,
                TakerFundingLimits::default()
            ),
            Err(TakerFundingError::InsufficientFunds { asset }) if asset == policy || asset == input
        ));
        drop(lease);

        let (retry_request, retry_receive) = exact_in_request(&pool, policy, input, 100, 700);
        pool.reserve_request(&retry_request, retry_receive, TakerFundingLimits::default())
            .expect("released lease is reusable");
    }

    #[test]
    fn combines_trade_and_fee_maximum_when_policy_asset_is_the_input() {
        let policy = asset(1);
        let (_directory, wallet) = wallet(policy);
        let inventory = vec![utxo(&wallet, policy, 80, 11), utxo(&wallet, policy, 40, 12)];
        let pool = TakerFundingPool::new(
            Arc::clone(&wallet),
            taker_identity(policy),
            inventory,
            BTreeSet::new(),
        )
        .expect("funding pool");
        let (request, receive) = exact_in_request(&pool, policy, policy, 100, 20);
        let lease = pool
            .reserve_request(&request, receive, TakerFundingLimits::default())
            .expect("combined funding lease");
        assert_eq!(lease.projected_wallet_input_count(), 2);
        assert_eq!(lease.maximum_change_output_count(), 1);
    }

    #[test]
    fn durable_exclusions_need_not_be_in_the_current_inventory() {
        let policy = asset(1);
        let input = asset(2);
        let (_directory, wallet) = wallet(policy);
        let available = utxo(&wallet, input, 100, 21);
        let absent = OutPoint::new(Txid::from_byte_array([22; 32]), 0);
        TakerFundingPool::new(
            wallet,
            taker_identity(policy),
            vec![available],
            BTreeSet::from([absent]),
        )
        .expect("mempool-spent journal exclusion may be absent");
    }

    #[test]
    fn exact_out_route_keeps_fixed_inputs_and_creates_exact_change() {
        let policy = asset(1);
        let input = asset(2);
        let output_asset = asset(3);
        let (_directory, wallet) = wallet(policy);
        let trade = utxo(&wallet, input, 120, 31);
        let fee = utxo(&wallet, policy, 1_000, 32);
        let provider = utxo(&wallet, output_asset, 5, 33);
        let inventory = vec![trade, fee];
        let pool = TakerFundingPool::new(
            Arc::clone(&wallet),
            taker_identity(policy),
            inventory.clone(),
            BTreeSet::new(),
        )
        .expect("funding pool");
        let stale_refresh = pool
            .begin_inventory_refresh()
            .expect("refresh begins before durable arm");
        let receive = pool
            .fresh_receive_destination()
            .expect("receive destination");
        let request = ExecutionRequest::exact_out(
            context(policy),
            input,
            100,
            AssetAmount::new(output_asset, 5).expect("output amount"),
            receive.recipient().expect("recipient"),
            BTreeMap::new(),
            500,
        )
        .expect("execution request");
        let lease = pool
            .reserve_request(&request, receive, TakerFundingLimits::default())
            .expect("funding lease");
        let leg_request = request
            .exact_out_leg(LegId::new(1), 5, lease.payer_blinder())
            .expect("leg request");
        let payment_destination = wallet
            .fresh_taker_receive_destination()
            .expect("payment destination");
        let provider_input_id = InputId::new(1);
        let proposal = ProposedLeg::new(
            ExactExecution::new(
                AssetAmount::new(input, 80).expect("actual input"),
                AssetAmount::new(output_asset, 5).expect("actual output"),
            )
            .expect("execution"),
            BTreeMap::new(),
            TransactionContribution::new(
                vec![InputSpec::tree_less_p2tr_sighash_all(
                    provider_input_id,
                    provider.outpoint,
                    provider.txout.clone(),
                    InputSequence::Final,
                    provider.internal_key,
                )],
                vec![
                    OutputSpec::confidential(
                        OutputId::new(1),
                        input,
                        80,
                        payment_destination.script_pubkey().clone(),
                        BitcoinPublicKey::new(payment_destination.blinding_public_key()),
                        BlinderRef::External(lease.payer_blinder()),
                    ),
                    OutputSpec::confidential(
                        OutputId::new(2),
                        output_asset,
                        5,
                        request.recipient().script_pubkey().clone(),
                        request.recipient().blinding_key(),
                        BlinderRef::Local(provider_input_id),
                    ),
                ],
                LockTimeConstraint::Unconstrained,
            ),
            OutputId::new(1),
            OutputId::new(2),
        )
        .expect("proposal");
        let leg = leg_request.authorize(proposal).expect("prepared leg");
        let validated = request
            .validate_route(
                vec![leg],
                NetworkFee::new(policy, 500).expect("network fee"),
            )
            .expect("validated route");
        let funded = lease
            .fund_route(validated, CompositionLimits::default())
            .expect("funded route");

        assert_eq!(funded.wallet().lease().selected_outpoints().len(), 2);
        assert_eq!(funded.wallet().input_bindings.len(), 2);
        assert_eq!(funded.wallet().output_bindings.len(), 3);
        assert_eq!(funded.route().transaction().pset().inputs().len(), 3);
        assert_eq!(funded.route().transaction().pset().outputs().len(), 5);

        let selected = funded.wallet().lease().selected_outpoints().clone();
        funded
            .wallet()
            .promote_durable_exclusions()
            .expect("simulated durable arm");
        assert!(matches!(
            pool.replace_inventory(&stale_refresh, inventory.clone(), BTreeSet::new()),
            Err(TakerFundingError::StaleInventoryRefresh)
        ));
        drop(funded);

        let (retry_request, retry_receive) = exact_in_request(&pool, policy, input, 1, 1);
        assert!(matches!(
            pool.reserve_request(&retry_request, retry_receive, TakerFundingLimits::default(),),
            Err(TakerFundingError::InsufficientFunds { .. })
        ));

        let current_refresh = pool
            .begin_inventory_refresh()
            .expect("refresh after durable arm");
        pool.replace_inventory(&current_refresh, inventory, selected)
            .expect("fresh authoritative exclusions reconcile");
    }

    #[test]
    fn wrong_wallet_inventory_is_rejected() {
        let policy = asset(1);
        let (_first_directory, first) = wallet(policy);
        let (_second_directory, second) = wallet(policy);
        let foreign = utxo(&first, asset(2), 100, 41);
        assert!(matches!(
            TakerFundingPool::new(
                second,
                taker_identity(policy),
                vec![foreign],
                BTreeSet::new(),
            ),
            Err(TakerFundingError::Wallet(
                PersistentWalletError::TakerLocatorNotCataloged | PersistentWalletError::Wallet(_)
            ))
        ));
    }

    #[test]
    fn inventory_refresh_tokens_are_pool_scoped() {
        let policy = asset(1);
        let (_first_directory, first) = wallet(policy);
        let (_second_directory, second) = wallet(policy);
        let first =
            TakerFundingPool::new(first, taker_identity(policy), Vec::new(), BTreeSet::new())
                .expect("first pool");
        let second =
            TakerFundingPool::new(second, taker_identity(policy), Vec::new(), BTreeSet::new())
                .expect("second pool");
        let token = first.begin_inventory_refresh().expect("refresh token");
        assert!(matches!(
            second.replace_inventory(&token, Vec::new(), BTreeSet::new()),
            Err(TakerFundingError::ForeignInventoryRefreshToken)
        ));
    }

    #[test]
    fn funding_pool_authority_is_shared_by_clones_and_released_on_last_drop() {
        let policy = asset(1);
        let (_directory, wallet) = wallet(policy);
        let pool = TakerFundingPool::new(
            Arc::clone(&wallet),
            taker_identity(policy),
            Vec::new(),
            BTreeSet::new(),
        )
        .expect("first funding authority");
        let clone = pool.clone();

        assert!(matches!(
            TakerFundingPool::new(
                Arc::clone(&wallet),
                taker_identity(policy),
                Vec::new(),
                BTreeSet::new(),
            ),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));
        drop(pool);
        assert!(matches!(
            TakerFundingPool::new(
                Arc::clone(&wallet),
                taker_identity(policy),
                Vec::new(),
                BTreeSet::new(),
            ),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));

        drop(clone);
        TakerFundingPool::new(wallet, taker_identity(policy), Vec::new(), BTreeSet::new())
            .expect("last pool clone releases authority");
    }

    #[test]
    fn startup_claim_excludes_other_pools_before_inventory_is_initialized() {
        let policy = asset(1);
        let (_directory, wallet) = wallet(policy);
        let claim = TakerFundingPool::claim(Arc::clone(&wallet), taker_identity(policy))
            .expect("claim startup authority before recovery reads");

        assert!(matches!(
            TakerFundingPool::new(
                Arc::clone(&wallet),
                taker_identity(policy),
                Vec::new(),
                BTreeSet::new(),
            ),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));

        let pool = claim
            .initialize(Vec::new(), BTreeSet::new())
            .expect("transfer startup authority into the pool");
        assert!(matches!(
            TakerFundingPool::claim(Arc::clone(&wallet), taker_identity(policy)),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));
        drop(pool);
        TakerFundingPool::claim(wallet, taker_identity(policy))
            .expect("dropping the pool releases transferred authority");
    }

    #[test]
    fn outstanding_lease_retains_funding_pool_authority() {
        let policy = asset(1);
        let (_directory, wallet) = wallet(policy);
        let inventory = vec![utxo(&wallet, policy, 120, 51)];
        let pool = TakerFundingPool::new(
            Arc::clone(&wallet),
            taker_identity(policy),
            inventory.clone(),
            BTreeSet::new(),
        )
        .expect("funding pool");
        let (request, receive) = exact_in_request(&pool, policy, policy, 100, 20);
        let lease = pool
            .reserve_request(&request, receive, TakerFundingLimits::default())
            .expect("funding lease");
        drop(pool);

        assert!(matches!(
            TakerFundingPool::new(
                Arc::clone(&wallet),
                taker_identity(policy),
                inventory.clone(),
                BTreeSet::new(),
            ),
            Err(TakerFundingError::FundingPoolAuthorityAlreadyClaimed)
        ));

        drop(lease);
        TakerFundingPool::new(wallet, taker_identity(policy), inventory, BTreeSet::new())
            .expect("dropping the last lease releases authority");
    }

    #[test]
    fn concurrent_funding_pool_acquisition_has_exactly_one_winner() {
        const CONTENDERS: usize = 8;

        let policy = asset(1);
        let (_directory, wallet) = wallet(policy);
        let start = Arc::new(Barrier::new(CONTENDERS + 1));
        let handles = (0..CONTENDERS)
            .map(|_| {
                let wallet = Arc::clone(&wallet);
                let start = Arc::clone(&start);
                thread::spawn(move || {
                    start.wait();
                    TakerFundingPool::new(
                        wallet,
                        taker_identity(policy),
                        Vec::new(),
                        BTreeSet::new(),
                    )
                })
            })
            .collect::<Vec<_>>();
        start.wait();

        // Keep every successful result alive while joining the remaining
        // contenders so the winner cannot release and hand authority to a
        // later thread in the same race.
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("contender did not panic"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| matches!(
                    error,
                    TakerFundingError::FundingPoolAuthorityAlreadyClaimed
                ))
        );

        drop(results);
        TakerFundingPool::new(wallet, taker_identity(policy), Vec::new(), BTreeSet::new())
            .expect("race winner releases authority when dropped");
    }
}
