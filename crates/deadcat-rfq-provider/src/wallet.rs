//! Backend-neutral wallet discovery, destination, and signing capabilities.
//!
//! This module deliberately models capabilities rather than a particular
//! wallet RPC. Discovery authenticates the public transaction output against
//! its confidential opening and an exact tree-less P2TR key before producing
//! durable inventory metadata. The opening remains only in the redacted,
//! in-memory [`WalletOwnedOutput`] so collaborative blinding can consume it;
//! [`InventoryItem`] and the durable signing job never retain blinding factors.
//!
//! A signer receives only a durable [`SigningJob`]. It cannot be asked through
//! this interface to sign detached caller-supplied bytes, keys, or sighash
//! policies. Version one fixes provider inputs to P2TR key-path spends with an
//! explicitly serialized `SIGHASH_ALL` byte.

use core::fmt;
use std::error::Error;

use elements::confidential::{Asset, Value};
use elements::encode::serialize;
use elements::hashes::Hash as _;
use elements::secp256k1_zkp::{PublicKey, Secp256k1, XOnlyPublicKey};
use elements::{
    AssetId, BlockHash, OutPoint, SchnorrSig, SchnorrSighashType, Script, TxOut, TxOutSecrets,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::model::{
    InventoryBinding, InventoryItem, ModelError, ProviderIdentity, SigningCommitment, SigningJob,
    WalletKeyLocator,
};

/// Serialized Schnorr signature length when `SIGHASH_ALL` is explicit.
pub const P2TR_SIGHASH_ALL_SIGNATURE_BYTES: usize = 65;
/// Serialized witness-stack length for one explicit-`SIGHASH_ALL` key-path signature.
///
/// This is one compact-size stack count, one compact-size item length, and the
/// 65-byte signature. Transaction fee projection must account separately for
/// the surrounding Elements input-witness fields.
pub const P2TR_SIGHASH_ALL_SCRIPT_WITNESS_BYTES: usize = 67;

const OUTPUT_BINDING_DOMAIN: &[u8] = b"deadcat/rfq/wallet-owned-output/v1";
const SNAPSHOT_COMMITMENT_DOMAIN: &[u8] = b"deadcat/rfq/inventory-snapshot/v1";

/// Wallet-authenticated provider output suitable for version-one inventory.
///
/// The full public prevout and its validated confidential opening are retained
/// for later collaborative blinding and validation. The custom `Debug`
/// implementation omits the opening, and conversion to [`InventoryItem`]
/// deliberately drops every blinding factor before persistence.
#[derive(Clone, PartialEq, Eq)]
pub struct WalletOwnedOutput {
    txout: TxOut,
    opening: ConfidentialInputOpening,
    item: InventoryItem,
}

/// Sensitive in-memory opening of one provider confidential input.
///
/// This value exists only to let the provider blind its portion of a PSET. It
/// is deliberately absent from durable inventory, reservation records,
/// signing targets, raw-factor commitment transcripts, and debug output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfidentialInputOpening(TxOutSecrets);

impl ConfidentialInputOpening {
    /// Reveal the opening to the provider's collaborative-blinding adapter.
    /// Callers must not log or persist the returned blinding factors.
    // The concrete adapter is the next provider layer and will be this
    // crate-private capability's only non-test consumer.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn txout_secrets(self) -> TxOutSecrets {
        self.0
    }
}

impl fmt::Debug for ConfidentialInputOpening {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConfidentialInputOpening([redacted])")
    }
}

impl WalletOwnedOutput {
    /// Authenticate one wallet-discovered output.
    ///
    /// The caller is the wallet boundary: it is responsible for associating
    /// `wallet_locator` with both the spend and blinding capabilities used to
    /// discover this output. A surjection proof is required, but cannot be
    /// verified in isolation because its input-generator domain belongs to the
    /// output's creating transaction. The source must therefore authenticate
    /// that the creating transaction passed its configured chain or mempool
    /// validation policy. The settlement validator rechecks this exact prevout
    /// and validates the new transaction's confidential balance and proofs;
    /// it cannot reconstruct the old proof's missing generator domain from
    /// this isolated output alone.
    pub fn new(
        outpoint: OutPoint,
        txout: TxOut,
        opening: TxOutSecrets,
        internal_key: XOnlyPublicKey,
        wallet_locator: WalletKeyLocator,
    ) -> Result<Self, WalletBoundaryError> {
        if outpoint.is_null() || outpoint.vout & 0xc000_0000 != 0 {
            return Err(ModelError::InvalidInventoryOutpoint(outpoint).into());
        }
        if opening.value == 0 {
            return Err(ModelError::ZeroInventoryAmount.into());
        }
        if !txout.asset.is_confidential() {
            return Err(WalletBoundaryError::NonConfidentialAsset);
        }
        if !txout.value.is_confidential() {
            return Err(WalletBoundaryError::NonConfidentialValue);
        }
        if !txout.nonce.is_confidential() {
            return Err(WalletBoundaryError::NonConfidentialNonce);
        }
        if txout.witness.surjection_proof.is_none() {
            return Err(WalletBoundaryError::MissingSurjectionProof);
        }
        let Some(rangeproof) = txout.witness.rangeproof.as_deref() else {
            return Err(WalletBoundaryError::MissingRangeproof);
        };

        let secp = Secp256k1::new();
        let expected_script = Script::new_v1_p2tr(&secp, internal_key, None);
        if txout.script_pubkey != expected_script {
            return Err(WalletBoundaryError::NotExactTreeLessP2tr);
        }

        let expected_asset = Asset::new_confidential(&secp, opening.asset, opening.asset_bf);
        if txout.asset != expected_asset {
            return Err(WalletBoundaryError::AssetOpeningMismatch);
        }
        let expected_value = Value::new_confidential_from_assetid(
            &secp,
            opening.value,
            opening.asset,
            opening.value_bf,
            opening.asset_bf,
        );
        if txout.value != expected_value {
            return Err(WalletBoundaryError::ValueOpeningMismatch);
        }

        let value_commitment = txout
            .value
            .commitment()
            .ok_or(WalletBoundaryError::NonConfidentialValue)?;
        let asset_generator = txout
            .asset
            .commitment()
            .ok_or(WalletBoundaryError::NonConfidentialAsset)?;
        let proven_range = rangeproof
            .verify(
                &secp,
                value_commitment,
                txout.script_pubkey.as_bytes(),
                asset_generator,
            )
            .map_err(|_| WalletBoundaryError::InvalidRangeproof)?;
        if !proven_range.contains(&opening.value) {
            return Err(WalletBoundaryError::OpeningOutsideProvenRange);
        }

        let binding = output_binding(
            outpoint,
            &txout,
            opening.asset,
            opening.value,
            internal_key,
            wallet_locator,
        );
        let item = InventoryItem::new(
            outpoint,
            opening.asset,
            opening.value,
            wallet_locator,
            internal_key,
            binding,
        )?;

        Ok(Self {
            txout,
            opening: ConfidentialInputOpening(opening),
            item,
        })
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.item.outpoint()
    }

    #[must_use]
    pub const fn asset(&self) -> elements::AssetId {
        self.item.asset()
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.item.amount()
    }

    #[must_use]
    pub const fn wallet_locator(&self) -> WalletKeyLocator {
        self.item.wallet_locator()
    }

    #[must_use]
    pub const fn internal_key(&self) -> XOnlyPublicKey {
        self.item.internal_key()
    }

    #[must_use]
    pub const fn binding(&self) -> InventoryBinding {
        self.item.binding()
    }

    #[must_use]
    pub const fn inventory_item(&self) -> InventoryItem {
        self.item
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.txout
    }

    /// Return the validated opening needed for provider-side non-last PSET
    /// blinding. The returned factors must remain ephemeral.
    // Opening access stays inside this crate so quote/pricing consumers cannot
    // extract wallet input secrets from the public inventory view.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) const fn confidential_input_opening(&self) -> ConfidentialInputOpening {
        self.opening
    }
}

impl fmt::Debug for WalletOwnedOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WalletOwnedOutput")
            .field("outpoint", &self.outpoint())
            .field("asset", &self.asset())
            .field("amount", &self.amount())
            .field("wallet_locator", &self.wallet_locator())
            .field("internal_key", &self.internal_key())
            .field("binding", &self.binding())
            .finish_non_exhaustive()
    }
}

/// Chain point at which a complete wallet inventory scan was observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletScanAnchor {
    block_hash: BlockHash,
    block_height: u32,
}

impl WalletScanAnchor {
    #[must_use]
    pub const fn new(block_hash: BlockHash, block_height: u32) -> Self {
        Self {
            block_hash,
            block_height,
        }
    }

    #[must_use]
    pub const fn block_hash(self) -> BlockHash {
        self.block_hash
    }

    #[must_use]
    pub const fn block_height(self) -> u32 {
        self.block_height
    }
}

/// Deterministic commitment to one complete, canonically ordered scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InventorySnapshotCommitment([u8; 32]);

impl InventorySnapshotCommitment {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Complete provider-wallet inventory at one chain scan anchor.
///
/// Outputs are sorted by outpoint, and duplicates are rejected. Consequently,
/// the commitment does not depend on backend iteration order. Implementations
/// of [`InventorySource`] must return the complete currently spendable set;
/// callers treat an output missing from a new snapshot as ineligible even when
/// an older durable inventory record still exists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InventorySnapshot {
    identity: ProviderIdentity,
    anchor: WalletScanAnchor,
    outputs: Vec<WalletOwnedOutput>,
    commitment: InventorySnapshotCommitment,
}

impl InventorySnapshot {
    pub fn new(
        identity: ProviderIdentity,
        anchor: WalletScanAnchor,
        mut outputs: Vec<WalletOwnedOutput>,
    ) -> Result<Self, WalletBoundaryError> {
        outputs.sort_by_key(WalletOwnedOutput::outpoint);
        if let Some(duplicate) = outputs
            .windows(2)
            .find(|pair| pair[0].outpoint() == pair[1].outpoint())
            .map(|pair| pair[0].outpoint())
        {
            return Err(WalletBoundaryError::DuplicateSnapshotOutpoint(duplicate));
        }
        let commitment = snapshot_commitment(identity, anchor, &outputs);
        Ok(Self {
            identity,
            anchor,
            outputs,
            commitment,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> ProviderIdentity {
        self.identity
    }

    #[must_use]
    pub const fn anchor(&self) -> WalletScanAnchor {
        self.anchor
    }

    #[must_use]
    pub fn outputs(&self) -> &[WalletOwnedOutput] {
        &self.outputs
    }

    #[must_use]
    pub const fn commitment(&self) -> InventorySnapshotCommitment {
        self.commitment
    }
}

/// Authoritative source of complete, fresh provider-wallet inventory scans.
pub trait InventorySource {
    type Error: Error + Send + Sync + 'static;

    /// Return a newly observed, complete inventory snapshot.
    ///
    /// This call must not return a process-cached historical snapshot as fresh.
    /// It must return one coherent view at the reported chain anchor—not a
    /// delta or a streaming mixture of scan points—and must fail if the backend
    /// cannot establish that view. The backend is also responsible for
    /// returning only outputs whose creating transactions passed its configured
    /// chain or mempool validation policy; this trait cannot prove that claim.
    /// The coordinator independently verifies the returned provider/chain
    /// identity and intersects its outputs with durable `Available` state.
    fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error>;
}

/// Why the provider needs a fresh confidential destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationPurpose {
    /// Receive the asset paid to the provider by a settlement.
    SettlementReceive,
    /// Receive provider change from a settlement.
    SettlementChange,
}

/// Fresh wallet destination with P2TR spend and confidential-blinding data.
#[derive(Clone, PartialEq, Eq)]
pub struct ConfidentialDestination {
    script_pubkey: Script,
    blinding_public_key: PublicKey,
    internal_key: XOnlyPublicKey,
    wallet_locator: WalletKeyLocator,
}

impl ConfidentialDestination {
    /// Validate that a wallet-returned script is the exact tree-less P2TR
    /// output for its claimed internal key.
    pub fn new(
        script_pubkey: Script,
        blinding_public_key: PublicKey,
        internal_key: XOnlyPublicKey,
        wallet_locator: WalletKeyLocator,
    ) -> Result<Self, WalletBoundaryError> {
        let expected = Script::new_v1_p2tr(&Secp256k1::new(), internal_key, None);
        if script_pubkey != expected {
            return Err(WalletBoundaryError::NotExactTreeLessP2tr);
        }
        Ok(Self {
            script_pubkey,
            blinding_public_key,
            internal_key,
            wallet_locator,
        })
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &Script {
        &self.script_pubkey
    }

    #[must_use]
    pub const fn blinding_public_key(&self) -> PublicKey {
        self.blinding_public_key
    }

    #[must_use]
    pub const fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }

    #[must_use]
    pub const fn wallet_locator(&self) -> WalletKeyLocator {
        self.wallet_locator
    }
}

impl fmt::Debug for ConfidentialDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfidentialDestination")
            .field("script_pubkey", &self.script_pubkey)
            .field("blinding_public_key", &self.blinding_public_key)
            .field("internal_key", &self.internal_key)
            .field("wallet_locator", &"[opaque]")
            .finish()
    }
}

/// Source of non-reused provider receive and change destinations.
pub trait DestinationSource {
    type Error: Error + Send + Sync + 'static;

    /// Return a globally fresh destination whose recovery metadata remains
    /// usable after the caller durably persists it and the process restarts.
    ///
    /// The destination must never have been returned for either purpose. A
    /// caller may permanently burn an issued destination when a concurrent
    /// idempotent request wins or a database mutation rolls back; the backend
    /// must never recycle it. Global non-reuse and durable recoverability are
    /// backend guarantees that this interface cannot infer or enforce.
    fn fresh_confidential_destination(
        &self,
        purpose: DestinationPurpose,
    ) -> Result<ConfidentialDestination, Self::Error>;
}

/// Trusted provider-wallet capability for validating settlement outputs.
///
/// Output recovery belongs behind the wallet boundary because it requires the
/// destination's confidential blinding secret. Public proof verification is
/// not enough: an implementation must resolve the durable
/// [`WalletKeyLocator`], derive the ECDH nonce encoded by the output's
/// confidential nonce, and rewind the rangeproof. The blinding key, ECDH
/// shared secret, asset blinding factor, and value blinding factor must remain
/// internal to the wallet implementation.
pub trait ProviderOutputRecovery {
    type Error: Error + Send + Sync + 'static;

    /// Validate that `wallet_locator` resolves to `expected_internal_key`,
    /// that this tree-less key controls `txout`, and that the output is
    /// recoverable and opens to exactly `expected_asset` and
    /// `expected_amount`.
    ///
    /// The implementation must require confidential asset, value, and nonce
    /// commitments and use the wallet's own durable locator state; PSET
    /// blinding-key metadata is not evidence of ownership or recoverability.
    /// It must return an error if the locator does not recover the expected
    /// spend key, the script is not its tree-less P2TR output, ECDH nonce
    /// derivation or rangeproof rewind fails, or the recovered asset or amount
    /// differs. Success exposes no [`TxOutSecrets`] or other secret material to
    /// the caller.
    fn validate_confidential_output(
        &self,
        wallet_locator: WalletKeyLocator,
        expected_internal_key: XOnlyPublicKey,
        txout: &TxOut,
        expected_asset: AssetId,
        expected_amount: u64,
    ) -> Result<(), Self::Error>;
}

/// One explicit-`SIGHASH_ALL` P2TR key-path signature for a provider input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderInputSignature {
    outpoint: OutPoint,
    signature: SchnorrSig,
    serialized: [u8; P2TR_SIGHASH_ALL_SIGNATURE_BYTES],
}

impl ProviderInputSignature {
    pub fn new(outpoint: OutPoint, signature: SchnorrSig) -> Result<Self, WalletBoundaryError> {
        if signature.hash_ty != SchnorrSighashType::All {
            return Err(WalletBoundaryError::NonExplicitSighashAll {
                outpoint,
                actual: signature.hash_ty,
            });
        }
        let encoded = signature.to_vec();
        let serialized: [u8; P2TR_SIGHASH_ALL_SIGNATURE_BYTES] = encoded
            .try_into()
            .map_err(|_| WalletBoundaryError::InvalidSighashAllEncoding(outpoint))?;
        if serialized[P2TR_SIGHASH_ALL_SIGNATURE_BYTES - 1] != SchnorrSighashType::All as u8 {
            return Err(WalletBoundaryError::InvalidSighashAllEncoding(outpoint));
        }
        Ok(Self {
            outpoint,
            signature,
            serialized,
        })
    }

    #[must_use]
    pub const fn outpoint(self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn signature(self) -> SchnorrSig {
        self.signature
    }

    #[must_use]
    pub const fn serialized(&self) -> &[u8; P2TR_SIGHASH_ALL_SIGNATURE_BYTES] {
        &self.serialized
    }
}

/// Shape-validated signatures for exactly one durable signing job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningResponse {
    commitment: SigningCommitment,
    signatures: Vec<ProviderInputSignature>,
}

impl SigningResponse {
    /// Bind signatures to the exact ordered target list of `job`.
    ///
    /// Cryptographic verification and insertion are performed by the provider
    /// signing coordinator against the exact committed transaction and its
    /// already-authoritatively-checked prevouts.
    pub fn new(
        job: &SigningJob,
        signatures: Vec<ProviderInputSignature>,
    ) -> Result<Self, WalletBoundaryError> {
        if signatures.len() != job.targets().len() {
            return Err(WalletBoundaryError::SignatureCountMismatch {
                expected: job.targets().len(),
                actual: signatures.len(),
            });
        }
        for (index, (target, signature)) in job.targets().iter().zip(&signatures).enumerate() {
            if target.outpoint() != signature.outpoint() {
                return Err(WalletBoundaryError::SignatureTargetMismatch {
                    index,
                    expected: target.outpoint(),
                    actual: signature.outpoint(),
                });
            }
        }
        Ok(Self {
            commitment: job.commitment(),
            signatures,
        })
    }

    #[must_use]
    pub const fn commitment(&self) -> SigningCommitment {
        self.commitment
    }

    #[must_use]
    pub fn signatures(&self) -> &[ProviderInputSignature] {
        &self.signatures
    }
}

/// Provider wallet or HSM signer capability.
///
/// The sole signing input is an unforgeable durable [`SigningJob`]. Concrete
/// implementations recover keys through each job target's opaque locator and
/// must verify that each locator resolves to the target's exact untweaked
/// public key before signing only the persisted PSET bytes with P2TR key path
/// `SIGHASH_ALL`. Resolution must use durable wallet ownership history rather
/// than only the current unspent-output list, because a committed input may
/// disappear after an ambiguous signing attempt.
pub trait ProviderSigner {
    type Error: Error + Send + Sync + 'static;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error>;
}

/// Validation failures at the provider wallet boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WalletBoundaryError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error("wallet output asset is not confidential")]
    NonConfidentialAsset,
    #[error("wallet output value is not confidential")]
    NonConfidentialValue,
    #[error("wallet output nonce is not confidential")]
    NonConfidentialNonce,
    #[error("wallet output is missing its asset surjection proof")]
    MissingSurjectionProof,
    #[error("wallet output is missing its value rangeproof")]
    MissingRangeproof,
    #[error("wallet output is not the exact tree-less P2TR script for its internal key")]
    NotExactTreeLessP2tr,
    #[error("wallet output asset commitment disagrees with its opening")]
    AssetOpeningMismatch,
    #[error("wallet output value commitment disagrees with its opening")]
    ValueOpeningMismatch,
    #[error("wallet output rangeproof does not verify")]
    InvalidRangeproof,
    #[error("wallet output opening lies outside its rangeproof's proven range")]
    OpeningOutsideProvenRange,
    #[error("wallet inventory snapshot contains duplicate outpoint {0:?}")]
    DuplicateSnapshotOutpoint(OutPoint),
    #[error("provider signature for {outpoint:?} is not explicit SIGHASH_ALL: {actual:?}")]
    NonExplicitSighashAll {
        outpoint: OutPoint,
        actual: SchnorrSighashType,
    },
    #[error("provider signature for {0:?} has a non-canonical SIGHASH_ALL encoding")]
    InvalidSighashAllEncoding(OutPoint),
    #[error("signer returned {actual} signatures for {expected} durable targets")]
    SignatureCountMismatch { expected: usize, actual: usize },
    #[error("signer response target {index} is {actual:?}, expected durable target {expected:?}")]
    SignatureTargetMismatch {
        index: usize,
        expected: OutPoint,
        actual: OutPoint,
    },
}

fn output_binding(
    outpoint: OutPoint,
    txout: &TxOut,
    asset: elements::AssetId,
    amount: u64,
    internal_key: XOnlyPublicKey,
    wallet_locator: WalletKeyLocator,
) -> InventoryBinding {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, OUTPUT_BINDING_DOMAIN);
    hash_frame(&mut hasher, &serialize(&outpoint));
    hash_frame(&mut hasher, &serialize(txout));
    hash_frame(&mut hasher, &serialize(&txout.witness));
    hash_frame(&mut hasher, &asset.into_inner().to_byte_array());
    hash_frame(&mut hasher, &amount.to_be_bytes());
    hash_frame(&mut hasher, &internal_key.serialize());
    hash_frame(&mut hasher, &wallet_locator.to_bytes());
    InventoryBinding::new(hasher.finalize().into())
}

/// Recompute a durable inventory binding when the full public prevout is
/// available (for example inside a persisted firm quote).
pub(crate) fn recompute_inventory_binding(item: InventoryItem, txout: &TxOut) -> InventoryBinding {
    output_binding(
        item.outpoint(),
        txout,
        item.asset(),
        item.amount(),
        item.internal_key(),
        item.wallet_locator(),
    )
}

fn snapshot_commitment(
    identity: ProviderIdentity,
    anchor: WalletScanAnchor,
    outputs: &[WalletOwnedOutput],
) -> InventorySnapshotCommitment {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, SNAPSHOT_COMMITMENT_DOMAIN);
    hash_frame(&mut hasher, &identity.provider().to_bytes());
    hash_frame(&mut hasher, &identity.genesis_hash().to_byte_array());
    hash_frame(
        &mut hasher,
        &identity.policy_asset().into_inner().to_byte_array(),
    );
    hash_frame(&mut hasher, &anchor.block_hash().to_byte_array());
    hash_frame(&mut hasher, &anchor.block_height().to_be_bytes());
    hash_frame(
        &mut hasher,
        &u64::try_from(outputs.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for output in outputs {
        hash_frame(&mut hasher, &serialize(&output.outpoint()));
        hash_frame(&mut hasher, &output.binding().to_bytes());
    }
    InventorySnapshotCommitment(hasher.finalize().into())
}

fn hash_frame(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use core::convert::Infallible;

    use elements::confidential::{AssetBlindingFactor, Nonce, ValueBlindingFactor};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::rand::thread_rng;
    use elements::secp256k1_zkp::{Keypair, Message, SecretKey};
    use elements::taproot::TapNodeHash;
    use elements::{Address, AddressParams, AssetId, TxOutWitness, Txid};

    use super::*;
    use crate::model::{ProviderId, ReservationId, SigningTarget, TransactionFee};

    #[derive(Clone)]
    struct WalletFixture {
        internal_key: XOnlyPublicKey,
        spend_keypair: Keypair,
        blinding_public_key: PublicKey,
        script_pubkey: Script,
    }

    impl WalletFixture {
        fn new(spend_marker: u8, blind_marker: u8) -> Self {
            let secp = Secp256k1::new();
            let spend_secret = SecretKey::from_slice(&[spend_marker; 32]).expect("spend key");
            let spend_keypair = Keypair::from_secret_key(&secp, &spend_secret);
            let (internal_key, _) = spend_keypair.x_only_public_key();
            let blinding_secret = SecretKey::from_slice(&[blind_marker; 32]).expect("blinding key");
            let blinding_public_key = PublicKey::from_secret_key(&secp, &blinding_secret);
            let script_pubkey = Address::p2tr(
                &secp,
                internal_key,
                None,
                Some(blinding_public_key),
                &AddressParams::ELEMENTS,
            )
            .script_pubkey();
            Self {
                internal_key,
                spend_keypair,
                blinding_public_key,
                script_pubkey,
            }
        }

        fn output(
            &self,
            marker: u8,
            asset: AssetId,
            amount: u64,
        ) -> (OutPoint, TxOut, TxOutSecrets) {
            let explicit = TxOut {
                asset: Asset::Explicit(asset),
                value: Value::Explicit(amount),
                nonce: Nonce::Null,
                script_pubkey: self.script_pubkey.clone(),
                witness: TxOutWitness::default(),
            };
            let (txout, asset_bf, value_bf, _) = explicit
                .to_non_last_confidential(
                    &mut thread_rng(),
                    &Secp256k1::new(),
                    self.blinding_public_key,
                    &[TxOutSecrets::new(
                        asset,
                        AssetBlindingFactor::zero(),
                        amount,
                        ValueBlindingFactor::zero(),
                    )],
                )
                .expect("confidential output");
            (
                outpoint(marker),
                txout,
                TxOutSecrets::new(asset, asset_bf, amount, value_bf),
            )
        }
    }

    fn outpoint(marker: u8) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([marker; 32]), u32::from(marker))
    }

    fn asset(marker: u8) -> AssetId {
        AssetId::from_byte_array([marker; 32])
    }

    fn locator(marker: u8) -> WalletKeyLocator {
        WalletKeyLocator::new([marker; 32]).expect("locator")
    }

    fn identity() -> ProviderIdentity {
        ProviderIdentity::new(
            ProviderId::new([1; 32]),
            BlockHash::from_byte_array([2; 32]),
            asset(3),
        )
    }

    fn owned_output(wallet: &WalletFixture, marker: u8) -> WalletOwnedOutput {
        let (outpoint, txout, opening) = wallet.output(marker, asset(7), 10_000);
        WalletOwnedOutput::new(
            outpoint,
            txout,
            opening,
            wallet.internal_key,
            locator(marker),
        )
        .expect("authenticated wallet output")
    }

    #[test]
    fn authenticates_confidential_tree_less_p2tr_inventory() {
        let wallet = WalletFixture::new(4, 5);
        let (expected_outpoint, txout, expected_opening) = wallet.output(6, asset(7), 10_000);
        let output = WalletOwnedOutput::new(
            expected_outpoint,
            txout,
            expected_opening,
            wallet.internal_key,
            locator(6),
        )
        .expect("authenticated wallet output");
        let opening = output.confidential_input_opening();

        assert_eq!(output.outpoint(), outpoint(6));
        assert_eq!(output.asset(), asset(7));
        assert_eq!(output.amount(), 10_000);
        assert_eq!(output.internal_key(), wallet.internal_key);
        assert_eq!(output.wallet_locator(), locator(6));
        assert_eq!(output.txout().script_pubkey, wallet.script_pubkey);
        assert!(output.txout().witness.rangeproof.is_some());
        assert!(output.txout().witness.surjection_proof.is_some());
        assert_eq!(opening.txout_secrets(), expected_opening);
        assert_eq!(
            format!("{opening:?}"),
            "ConfidentialInputOpening([redacted])"
        );
        assert!(!format!("{output:?}").contains("opening"));
    }

    #[test]
    fn wallet_locator_rejects_the_reserved_value_and_redacts_debug_output() {
        assert_eq!(
            WalletKeyLocator::new([0; 32]),
            Err(ModelError::InvalidWalletKeyLocator)
        );
        let locator = WalletKeyLocator::new([0xab; 32]).expect("locator");
        assert_eq!(format!("{locator:?}"), "WalletKeyLocator([opaque])");
    }

    #[test]
    fn rejects_invalid_outpoints_and_zero_openings() {
        let wallet = WalletFixture::new(8, 9);
        let (_, txout, opening) = wallet.output(10, asset(11), 1);
        assert_eq!(
            WalletOwnedOutput::new(
                OutPoint::null(),
                txout.clone(),
                opening,
                wallet.internal_key,
                locator(10),
            ),
            Err(WalletBoundaryError::Model(
                ModelError::InvalidInventoryOutpoint(OutPoint::null())
            ))
        );

        let zero = TxOutSecrets::new(opening.asset, opening.asset_bf, 0, opening.value_bf);
        assert_eq!(
            WalletOwnedOutput::new(outpoint(10), txout, zero, wallet.internal_key, locator(10),),
            Err(WalletBoundaryError::Model(ModelError::ZeroInventoryAmount))
        );
    }

    #[test]
    fn requires_every_confidential_field_and_both_proofs() {
        let wallet = WalletFixture::new(12, 13);
        let (outpoint, txout, opening) = wallet.output(14, asset(15), 20);

        let mut explicit_asset = txout.clone();
        explicit_asset.asset = Asset::Explicit(opening.asset);
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                explicit_asset,
                opening,
                wallet.internal_key,
                locator(14),
            ),
            Err(WalletBoundaryError::NonConfidentialAsset)
        );

        let mut explicit_value = txout.clone();
        explicit_value.value = Value::Explicit(opening.value);
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                explicit_value,
                opening,
                wallet.internal_key,
                locator(14),
            ),
            Err(WalletBoundaryError::NonConfidentialValue)
        );

        let mut null_nonce = txout.clone();
        null_nonce.nonce = Nonce::Null;
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                null_nonce,
                opening,
                wallet.internal_key,
                locator(14),
            ),
            Err(WalletBoundaryError::NonConfidentialNonce)
        );

        let mut no_surjection_proof = txout.clone();
        no_surjection_proof.witness.surjection_proof = None;
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                no_surjection_proof,
                opening,
                wallet.internal_key,
                locator(14),
            ),
            Err(WalletBoundaryError::MissingSurjectionProof)
        );

        let mut no_rangeproof = txout;
        no_rangeproof.witness.rangeproof = None;
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                no_rangeproof,
                opening,
                wallet.internal_key,
                locator(14),
            ),
            Err(WalletBoundaryError::MissingRangeproof)
        );
    }

    #[test]
    fn verifies_opening_commitments_and_rangeproof() {
        let wallet = WalletFixture::new(16, 17);
        let (outpoint, txout, opening) = wallet.output(18, asset(19), 30);

        let wrong_asset =
            TxOutSecrets::new(asset(20), opening.asset_bf, opening.value, opening.value_bf);
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                txout.clone(),
                wrong_asset,
                wallet.internal_key,
                locator(18),
            ),
            Err(WalletBoundaryError::AssetOpeningMismatch)
        );

        let wrong_value = TxOutSecrets::new(
            opening.asset,
            opening.asset_bf,
            opening.value + 1,
            opening.value_bf,
        );
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                txout.clone(),
                wrong_value,
                wallet.internal_key,
                locator(18),
            ),
            Err(WalletBoundaryError::ValueOpeningMismatch)
        );

        let (_, other_txout, _) = wallet.output(21, opening.asset, opening.value);
        let mut wrong_rangeproof = txout;
        wrong_rangeproof.witness.rangeproof = other_txout.witness.rangeproof;
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                wrong_rangeproof,
                opening,
                wallet.internal_key,
                locator(18),
            ),
            Err(WalletBoundaryError::InvalidRangeproof)
        );
    }

    #[test]
    fn rejects_a_p2tr_output_not_bound_to_the_claimed_tree_less_key() {
        let wallet = WalletFixture::new(22, 23);
        let other_wallet = WalletFixture::new(24, 25);
        let (outpoint, txout, opening) = wallet.output(26, asset(27), 40);

        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                txout.clone(),
                opening,
                other_wallet.internal_key,
                locator(26),
            ),
            Err(WalletBoundaryError::NotExactTreeLessP2tr)
        );

        let mut non_p2tr = txout.clone();
        non_p2tr.script_pubkey = Script::new();
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                non_p2tr,
                opening,
                wallet.internal_key,
                locator(26),
            ),
            Err(WalletBoundaryError::NotExactTreeLessP2tr)
        );

        let mut script_tree = txout;
        script_tree.script_pubkey = Script::new_v1_p2tr(
            &Secp256k1::new(),
            wallet.internal_key,
            Some(TapNodeHash::from_byte_array([1; 32])),
        );
        assert_eq!(
            WalletOwnedOutput::new(
                outpoint,
                script_tree,
                opening,
                wallet.internal_key,
                locator(26),
            ),
            Err(WalletBoundaryError::NotExactTreeLessP2tr)
        );
    }

    #[test]
    fn output_binding_commits_to_the_opaque_wallet_locator() {
        let wallet = WalletFixture::new(28, 29);
        let (outpoint, txout, opening) = wallet.output(30, asset(31), 50);
        let first = WalletOwnedOutput::new(
            outpoint,
            txout.clone(),
            opening,
            wallet.internal_key,
            locator(30),
        )
        .expect("first output");
        let second =
            WalletOwnedOutput::new(outpoint, txout, opening, wallet.internal_key, locator(31))
                .expect("second output");

        assert_ne!(first.binding(), second.binding());
    }

    #[test]
    fn snapshots_sort_outputs_reject_duplicates_and_commit_deterministically() {
        let wallet = WalletFixture::new(32, 33);
        let first = owned_output(&wallet, 34);
        let second = owned_output(&wallet, 35);
        let anchor = WalletScanAnchor::new(BlockHash::from_byte_array([36; 32]), 42);

        let forward =
            InventorySnapshot::new(identity(), anchor, vec![first.clone(), second.clone()])
                .expect("forward snapshot");
        let reverse = InventorySnapshot::new(identity(), anchor, vec![second, first.clone()])
            .expect("reverse snapshot");
        assert_eq!(forward.outputs(), reverse.outputs());
        assert_eq!(forward.commitment(), reverse.commitment());

        let other_identity = ProviderIdentity::new(
            ProviderId::new([37; 32]),
            identity().genesis_hash(),
            identity().policy_asset(),
        );
        let identity_changed =
            InventorySnapshot::new(other_identity, anchor, forward.outputs().to_vec())
                .expect("identity-changed snapshot");
        assert_ne!(forward.commitment(), identity_changed.commitment());

        let other_anchor = WalletScanAnchor::new(BlockHash::from_byte_array([38; 32]), 43);
        let anchor_changed =
            InventorySnapshot::new(identity(), other_anchor, forward.outputs().to_vec())
                .expect("anchor-changed snapshot");
        assert_ne!(forward.commitment(), anchor_changed.commitment());

        assert_eq!(
            InventorySnapshot::new(identity(), anchor, vec![first.clone(), first]),
            Err(WalletBoundaryError::DuplicateSnapshotOutpoint(outpoint(34)))
        );
    }

    #[test]
    fn confidential_destinations_require_the_claimed_tree_less_key() {
        let wallet = WalletFixture::new(37, 38);
        let destination = ConfidentialDestination::new(
            wallet.script_pubkey.clone(),
            wallet.blinding_public_key,
            wallet.internal_key,
            locator(39),
        )
        .expect("destination");
        assert_eq!(destination.script_pubkey(), &wallet.script_pubkey);
        assert_eq!(
            destination.blinding_public_key(),
            wallet.blinding_public_key
        );

        let other = WalletFixture::new(40, 41);
        assert_eq!(
            ConfidentialDestination::new(
                wallet.script_pubkey,
                wallet.blinding_public_key,
                other.internal_key,
                locator(39),
            ),
            Err(WalletBoundaryError::NotExactTreeLessP2tr)
        );
    }

    fn signature(
        wallet: &WalletFixture,
        _outpoint: OutPoint,
        hash_ty: SchnorrSighashType,
    ) -> SchnorrSig {
        let message = Message::from_digest([42; 32]);
        SchnorrSig {
            sig: Secp256k1::new().sign_schnorr(&message, &wallet.spend_keypair),
            hash_ty,
        }
    }

    fn signing_job(wallet: &WalletFixture, targets: &[OutPoint]) -> SigningJob {
        SigningJob {
            reservation_id: ReservationId::new([43; 32]),
            commitment: SigningCommitment::new([44; 32]),
            pre_sign_payload: vec![45; 16],
            fee: TransactionFee::new(asset(3), 1_000, 400, 100, 80).expect("fee"),
            targets: targets
                .iter()
                .enumerate()
                .map(|(index, outpoint)| SigningTarget {
                    outpoint: *outpoint,
                    wallet_locator: locator(u8::try_from(index + 1).expect("small test index")),
                    internal_key: wallet.internal_key,
                    inventory_binding: InventoryBinding::new(
                        [u8::try_from(index + 1).expect("small test index"); 32],
                    ),
                })
                .collect(),
        }
    }

    #[test]
    fn provider_signatures_require_explicit_sighash_all() {
        let wallet = WalletFixture::new(46, 47);
        let outpoint = outpoint(48);
        let explicit = ProviderInputSignature::new(
            outpoint,
            signature(&wallet, outpoint, SchnorrSighashType::All),
        )
        .expect("explicit SIGHASH_ALL");
        assert_eq!(
            explicit.serialized().len(),
            P2TR_SIGHASH_ALL_SIGNATURE_BYTES
        );
        assert_eq!(
            explicit.serialized()[P2TR_SIGHASH_ALL_SIGNATURE_BYTES - 1],
            SchnorrSighashType::All as u8
        );
        assert_eq!(
            serialize(&vec![explicit.serialized().to_vec()]).len(),
            P2TR_SIGHASH_ALL_SCRIPT_WITNESS_BYTES
        );

        for hash_type in [
            SchnorrSighashType::Default,
            SchnorrSighashType::None,
            SchnorrSighashType::Single,
            SchnorrSighashType::AllPlusAnyoneCanPay,
            SchnorrSighashType::NonePlusAnyoneCanPay,
            SchnorrSighashType::SinglePlusAnyoneCanPay,
            SchnorrSighashType::Reserved,
        ] {
            assert_eq!(
                ProviderInputSignature::new(outpoint, signature(&wallet, outpoint, hash_type),),
                Err(WalletBoundaryError::NonExplicitSighashAll {
                    outpoint,
                    actual: hash_type,
                })
            );
        }
    }

    #[test]
    fn signing_response_matches_every_durable_target_in_order() {
        let wallet = WalletFixture::new(49, 50);
        let first_outpoint = outpoint(51);
        let second_outpoint = outpoint(52);
        let job = signing_job(&wallet, &[first_outpoint, second_outpoint]);
        let first = ProviderInputSignature::new(
            first_outpoint,
            signature(&wallet, first_outpoint, SchnorrSighashType::All),
        )
        .expect("first signature");
        let second = ProviderInputSignature::new(
            second_outpoint,
            signature(&wallet, second_outpoint, SchnorrSighashType::All),
        )
        .expect("second signature");

        let response = SigningResponse::new(&job, vec![first, second]).expect("response");
        assert_eq!(response.commitment(), job.commitment());
        assert_eq!(response.signatures().len(), 2);

        assert_eq!(
            SigningResponse::new(&job, vec![first]),
            Err(WalletBoundaryError::SignatureCountMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert_eq!(
            SigningResponse::new(&job, vec![second, first]),
            Err(WalletBoundaryError::SignatureTargetMismatch {
                index: 0,
                expected: first_outpoint,
                actual: second_outpoint,
            })
        );
    }

    struct MockInventorySource(InventorySnapshot);

    impl InventorySource for MockInventorySource {
        type Error = Infallible;

        fn inventory_snapshot(&self) -> Result<InventorySnapshot, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct MockDestinationSource(ConfidentialDestination);

    impl DestinationSource for MockDestinationSource {
        type Error = Infallible;

        fn fresh_confidential_destination(
            &self,
            _purpose: DestinationPurpose,
        ) -> Result<ConfidentialDestination, Self::Error> {
            Ok(self.0.clone())
        }
    }

    struct MockSigner {
        wallet: WalletFixture,
    }

    impl ProviderSigner for MockSigner {
        type Error = WalletBoundaryError;

        fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
            let signatures = job
                .targets()
                .iter()
                .map(|target| {
                    ProviderInputSignature::new(
                        target.outpoint(),
                        signature(&self.wallet, target.outpoint(), SchnorrSighashType::All),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            SigningResponse::new(job, signatures)
        }
    }

    #[test]
    fn backend_traits_carry_only_validated_capabilities() {
        let wallet = WalletFixture::new(53, 54);
        let output = owned_output(&wallet, 55);
        let snapshot = InventorySnapshot::new(
            identity(),
            WalletScanAnchor::new(BlockHash::from_byte_array([56; 32]), 9),
            vec![output],
        )
        .expect("snapshot");
        let source = MockInventorySource(snapshot.clone());
        assert_eq!(source.inventory_snapshot().expect("infallible"), snapshot);

        let destination = ConfidentialDestination::new(
            wallet.script_pubkey.clone(),
            wallet.blinding_public_key,
            wallet.internal_key,
            locator(57),
        )
        .expect("destination");
        let destinations = MockDestinationSource(destination.clone());
        assert_eq!(
            destinations
                .fresh_confidential_destination(DestinationPurpose::SettlementReceive)
                .expect("infallible"),
            destination
        );

        let job = signing_job(&wallet, &[outpoint(58)]);
        let response = MockSigner { wallet }
            .sign(&job)
            .expect("shape-valid signature response");
        assert_eq!(response.commitment(), job.commitment());
        assert_eq!(response.signatures()[0].outpoint(), outpoint(58));
    }

    #[test]
    fn wallet_boundary_values_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WalletOwnedOutput>();
        assert_send_sync::<InventorySnapshot>();
        assert_send_sync::<ConfidentialDestination>();
        assert_send_sync::<SigningResponse>();
    }
}
