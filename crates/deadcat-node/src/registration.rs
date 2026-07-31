//! Evidence-first contract registration and creation-transaction verification.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr as _;
use std::sync::Arc;

use deadcat_contracts::binary_market::{
    BinaryMarketSlot, CompiledBinaryMarket, CompiledBinaryMarketError,
};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{
    MARKET_V1_TAG, MarketCollateral, MarketRecoveryHint, validate_recovery_txout,
};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainPosition, ContractDeclaration, ContractDescriptor, ContractId, ContractKind,
    ContractPackage, ContractSyncState, LiquidNetwork, MAX_CONTRACT_PACKAGE_DECLARATIONS,
    MAX_CONTRACT_PACKAGE_ROOTS, RecoveryHintLocation,
};
use elements::confidential::{Asset, Value};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{AssetId, BlockHash, OutPoint, Transaction, Txid};
use thiserror::Error;

use crate::chain::{ChainSource, ChainSourceError, TransactionStatus};
use crate::store::{
    AssetBinding, AssetRelationKind, ContractParameters, ContractRecord, ContractState,
    RegistrationEvidence, ScriptBinding, Store, StoreError, TrackedOutpoint,
};

const LIQUID_MAINNET_USDT: &str =
    "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";
pub const MAX_PACKAGE_DECLARATIONS: usize = MAX_CONTRACT_PACKAGE_DECLARATIONS;
pub const MAX_PACKAGE_ROOTS: usize = MAX_CONTRACT_PACKAGE_ROOTS;
/// Maximum cumulative consensus-encoded size of the unique creation
/// transactions fetched while verifying one package. This matches the 16 MiB
/// Iroh RPC frame ceiling and bounds server-side work for evidence which is
/// fetched from the chain source rather than carried in that inbound frame.
pub const MAX_PACKAGE_CREATION_EVIDENCE_BYTES: usize = deadcat_iroh::wire::MAX_FRAME_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRegistration {
    pub record: ContractRecord,
    pub creation_block_anchor: ChainAnchor,
    pub creation_transaction: Arc<Transaction>,
    pub associated_hint: Option<RecoveryHintLocation>,
}

pub struct RegistrationVerifier<'a, S> {
    source: &'a S,
    store: &'a Store,
    network: LiquidNetwork,
    genesis_hash: BlockHash,
    policy_asset: AssetId,
}

impl<'a, S> RegistrationVerifier<'a, S>
where
    S: ChainSource,
{
    #[must_use]
    pub const fn new(
        source: &'a S,
        store: &'a Store,
        network: LiquidNetwork,
        genesis_hash: BlockHash,
        policy_asset: AssetId,
    ) -> Self {
        Self {
            source,
            store,
            network,
            genesis_hash,
            policy_asset,
        }
    }

    /// Verify every declaration from canonical chain evidence. Package order is
    /// not trusted and each creation transaction is fetched at most once.
    pub async fn verify_package(
        &self,
        package: &ContractPackage,
    ) -> Result<Vec<VerifiedRegistration>, RegistrationError> {
        let declarations = self.validate_package(package)?;
        let mut evidence = HashMap::<Txid, CreationEvidence>::new();
        let mut evidence_bytes = 0_usize;
        let mut verified = BTreeMap::<ContractId, VerifiedRegistration>::new();

        for declaration in declarations.values() {
            let creation = self
                .creation_evidence(
                    declaration.contract_id.txid(),
                    &mut evidence,
                    &mut evidence_bytes,
                )
                .await?;
            let ContractDescriptor::BinaryMarketV1 { params } = declaration.descriptor;
            let registration = verify_binary_market_creation_shared(
                Arc::clone(&creation.transaction),
                creation.position,
                creation.anchor,
                self.network,
                self.policy_asset,
                Some(params),
                Some(declaration.contract_id),
            )?;
            verified.insert(declaration.contract_id, registration);
        }

        // Receipts and persistence inputs retain the sender's declaration order.
        package
            .declarations
            .iter()
            .map(|declaration| {
                verified.remove(&declaration.contract_id).ok_or_else(|| {
                    RegistrationError::InvalidPackage(
                        "declaration was not verified by a supported family".to_owned(),
                    )
                })
            })
            .collect()
    }

    /// Verify against canonical chain evidence and atomically persist the
    /// complete package. An identical retry is idempotent.
    pub async fn verify_and_register_package(
        &self,
        package: &ContractPackage,
    ) -> Result<Vec<(VerifiedRegistration, bool)>, RegistrationError> {
        let verified = self.verify_package(package).await?;
        let mut hint_claims = HashMap::<RecoveryHintLocation, usize>::new();
        for location in verified.iter().filter_map(|item| item.associated_hint) {
            *hint_claims.entry(location).or_default() += 1;
        }
        let registrations = verified
            .iter()
            .map(|item| {
                // Esplora-backed nodes may not have indexed historical hints.
                // Claim a verified hint atomically when its row exists, but a
                // missing advisory index row must not invalidate the contract.
                let associated_hint = match item.associated_hint {
                    Some(location)
                        if hint_claims.get(&location) == Some(&1)
                            && self.store.recovery_hint(location)?.is_some() =>
                    {
                        Some(location)
                    }
                    _ => None,
                };
                Ok((
                    item.record.clone(),
                    RegistrationEvidence {
                        anchor: item.creation_block_anchor,
                        transaction: Arc::clone(&item.creation_transaction),
                        associated_hint,
                    },
                ))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let results = self.store.register_contracts(&registrations)?;
        if results.len() != verified.len() {
            return Err(RegistrationError::InvalidPackage(
                "registration store returned the wrong result count".to_owned(),
            ));
        }
        Ok(verified
            .into_iter()
            .zip(results)
            .map(|(mut verified, result)| {
                verified.record = result.record;
                (verified, result.inserted)
            })
            .collect())
    }

    fn validate_package(
        &self,
        package: &ContractPackage,
    ) -> Result<BTreeMap<ContractId, ContractDeclaration>, RegistrationError> {
        if package.format_version != CONTRACT_PACKAGE_FORMAT_VERSION {
            return Err(RegistrationError::InvalidPackage(format!(
                "unsupported contract package format {}; expected {CONTRACT_PACKAGE_FORMAT_VERSION}",
                package.format_version
            )));
        }
        if package.chain.network != self.network || package.chain.genesis_hash != self.genesis_hash
        {
            return Err(RegistrationError::WrongChain);
        }
        if package.declarations.is_empty() || package.declarations.len() > MAX_PACKAGE_DECLARATIONS
        {
            return Err(RegistrationError::InvalidPackage(format!(
                "contract package must contain 1..={MAX_PACKAGE_DECLARATIONS} declarations"
            )));
        }
        if package.roots.is_empty()
            || package.roots.len() > MAX_PACKAGE_ROOTS
            || package.roots.len() > package.declarations.len()
        {
            return Err(RegistrationError::InvalidPackage(format!(
                "contract package must contain 1..={MAX_PACKAGE_ROOTS} roots, no more than its declarations"
            )));
        }

        let mut declarations = BTreeMap::new();
        for declaration in &package.declarations {
            if declarations
                .insert(declaration.contract_id, *declaration)
                .is_some()
            {
                return Err(RegistrationError::InvalidPackage(
                    "contract package contains duplicate declaration IDs".to_owned(),
                ));
            }
        }

        let roots = package.roots.iter().copied().collect::<BTreeSet<_>>();
        if roots.len() != package.roots.len() {
            return Err(RegistrationError::InvalidPackage(
                "contract package contains duplicate roots".to_owned(),
            ));
        }
        if roots.iter().any(|root| !declarations.contains_key(root)) {
            return Err(RegistrationError::InvalidPackage(
                "every package root must have a declaration".to_owned(),
            ));
        }

        if roots.len() != declarations.len() {
            return Err(RegistrationError::InvalidPackage(
                "every contract package declaration must be a root".to_owned(),
            ));
        }

        Ok(declarations)
    }

    async fn creation_evidence<'cache>(
        &self,
        txid: Txid,
        cache: &'cache mut HashMap<Txid, CreationEvidence>,
        cumulative_bytes: &mut usize,
    ) -> Result<&'cache CreationEvidence, RegistrationError> {
        if let Entry::Vacant(entry) = cache.entry(txid) {
            let transaction = self.source.transaction(txid).await?;
            if transaction.txid() != txid {
                return Err(RegistrationError::InvalidCreation(
                    "chain source returned a transaction with the wrong txid".to_owned(),
                ));
            }
            let transaction_bytes = elements::encode::serialize(&transaction).len();
            *cumulative_bytes =
                cumulative_bytes
                    .checked_add(transaction_bytes)
                    .ok_or_else(|| {
                        RegistrationError::InvalidPackage(
                            "creation evidence byte count overflowed usize".to_owned(),
                        )
                    })?;
            if *cumulative_bytes > MAX_PACKAGE_CREATION_EVIDENCE_BYTES {
                return Err(RegistrationError::InvalidPackage(format!(
                    "unique creation evidence exceeds the {MAX_PACKAGE_CREATION_EVIDENCE_BYTES}-byte package budget"
                )));
            }
            let (anchor, tx_index) = match self.source.transaction_status(txid).await? {
                TransactionStatus::Confirmed { anchor, tx_index } => (anchor, tx_index),
                TransactionStatus::Unconfirmed => {
                    return Err(RegistrationError::UnconfirmedCreation);
                }
            };
            let activation = self.store.activation_anchor()?;
            // Test-only verifier fixtures may omit chain bootstrap; production
            // builds require the persisted activation before accepting evidence.
            if activation.is_none() && !cfg!(test) {
                return Err(StoreError::ActivationNotInitialized.into());
            }
            if let Some(activation) = activation
                && anchor.height <= activation.height
            {
                return Err(RegistrationError::PreActivationCreation {
                    creation: anchor,
                    activation,
                });
            }
            entry.insert(CreationEvidence {
                transaction: Arc::new(transaction),
                anchor,
                position: ChainPosition {
                    block_height: anchor.height,
                    tx_index,
                },
            });
        }
        cache.get(&txid).ok_or_else(|| {
            RegistrationError::InvalidCreation("creation evidence cache failure".to_owned())
        })
    }
}

struct CreationEvidence {
    transaction: Arc<Transaction>,
    anchor: ChainAnchor,
    position: ChainPosition,
}

#[allow(clippy::too_many_arguments)]
pub fn verify_binary_market_creation(
    transaction: &Transaction,
    position: ChainPosition,
    anchor: ChainAnchor,
    network: LiquidNetwork,
    policy_asset: AssetId,
    supplied_params: Option<BinaryMarketParams>,
    expected_contract_id: Option<ContractId>,
) -> Result<VerifiedRegistration, RegistrationError> {
    verify_binary_market_creation_shared(
        Arc::new(transaction.clone()),
        position,
        anchor,
        network,
        policy_asset,
        supplied_params,
        expected_contract_id,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_binary_market_creation_shared(
    creation_transaction: Arc<Transaction>,
    position: ChainPosition,
    anchor: ChainAnchor,
    network: LiquidNetwork,
    policy_asset: AssetId,
    supplied_params: Option<BinaryMarketParams>,
    expected_contract_id: Option<ContractId>,
) -> Result<VerifiedRegistration, RegistrationError> {
    let transaction = creation_transaction.as_ref();
    let hints = market_hints(transaction, policy_asset);
    let (params, official_shape) = match supplied_params {
        Some(params) => {
            let yes_input = unique_defining_input(
                transaction,
                params.yes_token_asset_id,
                params.yes_reissuance_token_id,
            )?;
            let no_input = unique_defining_input(
                transaction,
                params.no_token_asset_id,
                params.no_reissuance_token_id,
            )?;
            if yes_input == no_input {
                return Err(RegistrationError::InvalidCreation(
                    "YES and NO resolve to the same defining issuance".to_owned(),
                ));
            }
            (params, false)
        }
        None => {
            if hints.len() != 1 {
                return Err(RegistrationError::InvalidCreation(
                    "automatic market recovery requires exactly one canonical market hint"
                        .to_owned(),
                ));
            }
            if transaction.input.len() < 2 || transaction.output.len() < 2 {
                return Err(RegistrationError::InvalidCreation(
                    "standalone market creation is missing its fixed inputs or outputs".to_owned(),
                ));
            }
            if !is_canonical_new_issuance(&transaction.input[0])
                || !is_canonical_new_issuance(&transaction.input[1])
                || transaction.input[2..]
                    .iter()
                    .any(elements::TxIn::has_issuance)
            {
                return Err(RegistrationError::InvalidCreation(
                    "standalone market issuance shape is not canonical".to_owned(),
                ));
            }
            let yes_input = 0;
            let no_input = 1;
            let assets = derive_issuance_assets(
                transaction.input[yes_input].previous_output,
                transaction.input[no_input].previous_output,
            );
            let hint = hints[0].1;
            let params = BinaryMarketParams {
                oracle_public_key: hint.oracle_public_key,
                collateral_asset_id: resolve_collateral(hint.collateral, network, policy_asset)?,
                yes_token_asset_id: assets.yes_token,
                no_token_asset_id: assets.no_token,
                yes_reissuance_token_id: assets.yes_reissuance_token,
                no_reissuance_token_id: assets.no_reissuance_token,
                base_payout: hint.base_payout,
                expiry_height: hint.expiry_height,
            };
            (params, true)
        }
    };

    let compiled = CompiledBinaryMarket::new(params)?;
    // Canonical lineage always starts with both RT legs on side A.
    let yes_commitments = commitments(
        params.yes_reissuance_token_id,
        factors(RtLeg::Yes, RtSide::A),
    )
    .map_err(|error| RegistrationError::InvalidCreation(error.to_string()))?;
    let no_commitments = commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
        .map_err(|error| RegistrationError::InvalidCreation(error.to_string()))?;

    let yes_output = unique_market_output(
        transaction,
        compiled
            .slot(BinaryMarketSlot::DormantYesRt)
            .script_pubkey(),
        yes_commitments,
    )?;
    let no_output = unique_market_output(
        transaction,
        compiled.slot(BinaryMarketSlot::DormantNoRt).script_pubkey(),
        no_commitments,
    )?;
    if official_shape && (yes_output != 0 || no_output != 1) {
        return Err(RegistrationError::InvalidCreation(
            "standalone market RT outputs are not at vout 0 and 1".to_owned(),
        ));
    }

    let matching_hints = hints
        .iter()
        .filter(|(_, hint)| market_hint_matches(*hint, params, network, policy_asset))
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();
    if supplied_params.is_none() && matching_hints.len() != 1 {
        return Err(RegistrationError::InvalidCreation(
            "standalone recovery hint does not match the derived market".to_owned(),
        ));
    }

    let txid = transaction.txid();
    let creation_anchor = OutPoint::new(txid, yes_output);
    if expected_contract_id
        .is_some_and(|contract_id| contract_id.creation_anchor() != creation_anchor)
    {
        return Err(RegistrationError::InvalidCreation(
            "market ContractId does not nominate its initial dormant YES RT output".to_owned(),
        ));
    }
    let contract_id = expected_contract_id.unwrap_or_else(|| ContractId::new(creation_anchor));
    let scripts = compiled
        .slots()
        .iter()
        .map(|slot| ScriptBinding {
            role: slot.slot() as u8,
            script_pubkey: slot.script_pubkey().as_bytes().to_vec(),
        })
        .collect();
    let record = ContractRecord {
        contract_id,
        kind: ContractKind::BinaryMarketV1,
        params: ContractParameters::BinaryMarket(params),
        creation_position: position,
        state: ContractState::BinaryMarket(BinaryMarketState::Trading {
            outstanding_pairs: 0,
        }),
        sync_state: ContractSyncState::CatchingUp {
            synced_through: anchor,
        },
        scripts,
        assets: vec![
            AssetBinding {
                asset_id: params.collateral_asset_id,
                relation: AssetRelationKind::Collateral,
                role: BinaryMarketSlot::UnresolvedCollateral as u8,
            },
            AssetBinding {
                asset_id: params.yes_token_asset_id,
                relation: AssetRelationKind::YesToken,
                role: 0,
            },
            AssetBinding {
                asset_id: params.no_token_asset_id,
                relation: AssetRelationKind::NoToken,
                role: 1,
            },
            AssetBinding {
                asset_id: params.yes_reissuance_token_id,
                relation: AssetRelationKind::YesReissuanceToken,
                role: BinaryMarketSlot::DormantYesRt as u8,
            },
            AssetBinding {
                asset_id: params.no_reissuance_token_id,
                relation: AssetRelationKind::NoReissuanceToken,
                role: BinaryMarketSlot::DormantNoRt as u8,
            },
        ],
        outpoints: vec![
            TrackedOutpoint {
                role: BinaryMarketSlot::DormantYesRt as u8,
                outpoint: OutPoint::new(txid, yes_output),
            },
            TrackedOutpoint {
                role: BinaryMarketSlot::DormantNoRt as u8,
                outpoint: OutPoint::new(txid, no_output),
            },
        ],
    };
    Ok(VerifiedRegistration {
        record,
        creation_block_anchor: anchor,
        creation_transaction,
        associated_hint: (matching_hints.len() == 1).then(|| RecoveryHintLocation {
            position,
            output_index: matching_hints[0],
        }),
    })
}

fn unique_defining_input(
    transaction: &Transaction,
    expected_asset: AssetId,
    expected_rt: AssetId,
) -> Result<usize, RegistrationError> {
    let matches = transaction
        .input
        .iter()
        .enumerate()
        .filter(|(_, input)| {
            is_canonical_new_issuance(input)
                && input.issuance_ids() == (expected_asset, expected_rt)
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => Ok(*index),
        _ => Err(RegistrationError::InvalidCreation(format!(
            "expected one defining issuance for {expected_asset}, found {}",
            matches.len()
        ))),
    }
}

fn is_canonical_new_issuance(input: &elements::TxIn) -> bool {
    input.has_issuance()
        && input.asset_issuance.asset_blinding_nonce == ZERO_TWEAK
        && input.asset_issuance.asset_entropy == [0; 32]
        && input.asset_issuance.amount == Value::Null
        && input.asset_issuance.inflation_keys == Value::Explicit(1)
}

fn unique_market_output(
    transaction: &Transaction,
    expected_script: &elements::Script,
    expected_commitments: (Asset, Value),
) -> Result<u32, RegistrationError> {
    let matches = transaction
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| {
            output.script_pubkey == *expected_script
                && output.asset == expected_commitments.0
                && output.value == expected_commitments.1
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [index] => u32::try_from(*index)
            .map_err(|_| RegistrationError::InvalidCreation("output index exceeds u32".to_owned())),
        _ => Err(RegistrationError::InvalidCreation(format!(
            "expected one deterministic dormant RT output, found {}",
            matches.len()
        ))),
    }
}

fn market_hints(
    transaction: &Transaction,
    policy_asset: AssetId,
) -> Vec<(u32, MarketRecoveryHint)> {
    transaction
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            let payload = validate_recovery_txout(output, policy_asset).ok()?;
            if payload.first() != Some(&MARKET_V1_TAG) {
                return None;
            }
            let hint = MarketRecoveryHint::decode(payload).ok()?;
            Some((u32::try_from(index).ok()?, hint))
        })
        .collect()
}

fn market_hint_matches(
    hint: MarketRecoveryHint,
    params: BinaryMarketParams,
    network: LiquidNetwork,
    policy_asset: AssetId,
) -> bool {
    hint.oracle_public_key == params.oracle_public_key
        && hint.base_payout == params.base_payout
        && hint.expiry_height == params.expiry_height
        && resolve_collateral(hint.collateral, network, policy_asset)
            .is_ok_and(|asset| asset == params.collateral_asset_id)
}

fn resolve_collateral(
    collateral: MarketCollateral,
    network: LiquidNetwork,
    policy_asset: AssetId,
) -> Result<AssetId, RegistrationError> {
    match collateral {
        MarketCollateral::PolicyAsset => Ok(policy_asset),
        MarketCollateral::Asset(asset) => Ok(asset),
        MarketCollateral::LiquidMainnetUsdt if network == LiquidNetwork::Liquid => {
            AssetId::from_str(LIQUID_MAINNET_USDT).map_err(|error| {
                RegistrationError::InvalidCreation(format!("invalid built-in USDt asset: {error}"))
            })
        }
        MarketCollateral::LiquidMainnetUsdt => Err(RegistrationError::InvalidCreation(
            "Liquid-mainnet USDt hint used on another network".to_owned(),
        )),
    }
}

#[derive(Debug, Error)]
pub enum RegistrationError {
    #[error("chain source error: {0}")]
    Chain(#[from] ChainSourceError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("creation transaction is not confirmed")]
    UnconfirmedCreation,
    #[error("contract creation {creation:?} is not after v1 activation checkpoint {activation:?}")]
    PreActivationCreation {
        creation: ChainAnchor,
        activation: ChainAnchor,
    },
    #[error("contract package targets a different Liquid chain")]
    WrongChain,
    #[error("invalid contract package: {0}")]
    InvalidPackage(String),
    #[error("contract compilation failed: {0}")]
    Compilation(#[from] CompiledBinaryMarketError),
    #[error("invalid contract creation: {0}")]
    InvalidCreation(String),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deadcat_contracts::recovery::recovery_txout;
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::{
        AssetIssuance, Block, BlockHash, LockTime, OutPoint, Script, Transaction, TxIn, TxOut,
        TxOutWitness, Txid,
    };

    use super::*;

    const VALID_XONLY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn anchor(height: u32, byte: u8) -> ChainAnchor {
        ChainAnchor {
            height,
            hash: BlockHash::from_byte_array([byte; 32]),
        }
    }

    fn issuance_input(byte: u8, vout: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([byte; 32]), vout),
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: ZERO_TWEAK,
                asset_entropy: [0; 32],
                amount: Value::Null,
                inflation_keys: Value::Explicit(1),
            },
            ..TxIn::default()
        }
    }

    fn standalone_market(
        policy_asset: AssetId,
    ) -> (Transaction, BinaryMarketParams, ChainPosition, ChainAnchor) {
        let yes_input = issuance_input(0x11, 3);
        let no_input = issuance_input(0x22, 4);
        let ids = derive_issuance_assets(yes_input.previous_output, no_input.previous_output);
        let params = BinaryMarketParams {
            oracle_public_key: VALID_XONLY,
            collateral_asset_id: policy_asset,
            yes_token_asset_id: ids.yes_token,
            no_token_asset_id: ids.no_token,
            yes_reissuance_token_id: ids.yes_reissuance_token,
            no_reissuance_token_id: ids.no_reissuance_token,
            base_payout: 1_000,
            expiry_height: 50_000,
        };
        let compiled = CompiledBinaryMarket::new(params).expect("compile market");
        let yes_commitments = commitments(
            params.yes_reissuance_token_id,
            factors(RtLeg::Yes, RtSide::A),
        )
        .expect("YES commitments");
        let no_commitments =
            commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
                .expect("NO commitments");
        let hint = MarketRecoveryHint {
            oracle_public_key: params.oracle_public_key,
            collateral: MarketCollateral::PolicyAsset,
            base_payout: params.base_payout,
            expiry_height: params.expiry_height,
        }
        .encode()
        .expect("hint");
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![yes_input, no_input],
            output: vec![
                TxOut {
                    asset: yes_commitments.0,
                    value: yes_commitments.1,
                    nonce: Nonce::Null,
                    script_pubkey: compiled
                        .slot(BinaryMarketSlot::DormantYesRt)
                        .script_pubkey()
                        .clone(),
                    witness: TxOutWitness::default(),
                },
                TxOut {
                    asset: no_commitments.0,
                    value: no_commitments.1,
                    nonce: Nonce::Null,
                    script_pubkey: compiled
                        .slot(BinaryMarketSlot::DormantNoRt)
                        .script_pubkey()
                        .clone(),
                    witness: TxOutWitness::default(),
                },
                recovery_txout(policy_asset, &hint).expect("recovery output"),
            ],
        };
        let position = ChainPosition {
            block_height: 100,
            tx_index: 2,
        };
        (transaction, params, position, anchor(100, 0x55))
    }

    fn declared_market_outputs(policy_asset: AssetId, params: BinaryMarketParams) -> [TxOut; 3] {
        let compiled = CompiledBinaryMarket::new(params).expect("compile declared market");
        let yes_commitments = commitments(
            params.yes_reissuance_token_id,
            factors(RtLeg::Yes, RtSide::A),
        )
        .expect("declared YES commitments");
        let no_commitments =
            commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
                .expect("declared NO commitments");
        let hint = MarketRecoveryHint {
            oracle_public_key: params.oracle_public_key,
            collateral: MarketCollateral::PolicyAsset,
            base_payout: params.base_payout,
            expiry_height: params.expiry_height,
        }
        .encode()
        .expect("declared market hint");

        [
            TxOut {
                asset: yes_commitments.0,
                value: yes_commitments.1,
                nonce: Nonce::Null,
                script_pubkey: compiled
                    .slot(BinaryMarketSlot::DormantYesRt)
                    .script_pubkey()
                    .clone(),
                witness: TxOutWitness::default(),
            },
            TxOut {
                asset: no_commitments.0,
                value: no_commitments.1,
                nonce: Nonce::Null,
                script_pubkey: compiled
                    .slot(BinaryMarketSlot::DormantNoRt)
                    .script_pubkey()
                    .clone(),
                witness: TxOutWitness::default(),
            },
            recovery_txout(policy_asset, &hint).expect("declared market recovery output"),
        ]
    }

    struct RegistrationSource {
        transactions: BTreeMap<Txid, Transaction>,
        status: TransactionStatus,
        transaction_calls: AtomicUsize,
        status_calls: AtomicUsize,
    }

    impl RegistrationSource {
        fn new(transaction: Transaction, status: TransactionStatus) -> Self {
            Self::many(vec![transaction], status)
        }

        fn many(transactions: Vec<Transaction>, status: TransactionStatus) -> Self {
            Self {
                transactions: transactions
                    .into_iter()
                    .map(|transaction| (transaction.txid(), transaction))
                    .collect(),
                status,
                transaction_calls: AtomicUsize::new(0),
                status_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl ChainSource for RegistrationSource {
        async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn block_hash(&self, _height: u32) -> Result<BlockHash, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn block(&self, _hash: BlockHash) -> Result<Block, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn transaction(&self, txid: Txid) -> Result<Transaction, ChainSourceError> {
            self.transaction_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self
                .transactions
                .get(&txid)
                .unwrap_or_else(|| panic!("unexpected transaction request {txid}"))
                .clone())
        }

        async fn transaction_status(
            &self,
            txid: Txid,
        ) -> Result<TransactionStatus, ChainSourceError> {
            self.status_calls.fetch_add(1, Ordering::Relaxed);
            assert!(
                self.transactions.contains_key(&txid),
                "unexpected transaction status request {txid}"
            );
            Ok(self.status)
        }

        async fn outspend(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<crate::chain::Outspend>, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn issuance_transaction(
            &self,
            _asset_id: AssetId,
        ) -> Result<Option<Txid>, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }

        async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, ChainSourceError> {
            unreachable!("registration reads only transaction evidence and status")
        }
    }

    #[test]
    fn standalone_market_is_fully_recovered_from_chain_evidence() {
        let policy_asset = asset(0x99);
        let (transaction, expected_params, position, anchor) = standalone_market(policy_asset);
        let verified = verify_binary_market_creation(
            &transaction,
            position,
            anchor,
            LiquidNetwork::ElementsRegtest,
            policy_asset,
            None,
            None,
        )
        .expect("verify");

        assert_eq!(
            verified.record.params,
            ContractParameters::BinaryMarket(expected_params)
        );
        assert_eq!(verified.record.scripts.len(), 8);
        assert_eq!(verified.record.outpoints.len(), 2);
        assert_eq!(verified.associated_hint.expect("hint").output_index, 2);

        let expected_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
        assert_eq!(
            verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                LiquidNetwork::ElementsRegtest,
                policy_asset,
                Some(expected_params),
                Some(expected_id),
            )
            .expect("exact market anchor")
            .record
            .contract_id,
            expected_id
        );
        assert!(matches!(
            verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                LiquidNetwork::ElementsRegtest,
                policy_asset,
                Some(expected_params),
                Some(ContractId::new(OutPoint::new(transaction.txid(), 1))),
            ),
            Err(RegistrationError::InvalidCreation(message))
                if message.contains("initial dormant YES RT output")
        ));
    }

    #[tokio::test]
    async fn chain_verified_market_registration_is_persisted_and_idempotent() {
        let policy_asset = asset(0x95);
        let (transaction, expected_params, position, creation_anchor) =
            standalone_market(policy_asset);
        let source = RegistrationSource::new(
            transaction.clone(),
            TransactionStatus::Confirmed {
                anchor: creation_anchor,
                tx_index: position.tx_index,
            },
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let database = directory.path().join("registration.redb");
        let store = Store::open(&database).expect("open store");
        store
            .initialize_tip(creation_anchor)
            .expect("initialize canonical tip");
        let verifier = RegistrationVerifier::new(
            &source,
            &store,
            LiquidNetwork::ElementsRegtest,
            BlockHash::all_zeros(),
            policy_asset,
        );
        let contract_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: deadcat_types::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::all_zeros(),
            },
            roots: vec![contract_id],
            declarations: vec![ContractDeclaration {
                contract_id,
                descriptor: ContractDescriptor::BinaryMarketV1 {
                    params: expected_params,
                },
            }],
        };

        let mut registrations = verifier
            .verify_and_register_package(&package)
            .await
            .expect("verify and register market");
        let (verified, inserted) = registrations.pop().expect("one registration");
        assert!(inserted);
        assert_eq!(
            verified.record.params,
            ContractParameters::BinaryMarket(expected_params)
        );
        assert_eq!(
            store
                .contract(verified.record.contract_id)
                .expect("read contract")
                .expect("persisted contract"),
            verified.record
        );
        assert_eq!(
            store.pending_backfills().expect("pending backfill").len(),
            1
        );

        let mut registrations = verifier
            .verify_and_register_package(&package)
            .await
            .expect("idempotent registration retry");
        let (_, inserted) = registrations.pop().expect("one registration");
        assert!(!inserted);
        drop(store);

        let reopened = Store::open(&database).expect("reopen store");
        assert_eq!(
            reopened
                .contract(verified.record.contract_id)
                .expect("read reopened contract")
                .expect("registration survived restart"),
            verified.record
        );
        let evidence = reopened
            .transaction(position)
            .expect("read creation evidence")
            .expect("persisted creation evidence");
        assert_eq!(
            elements::encode::deserialize::<Transaction>(&evidence.raw_tx)
                .expect("decode creation evidence"),
            transaction
        );
    }

    #[tokio::test]
    async fn reversed_same_transaction_package_registers_two_markets_atomically() {
        let policy_asset = asset(0x90);
        let first_yes_input = issuance_input(0x31, 1);
        let first_no_input = issuance_input(0x32, 2);
        let second_yes_input = issuance_input(0x41, 3);
        let second_no_input = issuance_input(0x42, 4);
        let first_ids = derive_issuance_assets(
            first_yes_input.previous_output,
            first_no_input.previous_output,
        );
        let second_ids = derive_issuance_assets(
            second_yes_input.previous_output,
            second_no_input.previous_output,
        );
        let first_params = BinaryMarketParams {
            oracle_public_key: VALID_XONLY,
            collateral_asset_id: policy_asset,
            yes_token_asset_id: first_ids.yes_token,
            no_token_asset_id: first_ids.no_token,
            yes_reissuance_token_id: first_ids.yes_reissuance_token,
            no_reissuance_token_id: first_ids.no_reissuance_token,
            base_payout: 1_000,
            expiry_height: 50_000,
        };
        let second_params = BinaryMarketParams {
            oracle_public_key: VALID_XONLY,
            collateral_asset_id: policy_asset,
            yes_token_asset_id: second_ids.yes_token,
            no_token_asset_id: second_ids.no_token,
            yes_reissuance_token_id: second_ids.yes_reissuance_token,
            no_reissuance_token_id: second_ids.no_reissuance_token,
            base_payout: 2_000,
            expiry_height: 60_000,
        };
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![
                first_yes_input,
                first_no_input,
                second_yes_input,
                second_no_input,
            ],
            output: declared_market_outputs(policy_asset, first_params)
                .into_iter()
                .chain(declared_market_outputs(policy_asset, second_params))
                .collect(),
        };
        let position = ChainPosition {
            block_height: 100,
            tx_index: 2,
        };
        let creation_anchor = anchor(100, 0x54);
        let first_market_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
        let second_market_id = ContractId::new(OutPoint::new(transaction.txid(), 3));
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: deadcat_types::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::all_zeros(),
            },
            // Deliberately reverse creation-output order. Registration receipts
            // must retain caller order even though both declarations share one
            // fetched and validated creation transaction.
            roots: vec![second_market_id, first_market_id],
            declarations: vec![
                ContractDeclaration {
                    contract_id: second_market_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 {
                        params: second_params,
                    },
                },
                ContractDeclaration {
                    contract_id: first_market_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 {
                        params: first_params,
                    },
                },
            ],
        };
        let source = RegistrationSource::new(
            transaction.clone(),
            TransactionStatus::Confirmed {
                anchor: creation_anchor,
                tx_index: position.tx_index,
            },
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let store =
            Store::open(directory.path().join("two-market-package.redb")).expect("open store");
        store
            .initialize_tip(creation_anchor)
            .expect("initialize tip");
        let verifier = RegistrationVerifier::new(
            &source,
            &store,
            LiquidNetwork::ElementsRegtest,
            BlockHash::all_zeros(),
            policy_asset,
        );

        let registrations = verifier
            .verify_and_register_package(&package)
            .await
            .expect("register two-market package");
        assert_eq!(source.transaction_calls.load(Ordering::Relaxed), 1);
        assert_eq!(source.status_calls.load(Ordering::Relaxed), 1);
        assert_eq!(registrations.len(), 2);
        assert_eq!(registrations[0].0.record.contract_id, second_market_id);
        assert_eq!(registrations[1].0.record.contract_id, first_market_id);
        assert!(Arc::ptr_eq(
            &registrations[0].0.creation_transaction,
            &registrations[1].0.creation_transaction,
        ));
        assert!(registrations.iter().all(|(_, inserted)| *inserted));
        assert!(
            store
                .contract(first_market_id)
                .expect("first market lookup")
                .is_some()
        );
        assert!(
            store
                .contract(second_market_id)
                .expect("second market lookup")
                .is_some()
        );
        assert_eq!(store.pending_backfills().expect("backfills").len(), 2);
        let evidence = store
            .transaction(position)
            .expect("creation evidence lookup")
            .expect("shared creation evidence");
        assert_eq!(
            elements::encode::deserialize::<Transaction>(&evidence.raw_tx)
                .expect("decode shared creation evidence"),
            transaction
        );
    }

    #[test]
    fn duplicate_deterministic_rt_output_is_ambiguous() {
        let policy_asset = asset(0x98);
        let (mut transaction, params, position, anchor) = standalone_market(policy_asset);
        transaction.output.push(transaction.output[0].clone());
        assert!(matches!(
            verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                LiquidNetwork::ElementsRegtest,
                policy_asset,
                Some(params),
                None,
            ),
            Err(RegistrationError::InvalidCreation(message)) if message.contains("found 2")
        ));
    }

    #[test]
    fn duplicate_advisory_hints_do_not_invalidate_a_declared_market() {
        let policy_asset = asset(0x92);
        let (mut transaction, params, position, anchor) = standalone_market(policy_asset);
        transaction.output.push(transaction.output[2].clone());

        let verified = verify_binary_market_creation(
            &transaction,
            position,
            anchor,
            LiquidNetwork::ElementsRegtest,
            policy_asset,
            Some(params),
            Some(ContractId::new(OutPoint::new(transaction.txid(), 0))),
        )
        .expect("full declaration is authoritative over hint association");
        assert_eq!(verified.associated_hint, None);
        assert!(
            verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                LiquidNetwork::ElementsRegtest,
                policy_asset,
                None,
                None,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn public_package_path_rejects_shape_and_chain_before_chain_io() {
        let policy_asset = asset(0x93);
        let (transaction, params, _, _) = standalone_market(policy_asset);
        let contract_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
        let declaration = ContractDeclaration {
            contract_id,
            descriptor: ContractDescriptor::BinaryMarketV1 { params },
        };
        let directory = tempfile::tempdir().expect("tempdir");
        let store = Store::open(directory.path().join("shape.redb")).expect("open store");
        let source = RegistrationSource::new(transaction, TransactionStatus::Unconfirmed);
        let verifier = RegistrationVerifier::new(
            &source,
            &store,
            LiquidNetwork::ElementsRegtest,
            BlockHash::all_zeros(),
            policy_asset,
        );
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: deadcat_types::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::all_zeros(),
            },
            roots: vec![contract_id],
            declarations: vec![declaration],
        };
        let mut wrong_version = package.clone();
        wrong_version.format_version = CONTRACT_PACKAGE_FORMAT_VERSION + 1;
        assert!(matches!(
            verifier.verify_package(&wrong_version).await,
            Err(RegistrationError::InvalidPackage(message))
                if message.contains("unsupported contract package format")
        ));

        let mut wrong_chain = package.clone();
        wrong_chain.chain.genesis_hash = BlockHash::from_byte_array([0x01; 32]);
        assert!(matches!(
            verifier.verify_package(&wrong_chain).await,
            Err(RegistrationError::WrongChain)
        ));

        let mut duplicate_root = package.clone();
        duplicate_root.declarations.push(ContractDeclaration {
            contract_id: ContractId::new(OutPoint::new(contract_id.txid(), 8)),
            descriptor: ContractDescriptor::BinaryMarketV1 { params },
        });
        duplicate_root.roots.push(contract_id);
        assert!(matches!(
            verifier.verify_package(&duplicate_root).await,
            Err(RegistrationError::InvalidPackage(message)) if message.contains("duplicate roots")
        ));

        let mut unknown_root = package.clone();
        unknown_root.roots[0] = ContractId::new(OutPoint::new(contract_id.txid(), 9));
        assert!(matches!(
            verifier.verify_package(&unknown_root).await,
            Err(RegistrationError::InvalidPackage(message))
                if message.contains("root must have a declaration")
        ));

        let mut unrooted = package.clone();
        unrooted.declarations.push(ContractDeclaration {
            contract_id: ContractId::new(OutPoint::new(contract_id.txid(), 8)),
            descriptor: ContractDescriptor::BinaryMarketV1 { params },
        });
        assert!(matches!(
            verifier.verify_package(&unrooted).await,
            Err(RegistrationError::InvalidPackage(message)) if message.contains("must be a root")
        ));

        let mut oversized = package;
        oversized.declarations = (0..=MAX_PACKAGE_DECLARATIONS)
            .map(|vout| ContractDeclaration {
                contract_id: ContractId::new(OutPoint::new(
                    contract_id.txid(),
                    u32::try_from(vout).expect("small vout"),
                )),
                descriptor: ContractDescriptor::BinaryMarketV1 { params },
            })
            .collect();
        assert!(matches!(
            verifier.verify_package(&oversized).await,
            Err(RegistrationError::InvalidPackage(message)) if message.contains("declarations")
        ));
        assert_eq!(source.transaction_calls.load(Ordering::Relaxed), 0);
        assert_eq!(source.status_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn public_package_path_bounds_cumulative_unique_creation_evidence_bytes() {
        let policy_asset = asset(0x91);
        let (mut first, params, position, creation_anchor) = standalone_market(policy_asset);
        let padded_output = TxOut {
            asset: Asset::Explicit(policy_asset),
            value: Value::Explicit(0),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![
                0x51;
                MAX_PACKAGE_CREATION_EVIDENCE_BYTES / 2 + 1_024
            ]),
            witness: TxOutWitness::default(),
        };
        first.output.push(padded_output);
        let mut second = first.clone();
        second.lock_time = LockTime::from_consensus(1);
        let first_bytes = elements::encode::serialize(&first).len();
        let second_bytes = elements::encode::serialize(&second).len();
        assert!(first_bytes < MAX_PACKAGE_CREATION_EVIDENCE_BYTES);
        assert!(second_bytes < MAX_PACKAGE_CREATION_EVIDENCE_BYTES);
        assert!(first_bytes + second_bytes > MAX_PACKAGE_CREATION_EVIDENCE_BYTES);
        let first_id = ContractId::new(OutPoint::new(first.txid(), 0));
        let second_id = ContractId::new(OutPoint::new(second.txid(), 0));
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: deadcat_types::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::all_zeros(),
            },
            roots: vec![first_id, second_id],
            declarations: vec![
                ContractDeclaration {
                    contract_id: first_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 { params },
                },
                ContractDeclaration {
                    contract_id: second_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 { params },
                },
            ],
        };
        let source = RegistrationSource::many(
            vec![first, second],
            TransactionStatus::Confirmed {
                anchor: creation_anchor,
                tx_index: position.tx_index,
            },
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let store = Store::open(directory.path().join("evidence-budget.redb")).expect("open store");
        let verifier = RegistrationVerifier::new(
            &source,
            &store,
            LiquidNetwork::ElementsRegtest,
            BlockHash::all_zeros(),
            policy_asset,
        );

        assert!(matches!(
            verifier.verify_package(&package).await,
            Err(RegistrationError::InvalidPackage(message))
                if message.contains("creation evidence") && message.contains("byte package budget")
        ));
        assert_eq!(source.transaction_calls.load(Ordering::Relaxed), 2);
        assert_eq!(source.status_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn market_creation_rejects_non_a_rt_side() {
        let policy_asset = asset(0x96);
        let (mut transaction, params, position, anchor) = standalone_market(policy_asset);
        let (asset, value) = commitments(
            params.yes_reissuance_token_id,
            factors(RtLeg::Yes, RtSide::B),
        )
        .expect("side-B YES commitments");
        transaction.output[0].asset = asset;
        transaction.output[0].value = value;

        assert!(matches!(
            verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                LiquidNetwork::ElementsRegtest,
                policy_asset,
                Some(params),
                None,
            ),
            Err(RegistrationError::InvalidCreation(message)) if message.contains("found 0")
        ));
    }
}
