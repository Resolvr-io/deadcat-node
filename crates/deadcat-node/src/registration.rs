//! Evidence-first contract registration and creation-transaction verification.

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::str::FromStr as _;
use std::sync::Arc;

use deadcat_contracts::binary_market::{BinaryMarketSlot, CompiledBinaryMarket};
use deadcat_contracts::maker_order::{CompiledMakerOrder, create, validate_against_market};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{
    MARKET_V1_TAG, MarketCollateral, MarketRecoveryHint, validate_recovery_txout,
};
use deadcat_contracts::rt::{RtLeg, RtSide, commitments, factors};
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, CONTRACT_PACKAGE_FORMAT_VERSION, ChainAnchor,
    ChainPosition, ContractDeclaration, ContractDescriptor, ContractId, ContractKind,
    ContractPackage, ContractSyncState, LiquidNetwork, MAX_CONTRACT_PACKAGE_DECLARATIONS,
    MAX_CONTRACT_PACKAGE_ROOTS, MakerOrderState, OrderDirection, RecoveryHintLocation,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{AssetId, BlockHash, OutPoint, Transaction, TxOutWitness, Txid};
use thiserror::Error;

use crate::chain::{ChainSource, ChainSourceError, TransactionStatus};
use crate::store::{
    AssetBinding, AssetRelationKind, ContractParameters, ContractRecord, ContractState,
    OrderBookEntry, RegistrationEvidence, ScriptBinding, Store, StoreError, TrackedOutpoint,
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
    /// not trusted: dependencies are resolved before their children and each
    /// creation transaction is fetched at most once.
    pub async fn verify_package(
        &self,
        package: &ContractPackage,
    ) -> Result<Vec<VerifiedRegistration>, RegistrationError> {
        let declarations = self.validate_package(package)?;
        let mut evidence = HashMap::<Txid, CreationEvidence>::new();
        let mut evidence_bytes = 0_usize;
        let mut verified = BTreeMap::<ContractId, VerifiedRegistration>::new();

        // Markets have no dependencies and are verified first regardless of
        // declaration order.
        for declaration in declarations.values().filter(|declaration| {
            matches!(
                declaration.descriptor,
                ContractDescriptor::BinaryMarketV1 { .. }
            )
        }) {
            let creation = self
                .creation_evidence(
                    declaration.contract_id.txid(),
                    &mut evidence,
                    &mut evidence_bytes,
                )
                .await?;
            let ContractDescriptor::BinaryMarketV1 { params } = declaration.descriptor else {
                unreachable!("filtered to market declarations")
            };
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

        for declaration in declarations.values().filter(|declaration| {
            matches!(
                declaration.descriptor,
                ContractDescriptor::MakerOrderV1 { .. }
            )
        }) {
            let ContractDescriptor::MakerOrderV1 {
                parent_market,
                side,
                params,
            } = declaration.descriptor
            else {
                unreachable!("filtered to maker-order declarations")
            };
            let stored_parent;
            let parent = if let Some(parent) = verified.get(&parent_market) {
                &parent.record
            } else {
                stored_parent = self
                    .store
                    .contract(parent_market)?
                    .ok_or(RegistrationError::ParentMarketNotFound)?;
                &stored_parent
            };
            let creation = self
                .creation_evidence(
                    declaration.contract_id.txid(),
                    &mut evidence,
                    &mut evidence_bytes,
                )
                .await?;
            if parent.creation_position > creation.position {
                return Err(RegistrationError::InvalidPackage(
                    "maker order precedes its parent market".to_owned(),
                ));
            }
            let registration = verify_maker_order_creation_shared(
                Arc::clone(&creation.transaction),
                creation.position,
                creation.anchor,
                declaration.contract_id,
                parent,
                side,
                params,
            )?;
            verified.insert(declaration.contract_id, registration);
        }

        // Receipts and persistence inputs retain the sender's declaration
        // order even though verification itself is dependency ordered.
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
            if declaration.descriptor.parent() == Some(declaration.contract_id) {
                return Err(RegistrationError::InvalidPackage(
                    "contract declaration depends on itself".to_owned(),
                ));
            }
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

        let mut reachable = BTreeSet::new();
        let mut pending = package.roots.clone();
        while let Some(contract_id) = pending.pop() {
            if !reachable.insert(contract_id) {
                continue;
            }
            if let Some(parent) = declarations
                .get(&contract_id)
                .and_then(|declaration| declaration.descriptor.parent())
                && declarations.contains_key(&parent)
            {
                pending.push(parent);
            }
        }
        if reachable.len() != declarations.len() {
            return Err(RegistrationError::InvalidPackage(
                "contract package contains declarations unreachable from its roots".to_owned(),
            ));
        }

        for declaration in declarations.values() {
            if let ContractDescriptor::MakerOrderV1 { parent_market, .. } = declaration.descriptor {
                if let Some(parent) = declarations.get(&parent_market) {
                    if !matches!(parent.descriptor, ContractDescriptor::BinaryMarketV1 { .. }) {
                        return Err(RegistrationError::ParentIsNotMarket);
                    }
                } else {
                    let parent = self
                        .store
                        .contract(parent_market)?
                        .ok_or(RegistrationError::ParentMarketNotFound)?;
                    if parent.kind != ContractKind::BinaryMarketV1 {
                        return Err(RegistrationError::ParentIsNotMarket);
                    }
                }
            }
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

    let compiled = CompiledBinaryMarket::new(params)
        .map_err(|error| RegistrationError::Compilation(error.to_string()))?;
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
        parent_market: None,
        outcome_side: None,
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
        order_book: None,
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

#[allow(clippy::too_many_arguments)]
pub fn verify_maker_order_creation(
    transaction: &Transaction,
    position: ChainPosition,
    anchor: ChainAnchor,
    contract_id: ContractId,
    parent: &ContractRecord,
    side: deadcat_types::OrderSide,
    params: deadcat_types::MakerOrderParams,
) -> Result<VerifiedRegistration, RegistrationError> {
    verify_maker_order_creation_shared(
        Arc::new(transaction.clone()),
        position,
        anchor,
        contract_id,
        parent,
        side,
        params,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_maker_order_creation_shared(
    creation_transaction: Arc<Transaction>,
    position: ChainPosition,
    anchor: ChainAnchor,
    contract_id: ContractId,
    parent: &ContractRecord,
    side: deadcat_types::OrderSide,
    params: deadcat_types::MakerOrderParams,
) -> Result<VerifiedRegistration, RegistrationError> {
    let transaction = creation_transaction.as_ref();
    if contract_id.txid() != transaction.txid() {
        return Err(RegistrationError::InvalidCreation(
            "maker ContractId transaction does not match its creation transaction".to_owned(),
        ));
    }
    let ContractParameters::BinaryMarket(parent_params) = &parent.params else {
        return Err(RegistrationError::ParentIsNotMarket);
    };
    let expected_base = match side {
        deadcat_types::OrderSide::Yes => parent_params.yes_token_asset_id,
        deadcat_types::OrderSide::No => parent_params.no_token_asset_id,
    };
    validate_against_market(
        params,
        expected_base,
        parent_params.collateral_asset_id,
        parent_params.collateral_per_pair().ok_or_else(|| {
            RegistrationError::InvalidCreation("invalid parent payout".to_owned())
        })?,
    )
    .map_err(|error| RegistrationError::InvalidCreation(error.to_string()))?;
    let compiled = CompiledMakerOrder::new(params)
        .map_err(|error| RegistrationError::Compilation(error.to_string()))?;

    let output = transaction
        .output
        .get(usize::try_from(contract_id.vout()).map_err(|_| {
            RegistrationError::InvalidCreation("maker output index exceeds usize".to_owned())
        })?)
        .ok_or_else(|| {
            RegistrationError::InvalidCreation(
                "maker ContractId output does not exist in the creation transaction".to_owned(),
            )
        })?;
    if output.script_pubkey != *compiled.script_pubkey() {
        return Err(RegistrationError::InvalidCreation(
            "maker ContractId output does not use the declared canonical order script".to_owned(),
        ));
    }
    if output.nonce != Nonce::Null || output.witness != TxOutWitness::default() {
        return Err(RegistrationError::InvalidCreation(
            "canonical order output has a nonce or confidential proofs".to_owned(),
        ));
    }
    let (asset, locked_amount) = match (output.asset, output.value) {
        (Asset::Explicit(asset), Value::Explicit(amount)) => (asset, amount),
        _ => {
            return Err(RegistrationError::InvalidCreation(
                "order output asset and value must be explicit".to_owned(),
            ));
        }
    };
    let expected_asset = match params.direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    if asset != expected_asset {
        return Err(RegistrationError::InvalidCreation(
            "order output holds the wrong asset".to_owned(),
        ));
    }
    let offered_base_capacity = match params.direction {
        OrderDirection::SellBase => locked_amount,
        OrderDirection::SellQuote => {
            let price = u64::from(params.price);
            if locked_amount % price != 0 {
                return Err(RegistrationError::InvalidCreation(
                    "SellQuote locked amount is not an exact multiple of price".to_owned(),
                ));
            }
            locked_amount / price
        }
    };
    let creation = create(params, offered_base_capacity)
        .map_err(|error| RegistrationError::InvalidCreation(error.to_string()))?;
    if creation.locked_amount != locked_amount {
        return Err(RegistrationError::InvalidCreation(
            "order locked amount is inconsistent with capacity".to_owned(),
        ));
    }

    let record = ContractRecord {
        contract_id,
        kind: ContractKind::MakerOrderV1,
        params: ContractParameters::MakerOrder(params),
        creation_position: position,
        state: ContractState::MakerOrder(MakerOrderState::Active {
            remaining_base: offered_base_capacity,
            total_filled_base: 0,
        }),
        sync_state: ContractSyncState::CatchingUp {
            synced_through: anchor,
        },
        parent_market: Some(parent.contract_id),
        outcome_side: Some(side),
        scripts: vec![ScriptBinding {
            role: 0,
            script_pubkey: compiled.script_pubkey().as_bytes().to_vec(),
        }],
        assets: vec![
            AssetBinding {
                asset_id: params.base_asset_id,
                relation: AssetRelationKind::OrderBase,
                role: 0,
            },
            AssetBinding {
                asset_id: params.quote_asset_id,
                relation: AssetRelationKind::OrderQuote,
                role: 1,
            },
        ],
        outpoints: vec![TrackedOutpoint {
            role: 0,
            outpoint: contract_id.creation_anchor(),
        }],
        order_book: Some(OrderBookEntry {
            market_id: parent.contract_id,
            side,
            direction: params.direction,
            price: params.price,
            creation_position: position,
            remaining_base: offered_base_capacity,
        }),
    };
    Ok(VerifiedRegistration {
        record,
        creation_block_anchor: anchor,
        creation_transaction,
        // V1 maker hints intentionally omit the maker key, receive script,
        // exact output, and parent vout. They are owner-recovery locators, not
        // a globally unique public contract association.
        associated_hint: None,
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
    #[error("contract package targets a different Liquid chain")]
    WrongChain,
    #[error("invalid contract package: {0}")]
    InvalidPackage(String),
    #[error("parent market is not registered")]
    ParentMarketNotFound,
    #[error("parent contract is not a binary market")]
    ParentIsNotMarket,
    #[error("contract compilation failed: {0}")]
    Compilation(String),
    #[error("invalid contract creation: {0}")]
    InvalidCreation(String),
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deadcat_contracts::maker_order::CompiledMakerOrder;
    use deadcat_contracts::recovery::{OrderRecoveryHint, recovery_txout};
    use deadcat_types::{OrderDirection, OrderSide};
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
    async fn reversed_same_transaction_package_registers_market_and_order_atomically() {
        let policy_asset = asset(0x94);
        let (mut transaction, market_params, position, creation_anchor) =
            standalone_market(policy_asset);
        let order_params = deadcat_types::MakerOrderParams {
            base_asset_id: market_params.yes_token_asset_id,
            quote_asset_id: market_params.collateral_asset_id,
            price: 100,
            min_active_base: 10,
            direction: OrderDirection::SellQuote,
            maker_receive_spk_hash: [0x43; 32],
            maker_pubkey: VALID_XONLY,
        };
        let compiled_order = CompiledMakerOrder::new(order_params).expect("compile order");
        let order_output = TxOut {
            asset: Asset::Explicit(order_params.quote_asset_id),
            value: Value::Explicit(2_000),
            nonce: Nonce::Null,
            script_pubkey: compiled_order.script_pubkey().clone(),
            witness: TxOutWitness::default(),
        };
        transaction.output.push(order_output.clone());
        transaction.output.push(order_output);
        let market_id = ContractId::new(OutPoint::new(transaction.txid(), 0));
        let first_order_id = ContractId::new(OutPoint::new(transaction.txid(), 3));
        let second_order_id = ContractId::new(OutPoint::new(transaction.txid(), 4));
        let package = ContractPackage {
            format_version: CONTRACT_PACKAGE_FORMAT_VERSION,
            chain: deadcat_types::ChainIdentity {
                network: LiquidNetwork::ElementsRegtest,
                genesis_hash: BlockHash::all_zeros(),
            },
            roots: vec![first_order_id, second_order_id],
            // Deliberately child-first: package order is not dependency order.
            declarations: vec![
                ContractDeclaration {
                    contract_id: first_order_id,
                    descriptor: ContractDescriptor::MakerOrderV1 {
                        parent_market: market_id,
                        side: OrderSide::Yes,
                        params: order_params,
                    },
                },
                ContractDeclaration {
                    contract_id: second_order_id,
                    descriptor: ContractDescriptor::MakerOrderV1 {
                        parent_market: market_id,
                        side: OrderSide::Yes,
                        params: order_params,
                    },
                },
                ContractDeclaration {
                    contract_id: market_id,
                    descriptor: ContractDescriptor::BinaryMarketV1 {
                        params: market_params,
                    },
                },
            ],
        };
        let source = RegistrationSource::new(
            transaction,
            TransactionStatus::Confirmed {
                anchor: creation_anchor,
                tx_index: position.tx_index,
            },
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let store = Store::open(directory.path().join("package.redb")).expect("open store");
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
            .expect("register composed package");
        assert_eq!(source.transaction_calls.load(Ordering::Relaxed), 1);
        assert_eq!(source.status_calls.load(Ordering::Relaxed), 1);
        assert_eq!(registrations.len(), 3);
        assert_eq!(registrations[0].0.record.contract_id, first_order_id);
        assert_eq!(registrations[1].0.record.contract_id, second_order_id);
        assert_eq!(registrations[2].0.record.contract_id, market_id);
        assert!(Arc::ptr_eq(
            &registrations[0].0.creation_transaction,
            &registrations[1].0.creation_transaction,
        ));
        assert!(Arc::ptr_eq(
            &registrations[1].0.creation_transaction,
            &registrations[2].0.creation_transaction,
        ));
        assert!(registrations.iter().all(|(_, inserted)| *inserted));
        assert!(store.contract(market_id).expect("market lookup").is_some());
        assert!(
            store
                .contract(first_order_id)
                .expect("first order lookup")
                .is_some()
        );
        assert!(
            store
                .contract(second_order_id)
                .expect("second order lookup")
                .is_some()
        );
        assert_eq!(store.pending_backfills().expect("backfills").len(), 3);
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

        let mut unreachable = package.clone();
        unreachable.declarations.push(ContractDeclaration {
            contract_id: ContractId::new(OutPoint::new(contract_id.txid(), 8)),
            descriptor: ContractDescriptor::BinaryMarketV1 { params },
        });
        assert!(matches!(
            verifier.verify_package(&unreachable).await,
            Err(RegistrationError::InvalidPackage(message)) if message.contains("unreachable")
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

    #[test]
    fn maker_order_registration_derives_capacity_and_parent_relation() {
        let policy_asset = asset(0x97);
        let (market_tx, _, market_position, market_anchor) = standalone_market(policy_asset);
        let parent = verify_binary_market_creation(
            &market_tx,
            market_position,
            market_anchor,
            LiquidNetwork::ElementsRegtest,
            policy_asset,
            None,
            None,
        )
        .expect("parent")
        .record;
        let ContractParameters::BinaryMarket(parent_params) = parent.params else {
            panic!("market params")
        };
        let params = deadcat_types::MakerOrderParams {
            base_asset_id: parent_params.yes_token_asset_id,
            quote_asset_id: parent_params.collateral_asset_id,
            price: 100,
            min_active_base: 10,
            direction: OrderDirection::SellQuote,
            maker_receive_spk_hash: [0x42; 32],
            maker_pubkey: VALID_XONLY,
        };
        let compiled = CompiledMakerOrder::new(params).expect("order compile");
        let hint = OrderRecoveryHint {
            side: OrderSide::Yes,
            direction: params.direction,
            masked_order_index: 0x1234,
            market_creation_txid: parent.contract_id.txid(),
            price: params.price,
            min_active_base: params.min_active_base,
        }
        .encode();
        let transaction = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![
                TxOut {
                    asset: Asset::Explicit(params.quote_asset_id),
                    value: Value::Explicit(2_000),
                    nonce: Nonce::Null,
                    script_pubkey: compiled.script_pubkey().clone(),
                    witness: TxOutWitness::default(),
                },
                recovery_txout(policy_asset, &hint).expect("hint output"),
            ],
        };
        let position = ChainPosition {
            block_height: 101,
            tx_index: 3,
        };
        let verified = verify_maker_order_creation(
            &transaction,
            position,
            anchor(101, 0x56),
            ContractId::new(OutPoint::new(transaction.txid(), 0)),
            &parent,
            OrderSide::Yes,
            params,
        )
        .expect("verify order");
        assert_eq!(
            verified.record.state,
            ContractState::MakerOrder(MakerOrderState::Active {
                remaining_base: 20,
                total_filled_base: 0,
            })
        );
        assert_eq!(verified.associated_hint, None);

        // Identity nominates an output, so byte-identical orders in the same
        // transaction remain independently addressable.
        let mut duplicated = transaction;
        duplicated.output.insert(1, duplicated.output[0].clone());
        let first = verify_maker_order_creation(
            &duplicated,
            position,
            anchor(101, 0x56),
            ContractId::new(OutPoint::new(duplicated.txid(), 0)),
            &parent,
            OrderSide::Yes,
            params,
        )
        .expect("first identical order");
        let second = verify_maker_order_creation(
            &duplicated,
            position,
            anchor(101, 0x56),
            ContractId::new(OutPoint::new(duplicated.txid(), 1)),
            &parent,
            OrderSide::Yes,
            params,
        )
        .expect("second identical order");
        assert_ne!(first.record.contract_id, second.record.contract_id);
        assert_eq!(first.record.params, second.record.params);
        assert!(
            verify_maker_order_creation(
                &duplicated,
                position,
                anchor(101, 0x56),
                ContractId::new(OutPoint::new(duplicated.txid(), 2)),
                &parent,
                OrderSide::Yes,
                params,
            )
            .is_err()
        );
    }
}
