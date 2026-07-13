//! Evidence-first contract registration and creation-transaction verification.

use std::str::FromStr as _;

use deadcat_contracts::binary_market::{BinaryMarketSlot, CompiledBinaryMarket};
use deadcat_contracts::maker_order::{CompiledMakerOrder, create, validate_against_market};
use deadcat_contracts::market_crypto::derive_issuance_assets;
use deadcat_contracts::recovery::{
    MARKET_V1_TAG, MarketCollateral, MarketRecoveryHint, OrderRecoveryHint, validate_recovery_txout,
};
use deadcat_contracts::rt::{commitments, creation_factors};
use deadcat_rpc::ContractCandidate;
use deadcat_types::{
    BinaryMarketParams, BinaryMarketState, ChainAnchor, ChainPosition, ContractKind,
    ContractSyncState, DeadcatOutPoint, LiquidNetwork, MakerOrderState, OrderDirection,
    RecoveryHintLocation,
};
use elements::confidential::{Asset, Nonce, Value};
use elements::secp256k1_zkp::ZERO_TWEAK;
use elements::{AssetId, Transaction, TxOutWitness};
use thiserror::Error;

use crate::chain::{ChainSource, ChainSourceError, TransactionStatus};
use crate::store::{
    AssetBinding, AssetRelationKind, ContractParameters, ContractRecord, ContractState,
    OrderBookEntry, RegistrationEvidence, ScriptBinding, Store, StoreError, TrackedOutpoint,
};

const LIQUID_MAINNET_USDT: &str =
    "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRegistration {
    pub record: ContractRecord,
    pub creation_anchor: ChainAnchor,
    pub creation_transaction: Transaction,
    pub associated_hint: Option<RecoveryHintLocation>,
}

pub struct RegistrationVerifier<'a, S> {
    source: &'a S,
    store: &'a Store,
    network: LiquidNetwork,
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
        policy_asset: AssetId,
    ) -> Self {
        Self {
            source,
            store,
            network,
            policy_asset,
        }
    }

    pub async fn verify(
        &self,
        candidate: ContractCandidate,
    ) -> Result<VerifiedRegistration, RegistrationError> {
        let creation_txid = match &candidate {
            ContractCandidate::BinaryMarket { creation_txid, .. }
            | ContractCandidate::MakerOrder { creation_txid, .. } => *creation_txid,
        };
        let transaction = self.source.transaction(creation_txid).await?;
        let (anchor, tx_index) = match self.source.transaction_status(creation_txid).await? {
            TransactionStatus::Confirmed { anchor, tx_index } => (anchor, tx_index),
            TransactionStatus::Unconfirmed => return Err(RegistrationError::UnconfirmedCreation),
        };
        let position = ChainPosition {
            block_height: anchor.height,
            tx_index,
        };

        match candidate {
            ContractCandidate::BinaryMarket { params, .. } => verify_binary_market_creation(
                &transaction,
                position,
                anchor,
                self.network,
                self.policy_asset,
                params,
            ),
            ContractCandidate::MakerOrder {
                parent_market,
                side,
                params,
                ..
            } => {
                let parent = self
                    .store
                    .contract(parent_market)?
                    .ok_or(RegistrationError::ParentMarketNotFound)?;
                verify_maker_order_creation(
                    &transaction,
                    position,
                    anchor,
                    &parent,
                    side,
                    params,
                    self.policy_asset,
                )
            }
        }
    }

    /// Verify against canonical chain evidence and atomically persist the
    /// resulting catching-up record. An identical retry is idempotent.
    pub async fn verify_and_register(
        &self,
        candidate: ContractCandidate,
    ) -> Result<(VerifiedRegistration, bool), RegistrationError> {
        let verified = self.verify(candidate).await?;
        let inserted = self.store.register_contract(
            &verified.record,
            &RegistrationEvidence {
                anchor: verified.creation_anchor,
                transaction: verified.creation_transaction.clone(),
            },
        )?;
        Ok((verified, inserted))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_binary_market_creation(
    transaction: &Transaction,
    position: ChainPosition,
    anchor: ChainAnchor,
    network: LiquidNetwork,
    policy_asset: AssetId,
    supplied_params: Option<BinaryMarketParams>,
) -> Result<VerifiedRegistration, RegistrationError> {
    let hints = market_hints(transaction, policy_asset);
    let (params, yes_input, no_input, official_shape) = match supplied_params {
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
            (params, yes_input, no_input, false)
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
            (params, yes_input, no_input, true)
        }
    };

    let compiled = CompiledBinaryMarket::new(params)
        .map_err(|error| RegistrationError::Compilation(error.to_string()))?;
    let yes_outpoint = transaction.input[yes_input].previous_output;
    let no_outpoint = transaction.input[no_input].previous_output;
    let yes_factors = creation_factors(yes_outpoint);
    let no_factors = creation_factors(no_outpoint);
    let yes_commitments = commitments(params.yes_reissuance_token_id, yes_factors)
        .map_err(|error| RegistrationError::InvalidCreation(error.to_string()))?;
    let no_commitments = commitments(params.no_reissuance_token_id, no_factors)
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
    if matching_hints.len() > 1 {
        return Err(RegistrationError::AmbiguousRecoveryHint);
    }
    if supplied_params.is_none() && matching_hints.len() != 1 {
        return Err(RegistrationError::InvalidCreation(
            "standalone recovery hint does not match the derived market".to_owned(),
        ));
    }

    let txid = transaction.txid();
    let contract_id = compiled.contract_id(txid);
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
                outpoint: DeadcatOutPoint::new(txid, yes_output),
            },
            TrackedOutpoint {
                role: BinaryMarketSlot::DormantNoRt as u8,
                outpoint: DeadcatOutPoint::new(txid, no_output),
            },
        ],
        order_book: None,
    };
    Ok(VerifiedRegistration {
        record,
        creation_anchor: anchor,
        creation_transaction: transaction.clone(),
        associated_hint: matching_hints
            .first()
            .map(|output_index| RecoveryHintLocation {
                position,
                output_index: *output_index,
            }),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_maker_order_creation(
    transaction: &Transaction,
    position: ChainPosition,
    anchor: ChainAnchor,
    parent: &ContractRecord,
    side: deadcat_types::OrderSide,
    params: deadcat_types::MakerOrderParams,
    policy_asset: AssetId,
) -> Result<VerifiedRegistration, RegistrationError> {
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

    let matches = transaction
        .output
        .iter()
        .enumerate()
        .filter(|(_, output)| output.script_pubkey == *compiled.script_pubkey())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(RegistrationError::InvalidCreation(format!(
            "expected one canonical order output, found {}",
            matches.len()
        )));
    }
    let (output_index, output) = matches[0];
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

    let hints = order_hints(transaction, policy_asset);
    let matching_hints = hints
        .iter()
        .filter(|(_, hint)| {
            hint.market_creation_txid == parent.contract_id.creation_txid
                && hint.side == side
                && hint.direction == params.direction
                && hint.price == params.price
                && hint.min_active_base == params.min_active_base
        })
        .map(|(index, _)| *index)
        .collect::<Vec<_>>();

    let output_index = u32::try_from(output_index)
        .map_err(|_| RegistrationError::InvalidCreation("output index exceeds u32".to_owned()))?;
    let txid = transaction.txid();
    let contract_id = compiled.contract_id(txid);
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
            outpoint: DeadcatOutPoint::new(txid, output_index),
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
        creation_anchor: anchor,
        creation_transaction: transaction.clone(),
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

fn order_hints(transaction: &Transaction, policy_asset: AssetId) -> Vec<(u32, OrderRecoveryHint)> {
    transaction
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            let payload = validate_recovery_txout(output, policy_asset).ok()?;
            let hint = OrderRecoveryHint::decode(payload).ok()?;
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
    #[error("parent market is not registered")]
    ParentMarketNotFound,
    #[error("parent contract is not a binary market")]
    ParentIsNotMarket,
    #[error("contract compilation failed: {0}")]
    Compilation(String),
    #[error("invalid contract creation: {0}")]
    InvalidCreation(String),
    #[error("more than one recovery hint can be associated with this contract")]
    AmbiguousRecoveryHint,
}

#[cfg(test)]
mod tests {
    use deadcat_contracts::maker_order::CompiledMakerOrder;
    use deadcat_contracts::recovery::{OrderRecoveryHint, recovery_txout};
    use deadcat_types::{OrderDirection, OrderSide};
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::{
        AssetIssuance, BlockHash, LockTime, OutPoint, Transaction, TxIn, TxOut, TxOutWitness, Txid,
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
            creation_factors(yes_input.previous_output),
        )
        .expect("YES commitments");
        let no_commitments = commitments(
            params.no_reissuance_token_id,
            creation_factors(no_input.previous_output),
        )
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
        )
        .expect("verify");

        assert_eq!(
            verified.record.params,
            ContractParameters::BinaryMarket(expected_params)
        );
        assert_eq!(verified.record.scripts.len(), 8);
        assert_eq!(verified.record.outpoints.len(), 2);
        assert_eq!(verified.associated_hint.expect("hint").output_index, 2);
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
            ),
            Err(RegistrationError::InvalidCreation(message)) if message.contains("found 2")
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
            market_creation_txid: parent.contract_id.creation_txid,
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
            &parent,
            OrderSide::Yes,
            params,
            policy_asset,
        )
        .expect("verify order");
        assert_eq!(
            verified.record.state,
            ContractState::MakerOrder(MakerOrderState::Active {
                remaining_base: 20,
                total_filled_base: 0,
            })
        );
        assert_eq!(verified.associated_hint.expect("hint").output_index, 1);
    }
}
