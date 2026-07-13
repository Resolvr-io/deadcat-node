//! Recovery-hint scanning. Hints identify candidates; compilation confirms them.

use deadcat_contracts::recovery::{
    MARKET_V1_TAG, MarketCollateral, MarketRecoveryHint, ORDER_NO_SELL_BASE_V1_TAG,
    ORDER_NO_SELL_QUOTE_V1_TAG, ORDER_YES_SELL_BASE_V1_TAG, ORDER_YES_SELL_QUOTE_V1_TAG,
    OrderRecoveryHint, parse_recovery_script, validate_recovery_txout,
};
use deadcat_rpc::RecoveryFamily;
use deadcat_types::{ChainPosition, LiquidNetwork, RecoveryHintLocation};
use elements::{AssetId, Transaction, Txid};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryHintCandidate {
    pub location: RecoveryHintLocation,
    pub creation_txid: Txid,
    pub family: RecoveryFamily,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RejectedRecoveryHint {
    pub output_index: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HintScanResult {
    pub candidates: Vec<RecoveryHintCandidate>,
    pub rejected: Vec<RejectedRecoveryHint>,
}

/// Scan one confirmed transaction without treating untrusted hint failures as
/// block-processing failures.
#[must_use]
pub fn scan_transaction_hints(
    transaction: &Transaction,
    position: ChainPosition,
    network: LiquidNetwork,
    policy_asset: AssetId,
) -> HintScanResult {
    let mut result = HintScanResult::default();
    let txid = transaction.txid();

    for (index, output) in transaction.output.iter().enumerate() {
        let Ok(payload) = parse_recovery_script(&output.script_pubkey) else {
            continue;
        };
        let Some(family) = recognized_family(payload.first().copied()) else {
            continue;
        };
        let output_index = u32::try_from(index).expect("Elements output count fits u32");

        let validation = validate_recovery_txout(output, policy_asset)
            .map(|_| ())
            .map_err(|error| error.to_string())
            .and_then(|()| match family {
                RecoveryFamily::BinaryMarketV1 => {
                    let hint =
                        MarketRecoveryHint::decode(payload).map_err(|error| error.to_string())?;
                    if hint.collateral == MarketCollateral::LiquidMainnetUsdt
                        && network != LiquidNetwork::Liquid
                    {
                        return Err("Liquid-mainnet USDt hint used on another network".to_owned());
                    }
                    Ok(())
                }
                RecoveryFamily::MakerOrderV1 => OrderRecoveryHint::decode(payload)
                    .map(|_| ())
                    .map_err(|error| error.to_string()),
            });

        match validation {
            Ok(()) => result.candidates.push(RecoveryHintCandidate {
                location: RecoveryHintLocation {
                    position,
                    output_index,
                },
                creation_txid: txid,
                family,
                payload: payload.to_vec(),
            }),
            Err(error) => result.rejected.push(RejectedRecoveryHint {
                output_index,
                reason: error,
            }),
        }
    }

    result
}

fn recognized_family(tag: Option<u8>) -> Option<RecoveryFamily> {
    match tag? {
        MARKET_V1_TAG => Some(RecoveryFamily::BinaryMarketV1),
        ORDER_YES_SELL_BASE_V1_TAG
        | ORDER_YES_SELL_QUOTE_V1_TAG
        | ORDER_NO_SELL_BASE_V1_TAG
        | ORDER_NO_SELL_QUOTE_V1_TAG => Some(RecoveryFamily::MakerOrderV1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use deadcat_contracts::recovery::{MarketRecoveryHint, recovery_txout};
    use elements::{LockTime, Script, TxOut};

    use super::*;

    fn tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    #[test]
    fn finds_valid_hint_and_ignores_unrelated_op_return() {
        let policy = AssetId::from_slice(&[0x11; 32]).expect("asset");
        let payload = MarketRecoveryHint {
            oracle_public_key: [0x22; 32],
            collateral: MarketCollateral::PolicyAsset,
            base_payout: 1_000,
            expiry_height: 100,
        }
        .encode()
        .expect("hint");
        let unrelated = TxOut {
            script_pubkey: Script::new_op_return(b"not-deadcat"),
            ..recovery_txout(policy, &payload).expect("output")
        };
        let transaction = tx(vec![
            unrelated,
            recovery_txout(policy, &payload).expect("output"),
        ]);
        let position = ChainPosition {
            block_height: 5,
            tx_index: 2,
        };

        let scan = scan_transaction_hints(
            &transaction,
            position,
            LiquidNetwork::ElementsRegtest,
            policy,
        );
        assert!(scan.rejected.is_empty());
        assert_eq!(scan.candidates.len(), 1);
        assert_eq!(scan.candidates[0].location.output_index, 1);
        assert_eq!(scan.candidates[0].family, RecoveryFamily::BinaryMarketV1);
    }

    #[test]
    fn recognized_hint_with_wrong_envelope_is_reported_not_fatal() {
        let policy = AssetId::from_slice(&[0x33; 32]).expect("asset");
        let wrong_asset = AssetId::from_slice(&[0x44; 32]).expect("asset");
        let payload = MarketRecoveryHint {
            oracle_public_key: [0x55; 32],
            collateral: MarketCollateral::PolicyAsset,
            base_payout: 1_000,
            expiry_height: 100,
        }
        .encode()
        .expect("hint");
        let transaction = tx(vec![recovery_txout(wrong_asset, &payload).expect("output")]);

        let scan = scan_transaction_hints(
            &transaction,
            ChainPosition {
                block_height: 1,
                tx_index: 0,
            },
            LiquidNetwork::ElementsRegtest,
            policy,
        );
        assert!(scan.candidates.is_empty());
        assert_eq!(scan.rejected.len(), 1);
    }
}
