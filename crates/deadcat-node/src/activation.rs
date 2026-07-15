//! Network-specific v1 activation checkpoints.
//!
//! A production checkpoint is the final block before Deadcat v1 contract
//! discovery begins. The first valid v1 creation height is therefore
//! `checkpoint.height + 1`.

use std::str::FromStr as _;

use deadcat_types::{ChainAnchor, LiquidNetwork};
use elements::BlockHash;
use thiserror::Error;

use crate::chain::{ChainSource, ChainSourceError};

pub const LIQUID_V1_ACTIVATION_HEIGHT: u32 = 3_974_391;
pub const LIQUID_V1_ACTIVATION_HASH: &str =
    "705d699fe1d7f9433837f5f8fec9347c2d5f25aebec5c70ce838db50db890c35";
pub const LIQUID_TESTNET_V1_ACTIVATION_HEIGHT: u32 = 2_529_866;
pub const LIQUID_TESTNET_V1_ACTIVATION_HASH: &str =
    "78fe3d5ce6a0df49e7f41adf2e20e610f34f2813dfeaaf50be869ad0e32f510e";

/// Return the immutable production checkpoint for a network.
///
/// Regtest chains are created dynamically and therefore select their own
/// checkpoint height at node initialization.
#[must_use]
pub fn production_activation_anchor(network: LiquidNetwork) -> Option<ChainAnchor> {
    let (height, hash) = match network {
        LiquidNetwork::Liquid => (LIQUID_V1_ACTIVATION_HEIGHT, LIQUID_V1_ACTIVATION_HASH),
        LiquidNetwork::LiquidTestnet => (
            LIQUID_TESTNET_V1_ACTIVATION_HEIGHT,
            LIQUID_TESTNET_V1_ACTIVATION_HASH,
        ),
        LiquidNetwork::ElementsRegtest => return None,
    };
    Some(ChainAnchor {
        height,
        hash: BlockHash::from_str(hash).expect("hard-coded activation hash is valid"),
    })
}

/// Resolve and verify the checkpoint against the configured backend.
///
/// Production anchors are immutable. `regtest_baseline_height` is accepted
/// only for a dynamically-created Elements regtest chain and defaults to its
/// genesis block.
pub async fn resolve_activation_anchor<S>(
    source: &S,
    network: LiquidNetwork,
    regtest_baseline_height: Option<u32>,
) -> Result<ChainAnchor, ActivationError>
where
    S: ChainSource,
{
    let expected = match production_activation_anchor(network) {
        Some(anchor) => {
            if regtest_baseline_height.is_some() {
                return Err(ActivationError::ProductionBaselineOverride { network });
            }
            anchor
        }
        None => {
            let height = regtest_baseline_height.unwrap_or(0);
            ChainAnchor {
                height,
                hash: source.block_hash(height).await?,
            }
        }
    };

    let tip = source.tip().await?;
    if tip.height < expected.height {
        return Err(ActivationError::CheckpointAboveTip {
            checkpoint: expected,
            tip,
        });
    }
    let actual = source.block_hash(expected.height).await?;
    if actual != expected.hash {
        return Err(ActivationError::CheckpointHashMismatch {
            network,
            height: expected.height,
            expected: expected.hash,
            actual,
        });
    }
    Ok(expected)
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ActivationError {
    #[error("chain source error: {0}")]
    ChainSource(#[from] ChainSourceError),
    #[error("--baseline-height is available only for elements-regtest, not {network:?}")]
    ProductionBaselineOverride { network: LiquidNetwork },
    #[error("activation checkpoint {checkpoint:?} is above backend tip {tip:?}")]
    CheckpointAboveTip {
        checkpoint: ChainAnchor,
        tip: ChainAnchor,
    },
    #[error(
        "activation checkpoint mismatch for {network:?} at height {height}: expected {expected}, got {actual}"
    )]
    CheckpointHashMismatch {
        network: LiquidNetwork,
        height: u32,
        expected: BlockHash,
        actual: BlockHash,
    },
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use elements::{AssetId, Block, OutPoint, Script, Transaction, Txid};

    use super::*;
    use crate::chain::{Outspend, TransactionStatus};

    #[derive(Clone, Copy)]
    struct AnchorSource {
        tip: ChainAnchor,
        checkpoint: ChainAnchor,
    }

    #[async_trait]
    impl ChainSource for AnchorSource {
        async fn tip(&self) -> Result<ChainAnchor, ChainSourceError> {
            Ok(self.tip)
        }

        async fn block_hash(&self, height: u32) -> Result<BlockHash, ChainSourceError> {
            if height == self.checkpoint.height {
                Ok(self.checkpoint.hash)
            } else {
                Err(ChainSourceError::NotFound(format!("block {height}")))
            }
        }

        async fn block(&self, _hash: BlockHash) -> Result<Block, ChainSourceError> {
            Err(unsupported())
        }

        async fn transaction(&self, _txid: Txid) -> Result<Transaction, ChainSourceError> {
            Err(unsupported())
        }

        async fn transaction_status(
            &self,
            _txid: Txid,
        ) -> Result<TransactionStatus, ChainSourceError> {
            Err(unsupported())
        }

        async fn outspend(
            &self,
            _outpoint: OutPoint,
        ) -> Result<Option<Outspend>, ChainSourceError> {
            Err(unsupported())
        }

        async fn script_history(&self, _script: &Script) -> Result<Vec<Txid>, ChainSourceError> {
            Err(unsupported())
        }

        async fn issuance_transaction(
            &self,
            _asset_id: AssetId,
        ) -> Result<Option<Txid>, ChainSourceError> {
            Err(unsupported())
        }

        async fn estimate_fee_rate(&self, _target_blocks: u16) -> Result<f64, ChainSourceError> {
            Err(unsupported())
        }

        async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, ChainSourceError> {
            Err(unsupported())
        }
    }

    fn unsupported() -> ChainSourceError {
        ChainSourceError::Unsupported("unused activation test method".to_owned())
    }

    fn hash(byte: u8) -> BlockHash {
        use elements::hashes::Hash as _;
        BlockHash::from_byte_array([byte; 32])
    }

    #[test]
    fn production_checkpoints_are_exact_and_regtest_is_dynamic() {
        assert_eq!(
            production_activation_anchor(LiquidNetwork::Liquid),
            Some(ChainAnchor {
                height: 3_974_391,
                hash: BlockHash::from_str(LIQUID_V1_ACTIVATION_HASH).expect("mainnet hash"),
            })
        );
        assert_eq!(
            production_activation_anchor(LiquidNetwork::LiquidTestnet),
            Some(ChainAnchor {
                height: 2_529_866,
                hash: BlockHash::from_str(LIQUID_TESTNET_V1_ACTIVATION_HASH).expect("testnet hash"),
            })
        );
        assert_eq!(
            production_activation_anchor(LiquidNetwork::ElementsRegtest),
            None
        );
    }

    #[tokio::test]
    async fn checkpoint_resolution_rejects_wrong_hash_tip_and_production_override() {
        let expected = production_activation_anchor(LiquidNetwork::Liquid).expect("anchor");
        let wrong = AnchorSource {
            tip: ChainAnchor {
                height: expected.height,
                hash: hash(0x22),
            },
            checkpoint: ChainAnchor {
                height: expected.height,
                hash: hash(0x22),
            },
        };
        assert!(matches!(
            resolve_activation_anchor(&wrong, LiquidNetwork::Liquid, None).await,
            Err(ActivationError::CheckpointHashMismatch { .. })
        ));
        assert!(matches!(
            resolve_activation_anchor(&wrong, LiquidNetwork::Liquid, Some(expected.height)).await,
            Err(ActivationError::ProductionBaselineOverride {
                network: LiquidNetwork::Liquid
            })
        ));

        let below = AnchorSource {
            tip: ChainAnchor {
                height: expected.height - 1,
                hash: hash(0x11),
            },
            checkpoint: expected,
        };
        assert!(matches!(
            resolve_activation_anchor(&below, LiquidNetwork::Liquid, None).await,
            Err(ActivationError::CheckpointAboveTip { .. })
        ));
    }

    #[tokio::test]
    async fn regtest_uses_the_exact_selected_dynamic_checkpoint() {
        let checkpoint = ChainAnchor {
            height: 7,
            hash: hash(0x77),
        };
        let source = AnchorSource {
            tip: ChainAnchor {
                height: 9,
                hash: hash(0x99),
            },
            checkpoint,
        };
        assert_eq!(
            resolve_activation_anchor(&source, LiquidNetwork::ElementsRegtest, Some(7))
                .await
                .expect("regtest checkpoint"),
            checkpoint
        );
    }
}
