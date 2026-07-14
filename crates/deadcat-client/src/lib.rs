//! Transport-free client verification and construction logic.

pub mod keys;
pub mod maker_builder;
pub mod market_builder;
pub mod validation;

mod simplicity;

use deadcat_contracts::recovery::{OrderRecoveryHint, RecoveryError};
use thiserror::Error;

/// Recover the candidate maker derivation index from a public order hint.
///
/// The caller must still derive and compile the order and match its creation
/// output. XOR unmasking alone is not an ownership proof.
pub fn recover_order_candidate_index(
    payload: &[u8],
    deadcat_secret_key: &[u8; 32],
) -> Result<u16, ClientError> {
    let hint = OrderRecoveryHint::decode(payload)?;
    Ok(hint.unmask_index(deadcat_secret_key))
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("invalid recovery hint: {0}")]
    Recovery(#[from] RecoveryError),
}

#[cfg(test)]
mod tests {
    use deadcat_contracts::recovery::{OrderRecoveryHint, order_mask};
    use deadcat_types::{OrderDirection, OrderSide};
    use elements::Txid;
    use elements::hashes::Hash as _;

    use super::*;

    #[test]
    fn owner_recovery_unmasks_but_requires_later_script_matching() {
        let secret = [0x42; 32];
        let order_index = 17;
        let mut hint = OrderRecoveryHint {
            side: OrderSide::Yes,
            direction: OrderDirection::SellBase,
            masked_order_index: 0,
            market_creation_txid: Txid::from_byte_array([0x24; 32]),
            price: 5_000,
            min_active_base: 100,
        };
        hint.masked_order_index = order_index ^ order_mask(hint, &secret);

        assert_eq!(
            recover_order_candidate_index(&hint.encode(), &secret).expect("recover"),
            order_index
        );
    }
}
