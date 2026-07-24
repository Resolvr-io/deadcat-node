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
    use deadcat_types::{ContractId, OrderDirection, OrderSide};
    use elements::hashes::Hash as _;
    use elements::{OutPoint, Txid};

    use super::*;

    #[test]
    fn owner_recovery_unmasks_but_requires_later_script_matching() {
        let secret = [0x42; 32];
        let order_index = 17;
        let mut hint = OrderRecoveryHint {
            side: OrderSide::Yes,
            direction: OrderDirection::SellBase,
            masked_order_index: 0,
            parent_market: ContractId::new(OutPoint::new(Txid::from_byte_array([0x24; 32]), 3))
                .into(),
            price: 5_000,
            min_active_base: 100,
            maker_pubkey: [
                0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
                0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
                0xce, 0x80, 0x3a, 0xc0,
            ],
        };
        hint.masked_order_index = order_index ^ order_mask(hint, &secret);

        assert_eq!(
            recover_order_candidate_index(&hint.encode(), &secret).expect("recover"),
            order_index
        );
    }
}
