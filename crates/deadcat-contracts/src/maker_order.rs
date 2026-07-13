//! Pure maker-order economics shared by interpretation and transaction builders.

pub use deadcat_types::MakerOrderState;
use deadcat_types::{MakerOrderParams, OrderDirection};
use thiserror::Error;

mod compiled;

pub use crate::artifacts::maker_order::MakerOrderProgram;
pub use crate::artifacts::maker_order::derived_maker_order;
pub use compiled::{CompiledMakerOrder, CompiledMakerOrderError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MakerOrderFill {
    pub filled_base: u64,
    pub maker_payment: u64,
    pub remaining_locked: Option<u64>,
    pub next_state: MakerOrderState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MakerOrderCreation {
    pub locked_amount: u64,
    pub state: MakerOrderState,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum MakerOrderError {
    #[error("base and quote assets must be distinct")]
    SameAsset,
    #[error("price must be nonzero")]
    ZeroPrice,
    #[error("minimum active base must be nonzero")]
    ZeroMinimum,
    #[error("price exceeds the parent market collateral per pair")]
    PriceAboveMarket,
    #[error("order base asset does not match its parent market side")]
    WrongBaseAsset,
    #[error("order quote asset does not match parent market collateral")]
    WrongQuoteAsset,
    #[error("offered capacity is below the active minimum")]
    CapacityBelowMinimum,
    #[error("order is not active")]
    NotActive,
    #[error("tracked input amount does not match materialized state")]
    StateInputMismatch,
    #[error("fill amount is below the active minimum")]
    FillBelowMinimum,
    #[error("partial remainder is below the active minimum")]
    RemainderBelowMinimum,
    #[error("partial remainder must be nonzero and smaller than the input")]
    InvalidRemainder,
    #[error("maker payment does not satisfy the exact-price equation")]
    WrongMakerPayment,
    #[error("checked monetary arithmetic overflowed")]
    ArithmeticOverflow,
}

/// Validate the constraints committed by the covenant itself.
pub fn validate_params(params: MakerOrderParams) -> Result<(), MakerOrderError> {
    if params.base_asset_id == params.quote_asset_id {
        return Err(MakerOrderError::SameAsset);
    }
    if params.price == 0 {
        return Err(MakerOrderError::ZeroPrice);
    }
    if params.min_active_base == 0 {
        return Err(MakerOrderError::ZeroMinimum);
    }
    Ok(())
}

/// Validate the additional relationship supplied by a verified parent market.
pub fn validate_against_market(
    params: MakerOrderParams,
    expected_base_asset: elements::AssetId,
    collateral_asset: elements::AssetId,
    collateral_per_pair: u64,
) -> Result<(), MakerOrderError> {
    validate_params(params)?;
    if params.base_asset_id != expected_base_asset {
        return Err(MakerOrderError::WrongBaseAsset);
    }
    if params.quote_asset_id != collateral_asset {
        return Err(MakerOrderError::WrongQuoteAsset);
    }
    if u64::from(params.price) > collateral_per_pair {
        return Err(MakerOrderError::PriceAboveMarket);
    }
    Ok(())
}

pub fn create(
    params: MakerOrderParams,
    offered_base_capacity: u64,
) -> Result<MakerOrderCreation, MakerOrderError> {
    validate_params(params)?;
    if offered_base_capacity < u64::from(params.min_active_base) {
        return Err(MakerOrderError::CapacityBelowMinimum);
    }
    let locked_amount = locked_for_base(params, offered_base_capacity)?;
    Ok(MakerOrderCreation {
        locked_amount,
        state: MakerOrderState::Active {
            remaining_base: offered_base_capacity,
            total_filled_base: 0,
        },
    })
}

/// Interpret one exact-price script-path fill.
///
/// `input_locked` and `maker_payment` are the explicit amounts introspected by
/// the covenant. `remainder_locked` is `None` for a full fill and the
/// witness-selected continuation amount for a partial fill.
pub fn fill(
    params: MakerOrderParams,
    state: MakerOrderState,
    input_locked: u64,
    maker_payment: u64,
    remainder_locked: Option<u64>,
) -> Result<MakerOrderFill, MakerOrderError> {
    validate_params(params)?;
    let MakerOrderState::Active {
        remaining_base,
        total_filled_base,
    } = state
    else {
        return Err(MakerOrderError::NotActive);
    };
    if input_locked != locked_for_base(params, remaining_base)? {
        return Err(MakerOrderError::StateInputMismatch);
    }

    let minimum = u64::from(params.min_active_base);
    let price = u64::from(params.price);
    let (filled_base, next_remaining_base) = match params.direction {
        OrderDirection::SellBase => match remainder_locked {
            None => (remaining_base, None),
            Some(remainder) => {
                if remainder == 0 || remainder >= input_locked {
                    return Err(MakerOrderError::InvalidRemainder);
                }
                let filled = input_locked
                    .checked_sub(remainder)
                    .ok_or(MakerOrderError::ArithmeticOverflow)?;
                (filled, Some(remainder))
            }
        },
        OrderDirection::SellQuote => {
            let filled = maker_payment;
            let quote_filled = filled
                .checked_mul(price)
                .ok_or(MakerOrderError::ArithmeticOverflow)?;
            match remainder_locked {
                None => {
                    if quote_filled != input_locked {
                        return Err(MakerOrderError::WrongMakerPayment);
                    }
                    (filled, None)
                }
                Some(remainder) => {
                    if remainder == 0 || remainder >= input_locked {
                        return Err(MakerOrderError::InvalidRemainder);
                    }
                    if quote_filled.checked_add(remainder) != Some(input_locked) {
                        return Err(MakerOrderError::WrongMakerPayment);
                    }
                    if remainder % price != 0 {
                        return Err(MakerOrderError::WrongMakerPayment);
                    }
                    (filled, Some(remainder / price))
                }
            }
        }
    };

    if filled_base < minimum {
        return Err(MakerOrderError::FillBelowMinimum);
    }
    if let Some(remainder_base) = next_remaining_base
        && remainder_base < minimum
    {
        return Err(MakerOrderError::RemainderBelowMinimum);
    }
    if filled_base > remaining_base {
        return Err(MakerOrderError::WrongMakerPayment);
    }

    let exact_payment = match params.direction {
        OrderDirection::SellBase => filled_base
            .checked_mul(price)
            .ok_or(MakerOrderError::ArithmeticOverflow)?,
        OrderDirection::SellQuote => filled_base,
    };
    if maker_payment != exact_payment {
        return Err(MakerOrderError::WrongMakerPayment);
    }

    let total_filled_base = total_filled_base
        .checked_add(filled_base)
        .ok_or(MakerOrderError::ArithmeticOverflow)?;
    let next_state = match next_remaining_base {
        Some(remaining_base) => MakerOrderState::Active {
            remaining_base,
            total_filled_base,
        },
        None => MakerOrderState::Consumed,
    };

    Ok(MakerOrderFill {
        filled_base,
        maker_payment,
        remaining_locked: remainder_locked,
        next_state,
    })
}

pub fn cancel(state: MakerOrderState) -> Result<MakerOrderState, MakerOrderError> {
    match state {
        MakerOrderState::Active { .. } => Ok(MakerOrderState::Cancelled),
        MakerOrderState::Consumed | MakerOrderState::Cancelled => Err(MakerOrderError::NotActive),
    }
}

fn locked_for_base(params: MakerOrderParams, base_capacity: u64) -> Result<u64, MakerOrderError> {
    match params.direction {
        OrderDirection::SellBase => Ok(base_capacity),
        OrderDirection::SellQuote => base_capacity
            .checked_mul(u64::from(params.price))
            .ok_or(MakerOrderError::ArithmeticOverflow),
    }
}

#[cfg(test)]
mod tests {
    use elements::AssetId;

    use super::*;

    fn params(direction: OrderDirection) -> MakerOrderParams {
        MakerOrderParams {
            base_asset_id: AssetId::from_slice(&[1; 32]).expect("base"),
            quote_asset_id: AssetId::from_slice(&[2; 32]).expect("quote"),
            price: 7,
            min_active_base: 3,
            direction,
            maker_receive_spk_hash: [3; 32],
            maker_pubkey: [4; 32],
        }
    }

    #[test]
    fn sell_base_partial_and_full_are_exact() {
        let params = params(OrderDirection::SellBase);
        let creation = create(params, 10).expect("create");
        assert_eq!(creation.locked_amount, 10);

        let partial = fill(params, creation.state, 10, 28, Some(6)).expect("partial");
        assert_eq!(partial.filled_base, 4);
        assert_eq!(partial.remaining_locked, Some(6));
        let full = fill(params, partial.next_state, 6, 42, None).expect("full");
        assert_eq!(full.next_state, MakerOrderState::Consumed);
        assert_eq!(full.filled_base, 6);
    }

    #[test]
    fn sell_quote_partial_and_full_preserve_integral_capacity() {
        let params = params(OrderDirection::SellQuote);
        let creation = create(params, 10).expect("create");
        assert_eq!(creation.locked_amount, 70);

        let partial = fill(params, creation.state, 70, 4, Some(42)).expect("partial");
        assert_eq!(
            partial.next_state,
            MakerOrderState::Active {
                remaining_base: 6,
                total_filled_base: 4,
            }
        );
        let full = fill(params, partial.next_state, 42, 6, None).expect("full");
        assert_eq!(full.next_state, MakerOrderState::Consumed);
    }

    #[test]
    fn rejects_dust_remainders_and_wrong_payments() {
        let base = params(OrderDirection::SellBase);
        let creation = create(base, 10).expect("create");
        assert_eq!(
            fill(base, creation.state, 10, 56, Some(2)),
            Err(MakerOrderError::RemainderBelowMinimum)
        );
        assert_eq!(
            fill(base, creation.state, 10, 29, Some(6)),
            Err(MakerOrderError::WrongMakerPayment)
        );

        let quote = params(OrderDirection::SellQuote);
        let creation = create(quote, 10).expect("create");
        assert_eq!(
            fill(quote, creation.state, 70, 4, Some(41)),
            Err(MakerOrderError::WrongMakerPayment)
        );
    }

    #[test]
    fn validates_parent_relationship_and_overflow() {
        let params = params(OrderDirection::SellQuote);
        assert_eq!(
            validate_against_market(params, params.base_asset_id, params.quote_asset_id, 6),
            Err(MakerOrderError::PriceAboveMarket)
        );

        let mut huge = params;
        huge.price = u32::MAX;
        assert_eq!(
            create(huge, u64::MAX),
            Err(MakerOrderError::ArithmeticOverflow)
        );
    }

    #[test]
    fn cancellation_is_terminal() {
        let state = create(params(OrderDirection::SellBase), 10)
            .expect("create")
            .state;
        assert_eq!(cancel(state), Ok(MakerOrderState::Cancelled));
        assert_eq!(
            cancel(MakerOrderState::Cancelled),
            Err(MakerOrderError::NotActive)
        );
    }
}
