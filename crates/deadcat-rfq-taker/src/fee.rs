//! Conservative launch-time network-fee selection for authenticated RFQ quotes.
//!
//! The selector deliberately prices the quote's *maximum* permitted transaction
//! weight, rather than attempting to predict the final blinded transaction's
//! exact size. Regular vsize is an upper bound for both fee metrics supported by
//! the RFQ protocol because discounted weight cannot exceed regular weight. This
//! trades fee precision for a guaranteed provider and local fee-rate floor.
//! The provider's maximum weight is a safety ceiling, not a prediction of the
//! realized transaction size, so this launch policy can materially overpay
//! when that ceiling is broad. The user's absolute fee cap bounds that cost;
//! callers should surface the planned fee, and a future shape-aware planner can
//! tighten it without weakening final whole-transaction validation.
//!
//! This is only the initial fee choice. Exact validation of the complete blinded
//! PSET remains mandatory defense-in-depth before the taker signs: it enforces
//! the provider's selected size metric against the transaction that will
//! actually be broadcast and catches any composition or proof-size surprises.

use std::error::Error;
use std::fmt;

use deadcat_client::composition::NetworkFee;
use deadcat_rfq_rpc::{FirmQuoteValidationError, VerifiedFirmQuote};

const WEIGHT_UNITS_PER_VBYTE: u64 = 4;
const SATS_PER_KVB: u128 = 1_000;

/// Select a policy-asset network fee for an authenticated firm quote.
///
/// `local_minimum_sats_per_kvb` is the greater of any caller and chain-backend
/// fee-rate requirements. `maximum_network_fee` is the user's absolute
/// authorization and is never exceeded. The resulting fee honors the
/// provider's absolute floor and the greater of its rate floor and the local
/// rate, priced over `ceil(maximum_transaction_weight / 4)` virtual bytes.
///
/// The quote is structurally revalidated even though [`VerifiedFirmQuote`] is
/// already an authentication capability. This keeps the arithmetic boundary
/// fail-closed if that upstream invariant changes in the future.
pub fn plan_network_fee(
    quote: &VerifiedFirmQuote,
    local_minimum_sats_per_kvb: u64,
    maximum_network_fee: u64,
) -> Result<NetworkFee, FeePlanningError> {
    quote
        .quote()
        .validate_structure()
        .map_err(FeePlanningError::InvalidQuote)?;

    let policy = quote.quote().fee_policy;
    let amount = planned_amount(
        FeeBounds {
            provider_minimum_sats_per_kvb: policy.minimum_sats_per_kvb,
            provider_minimum_absolute_fee: policy.minimum_absolute_fee,
            maximum_transaction_weight: policy.maximum_transaction_weight,
        },
        local_minimum_sats_per_kvb,
        maximum_network_fee,
    )?;

    NetworkFee::new(policy.policy_asset, amount).map_err(|_| FeePlanningError::InvalidPlannedFee)
}

/// Fail-closed errors from conservative fee selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeePlanningError {
    /// The supposedly authenticated quote no longer satisfies the wire-level
    /// structural invariants used by fee planning.
    InvalidQuote(FirmQuoteValidationError),
    /// A zero local rate would silently disable the caller/backend fee policy.
    ZeroLocalFeeRate,
    /// A checked size or fee calculation could not be represented.
    ArithmeticOverflow,
    /// The conservative required fee exceeds the user's absolute authorization.
    MaximumNetworkFeeExceeded { maximum: u64, required: u64 },
    /// The calculated amount could not form a valid network fee.
    InvalidPlannedFee,
}

impl fmt::Display for FeePlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQuote(error) => write!(formatter, "invalid firm quote: {error}"),
            Self::ZeroLocalFeeRate => formatter.write_str("local minimum fee rate must be nonzero"),
            Self::ArithmeticOverflow => {
                formatter.write_str("conservative network-fee calculation overflowed")
            }
            Self::MaximumNetworkFeeExceeded { maximum, required } => write!(
                formatter,
                "required network fee {required} exceeds user maximum {maximum}"
            ),
            Self::InvalidPlannedFee => {
                formatter.write_str("conservative calculation produced an invalid network fee")
            }
        }
    }
}

impl Error for FeePlanningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidQuote(error) => Some(error),
            Self::ZeroLocalFeeRate
            | Self::ArithmeticOverflow
            | Self::MaximumNetworkFeeExceeded { .. }
            | Self::InvalidPlannedFee => None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FeeBounds {
    provider_minimum_sats_per_kvb: u64,
    provider_minimum_absolute_fee: u64,
    maximum_transaction_weight: u64,
}

fn planned_amount(
    bounds: FeeBounds,
    local_minimum_sats_per_kvb: u64,
    maximum_network_fee: u64,
) -> Result<u64, FeePlanningError> {
    if local_minimum_sats_per_kvb == 0 {
        return Err(FeePlanningError::ZeroLocalFeeRate);
    }

    let maximum_vbytes = checked_ceil_div(
        u128::from(bounds.maximum_transaction_weight),
        u128::from(WEIGHT_UNITS_PER_VBYTE),
    )?;
    let selected_rate = bounds
        .provider_minimum_sats_per_kvb
        .max(local_minimum_sats_per_kvb);
    let rate_numerator = u128::from(selected_rate)
        .checked_mul(maximum_vbytes)
        .ok_or(FeePlanningError::ArithmeticOverflow)?;
    let rate_fee = checked_ceil_div(rate_numerator, SATS_PER_KVB)?;
    let rate_fee = u64::try_from(rate_fee).map_err(|_| FeePlanningError::ArithmeticOverflow)?;
    let required = bounds.provider_minimum_absolute_fee.max(rate_fee);

    if required > maximum_network_fee {
        return Err(FeePlanningError::MaximumNetworkFeeExceeded {
            maximum: maximum_network_fee,
            required,
        });
    }
    if required == 0 {
        return Err(FeePlanningError::InvalidPlannedFee);
    }

    Ok(required)
}

fn checked_ceil_div(numerator: u128, denominator: u128) -> Result<u128, FeePlanningError> {
    if denominator == 0 {
        return Err(FeePlanningError::ArithmeticOverflow);
    }
    let quotient = numerator / denominator;
    if numerator % denominator == 0 {
        Ok(quotient)
    } else {
        quotient
            .checked_add(1)
            .ok_or(FeePlanningError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(provider_rate: u64, provider_absolute: u64, maximum_weight: u64) -> FeeBounds {
        FeeBounds {
            provider_minimum_sats_per_kvb: provider_rate,
            provider_minimum_absolute_fee: provider_absolute,
            maximum_transaction_weight: maximum_weight,
        }
    }

    #[test]
    fn uses_local_rate_when_it_is_higher_and_rounds_both_boundaries_up() {
        // 4,001 weight units conservatively become 1,001 vbytes, then
        // ceil(101 sats/kvB * 1,001 vbytes / 1,000) is 102 sats.
        assert_eq!(planned_amount(bounds(100, 1, 4_001), 101, 102), Ok(102));
    }

    #[test]
    fn uses_provider_rate_when_it_is_higher() {
        assert_eq!(
            planned_amount(bounds(2_000, 1, 4_000), 1_000, 2_000),
            Ok(2_000)
        );
    }

    #[test]
    fn provider_absolute_floor_dominates_rate_floor() {
        assert_eq!(
            planned_amount(bounds(100, 5_000, 4_000), 200, 5_000),
            Ok(5_000)
        );
    }

    #[test]
    fn fee_equal_to_user_maximum_is_allowed() {
        assert_eq!(
            planned_amount(bounds(1_000, 1, 4_000), 1_000, 1_000),
            Ok(1_000)
        );
    }

    #[test]
    fn rejects_fee_above_user_maximum() {
        assert_eq!(
            planned_amount(bounds(1_000, 1, 4_001), 1_000, 1_000),
            Err(FeePlanningError::MaximumNetworkFeeExceeded {
                maximum: 1_000,
                required: 1_001,
            })
        );
    }

    #[test]
    fn rejects_zero_local_rate_even_with_a_provider_floor() {
        assert_eq!(
            planned_amount(bounds(1_000, 1, 4_000), 0, u64::MAX),
            Err(FeePlanningError::ZeroLocalFeeRate)
        );
    }

    #[test]
    fn rejects_unrepresentable_required_fee() {
        assert_eq!(
            planned_amount(bounds(u64::MAX, 1, u64::MAX), u64::MAX, u64::MAX),
            Err(FeePlanningError::ArithmeticOverflow)
        );
    }

    #[test]
    fn checked_ceiling_division_handles_the_largest_numerator() {
        assert_eq!(checked_ceil_div(u128::MAX, u128::MAX), Ok(1));
        assert_eq!(checked_ceil_div(u128::MAX, 2), Ok((u128::MAX / 2) + 1));
    }
}
