//! Pure binary-market economics and materialized-state transitions.
//!
//! This module deliberately does not inspect transactions. A future interpreter
//! validates a covenant spend and converts it into a [`BinaryMarketAction`];
//! this state machine then applies the same checked arithmetic used by builders
//! and the node's materialized view.

use crate::recovery::BASE_PAYOUTS;
pub use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use thiserror::Error;

mod compiled;

pub use crate::artifacts::binary_market::BinaryMarketProgram;
pub use crate::artifacts::binary_market::derived_binary_market;
pub use compiled::{CompiledBinaryMarket, CompiledBinaryMarketError, CompiledBinaryMarketSlot};

/// Version byte stored in market slot scripts.
pub const BINARY_MARKET_STORAGE_VERSION: u8 = 0x01;

/// The eight static v1 binary-market covenant slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BinaryMarketSlot {
    DormantYesRt = 0,
    DormantNoRt = 1,
    UnresolvedYesRt = 2,
    UnresolvedNoRt = 3,
    UnresolvedCollateral = 4,
    ResolvedYesCollateral = 5,
    ResolvedNoCollateral = 6,
    ExpiredCollateral = 7,
}

impl BinaryMarketSlot {
    pub const ALL: [Self; 8] = [
        Self::DormantYesRt,
        Self::DormantNoRt,
        Self::UnresolvedYesRt,
        Self::UnresolvedNoRt,
        Self::UnresolvedCollateral,
        Self::ResolvedYesCollateral,
        Self::ResolvedNoCollateral,
        Self::ExpiredCollateral,
    ];

    /// The canonical storage word: 30 zero bytes, version, then slot tag.
    #[must_use]
    pub const fn storage_word(self) -> [u8; 32] {
        let mut word = [0_u8; 32];
        word[30] = BINARY_MARKET_STORAGE_VERSION;
        word[31] = self as u8;
        word
    }

    pub fn from_storage_word(word: [u8; 32]) -> Result<Self, BinaryMarketSlotError> {
        if word[..30] != [0_u8; 30] {
            return Err(BinaryMarketSlotError::NonzeroReservedBytes);
        }
        if word[30] != BINARY_MARKET_STORAGE_VERSION {
            return Err(BinaryMarketSlotError::UnsupportedVersion(word[30]));
        }
        match word[31] {
            0 => Ok(Self::DormantYesRt),
            1 => Ok(Self::DormantNoRt),
            2 => Ok(Self::UnresolvedYesRt),
            3 => Ok(Self::UnresolvedNoRt),
            4 => Ok(Self::UnresolvedCollateral),
            5 => Ok(Self::ResolvedYesCollateral),
            6 => Ok(Self::ResolvedNoCollateral),
            7 => Ok(Self::ExpiredCollateral),
            tag => Err(BinaryMarketSlotError::UnknownSlot(tag)),
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BinaryMarketSlotError {
    #[error("market storage word has nonzero reserved bytes")]
    NonzeroReservedBytes,
    #[error("unsupported binary-market storage version {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("unknown binary-market slot {0}")]
    UnknownSlot(u8),
}

/// YES or NO in a binary market.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryOutcome {
    Yes,
    No,
}

/// A state-changing operation after covenant-level validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryMarketAction {
    Issue { pairs: u64 },
    Cancel { pairs: u64 },
    Resolve { outcome: BinaryOutcome },
    Expire,
    Redeem { outcome: BinaryOutcome, tokens: u64 },
}

impl BinaryMarketAction {
    #[must_use]
    pub const fn kind(self) -> BinaryMarketOperation {
        match self {
            Self::Issue { .. } => BinaryMarketOperation::Issue,
            Self::Cancel { .. } => BinaryMarketOperation::Cancel,
            Self::Resolve { .. } => BinaryMarketOperation::Resolve,
            Self::Expire => BinaryMarketOperation::Expire,
            Self::Redeem { .. } => BinaryMarketOperation::Redeem,
        }
    }
}

/// Operation names used in typed failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryMarketOperation {
    Issue,
    Cancel,
    Resolve,
    Expire,
    Redeem,
}

/// Compact state discriminant used in typed failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryMarketPhase {
    Trading,
    ResolvedYes,
    ResolvedNo,
    Expired,
}

impl From<BinaryMarketState> for BinaryMarketPhase {
    fn from(state: BinaryMarketState) -> Self {
        match state {
            BinaryMarketState::Trading { .. } => Self::Trading,
            BinaryMarketState::ResolvedYes { .. } => Self::ResolvedYes,
            BinaryMarketState::ResolvedNo { .. } => Self::ResolvedNo,
            BinaryMarketState::Expired { .. } => Self::Expired,
        }
    }
}

/// Exact economic effect of an applied market operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryMarketTransition {
    Issued {
        pairs: u64,
        collateral_locked: u64,
    },
    Cancelled {
        pairs: u64,
        collateral_released: u64,
        full: bool,
    },
    Resolved {
        outcome: BinaryOutcome,
        collateral_retained: u64,
    },
    Expired {
        collateral_retained: u64,
    },
    Redeemed {
        outcome: BinaryOutcome,
        tokens: u64,
        collateral_released: u64,
        complete: bool,
    },
}

/// Old state, new state, and the exact collateral effect of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedBinaryMarketTransition {
    pub old_state: BinaryMarketState,
    pub new_state: BinaryMarketState,
    pub transition: BinaryMarketTransition,
}

/// Canonical binary-market payout arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryMarketEconomics {
    base_payout: u64,
    collateral_per_pair: u64,
}

impl BinaryMarketEconomics {
    /// Construct economics for one of the sixteen canonical v1 denominations.
    pub fn new(base_payout: u64) -> Result<Self, BinaryMarketError> {
        if !BASE_PAYOUTS.contains(&base_payout) {
            return Err(BinaryMarketError::InvalidBasePayout { base_payout });
        }
        let collateral_per_pair =
            base_payout
                .checked_mul(2)
                .ok_or(BinaryMarketError::AmountOverflow {
                    amount: base_payout,
                    unit_payout: 2,
                })?;
        Ok(Self {
            base_payout,
            collateral_per_pair,
        })
    }

    #[must_use]
    pub const fn base_payout(self) -> u64 {
        self.base_payout
    }

    #[must_use]
    pub const fn collateral_per_pair(self) -> u64 {
        self.collateral_per_pair
    }

    /// Exact collateral represented by a trading-state pair count.
    pub fn collateral_for_pairs(self, pairs: u64) -> Result<u64, BinaryMarketError> {
        checked_payout(pairs, self.collateral_per_pair)
    }

    /// Validate a materialized state against denomination-level invariants.
    pub fn validate_state(self, state: BinaryMarketState) -> Result<(), BinaryMarketError> {
        match state {
            BinaryMarketState::Trading { outstanding_pairs } => {
                self.collateral_for_pairs(outstanding_pairs)?;
            }
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed,
            }
            | BinaryMarketState::ResolvedNo {
                collateral_unredeemed,
            } => {
                if collateral_unredeemed % self.collateral_per_pair != 0 {
                    return Err(BinaryMarketError::InvalidStateAmount {
                        phase: state.into(),
                        collateral: collateral_unredeemed,
                        unit_payout: self.collateral_per_pair,
                    });
                }
            }
            BinaryMarketState::Expired {
                collateral_unredeemed,
            } => {
                if collateral_unredeemed % self.base_payout != 0 {
                    return Err(BinaryMarketError::InvalidStateAmount {
                        phase: BinaryMarketPhase::Expired,
                        collateral: collateral_unredeemed,
                        unit_payout: self.base_payout,
                    });
                }
            }
        }
        Ok(())
    }

    /// Apply one covenant-validated operation using checked arithmetic.
    pub fn apply(
        self,
        state: BinaryMarketState,
        action: BinaryMarketAction,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        self.validate_state(state)?;
        match action {
            BinaryMarketAction::Issue { pairs } => self.issue(state, pairs),
            BinaryMarketAction::Cancel { pairs } => self.cancel(state, pairs),
            BinaryMarketAction::Resolve { outcome } => self.resolve(state, outcome),
            BinaryMarketAction::Expire => self.expire(state),
            BinaryMarketAction::Redeem { outcome, tokens } => self.redeem(state, outcome, tokens),
        }
    }

    fn issue(
        self,
        state: BinaryMarketState,
        pairs: u64,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        require_nonzero(BinaryMarketOperation::Issue, pairs)?;
        let BinaryMarketState::Trading { outstanding_pairs } = state else {
            return Err(invalid_state(BinaryMarketOperation::Issue, state));
        };
        let next_pairs = outstanding_pairs.checked_add(pairs).ok_or(
            BinaryMarketError::OutstandingPairsOverflow {
                current: outstanding_pairs,
                added: pairs,
            },
        )?;
        self.collateral_for_pairs(next_pairs)?;
        let collateral_locked = self.collateral_for_pairs(pairs)?;
        Ok(AppliedBinaryMarketTransition {
            old_state: state,
            new_state: BinaryMarketState::Trading {
                outstanding_pairs: next_pairs,
            },
            transition: BinaryMarketTransition::Issued {
                pairs,
                collateral_locked,
            },
        })
    }

    fn cancel(
        self,
        state: BinaryMarketState,
        pairs: u64,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        require_nonzero(BinaryMarketOperation::Cancel, pairs)?;
        let BinaryMarketState::Trading { outstanding_pairs } = state else {
            return Err(invalid_state(BinaryMarketOperation::Cancel, state));
        };
        let remaining_pairs = outstanding_pairs.checked_sub(pairs).ok_or(
            BinaryMarketError::CancellationExceedsOutstanding {
                requested: pairs,
                outstanding: outstanding_pairs,
            },
        )?;
        self.collateral_for_pairs(remaining_pairs)?;
        let collateral_released = self.collateral_for_pairs(pairs)?;
        Ok(AppliedBinaryMarketTransition {
            old_state: state,
            new_state: BinaryMarketState::Trading {
                outstanding_pairs: remaining_pairs,
            },
            transition: BinaryMarketTransition::Cancelled {
                pairs,
                collateral_released,
                full: remaining_pairs == 0,
            },
        })
    }

    fn resolve(
        self,
        state: BinaryMarketState,
        outcome: BinaryOutcome,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        let BinaryMarketState::Trading { outstanding_pairs } = state else {
            return Err(invalid_state(BinaryMarketOperation::Resolve, state));
        };
        let collateral_retained = self.collateral_for_pairs(outstanding_pairs)?;
        let new_state = match outcome {
            BinaryOutcome::Yes => BinaryMarketState::ResolvedYes {
                collateral_unredeemed: collateral_retained,
            },
            BinaryOutcome::No => BinaryMarketState::ResolvedNo {
                collateral_unredeemed: collateral_retained,
            },
        };
        Ok(AppliedBinaryMarketTransition {
            old_state: state,
            new_state,
            transition: BinaryMarketTransition::Resolved {
                outcome,
                collateral_retained,
            },
        })
    }

    fn expire(
        self,
        state: BinaryMarketState,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        let BinaryMarketState::Trading { outstanding_pairs } = state else {
            return Err(invalid_state(BinaryMarketOperation::Expire, state));
        };
        let collateral_retained = self.collateral_for_pairs(outstanding_pairs)?;
        Ok(AppliedBinaryMarketTransition {
            old_state: state,
            new_state: BinaryMarketState::Expired {
                collateral_unredeemed: collateral_retained,
            },
            transition: BinaryMarketTransition::Expired {
                collateral_retained,
            },
        })
    }

    fn redeem(
        self,
        state: BinaryMarketState,
        outcome: BinaryOutcome,
        tokens: u64,
    ) -> Result<AppliedBinaryMarketTransition, BinaryMarketError> {
        require_nonzero(BinaryMarketOperation::Redeem, tokens)?;
        let (collateral, unit_payout, constructor) = match state {
            BinaryMarketState::ResolvedYes {
                collateral_unredeemed,
            } => {
                require_winner(BinaryOutcome::Yes, outcome)?;
                (
                    collateral_unredeemed,
                    self.collateral_per_pair,
                    TerminalStateConstructor::Yes,
                )
            }
            BinaryMarketState::ResolvedNo {
                collateral_unredeemed,
            } => {
                require_winner(BinaryOutcome::No, outcome)?;
                (
                    collateral_unredeemed,
                    self.collateral_per_pair,
                    TerminalStateConstructor::No,
                )
            }
            BinaryMarketState::Expired {
                collateral_unredeemed,
            } => (
                collateral_unredeemed,
                self.base_payout,
                TerminalStateConstructor::Expired,
            ),
            BinaryMarketState::Trading { .. } => {
                return Err(invalid_state(BinaryMarketOperation::Redeem, state));
            }
        };
        let collateral_released = checked_payout(tokens, unit_payout)?;
        let remaining = collateral.checked_sub(collateral_released).ok_or(
            BinaryMarketError::RedemptionExceedsCollateral {
                requested: collateral_released,
                available: collateral,
            },
        )?;
        Ok(AppliedBinaryMarketTransition {
            old_state: state,
            new_state: constructor.with_collateral(remaining),
            transition: BinaryMarketTransition::Redeemed {
                outcome,
                tokens,
                collateral_released,
                complete: remaining == 0,
            },
        })
    }
}

#[derive(Clone, Copy)]
enum TerminalStateConstructor {
    Yes,
    No,
    Expired,
}

impl TerminalStateConstructor {
    const fn with_collateral(self, collateral_unredeemed: u64) -> BinaryMarketState {
        match self {
            Self::Yes => BinaryMarketState::ResolvedYes {
                collateral_unredeemed,
            },
            Self::No => BinaryMarketState::ResolvedNo {
                collateral_unredeemed,
            },
            Self::Expired => BinaryMarketState::Expired {
                collateral_unredeemed,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BinaryMarketError {
    #[error("{base_payout} is not a canonical v1 base payout")]
    InvalidBasePayout { base_payout: u64 },
    #[error("{operation:?} requires a nonzero quantity")]
    ZeroQuantity { operation: BinaryMarketOperation },
    #[error("cannot apply {operation:?} while the market is {phase:?}")]
    InvalidState {
        operation: BinaryMarketOperation,
        phase: BinaryMarketPhase,
    },
    #[error("outstanding-pair addition overflows: {current} + {added}")]
    OutstandingPairsOverflow { current: u64, added: u64 },
    #[error("amount calculation overflows: {amount} * {unit_payout}")]
    AmountOverflow { amount: u64, unit_payout: u64 },
    #[error("cannot cancel {requested} pairs when only {outstanding} are outstanding")]
    CancellationExceedsOutstanding { requested: u64, outstanding: u64 },
    #[error("cannot redeem {attempted:?} tokens after {winning:?} resolution")]
    LosingOutcome {
        winning: BinaryOutcome,
        attempted: BinaryOutcome,
    },
    #[error("redemption requests {requested} collateral but only {available} remains")]
    RedemptionExceedsCollateral { requested: u64, available: u64 },
    #[error("{phase:?} collateral {collateral} is not divisible by payout unit {unit_payout}")]
    InvalidStateAmount {
        phase: BinaryMarketPhase,
        collateral: u64,
        unit_payout: u64,
    },
}

fn checked_payout(amount: u64, unit_payout: u64) -> Result<u64, BinaryMarketError> {
    amount
        .checked_mul(unit_payout)
        .ok_or(BinaryMarketError::AmountOverflow {
            amount,
            unit_payout,
        })
}

fn require_nonzero(
    operation: BinaryMarketOperation,
    quantity: u64,
) -> Result<(), BinaryMarketError> {
    if quantity == 0 {
        return Err(BinaryMarketError::ZeroQuantity { operation });
    }
    Ok(())
}

fn invalid_state(operation: BinaryMarketOperation, state: BinaryMarketState) -> BinaryMarketError {
    BinaryMarketError::InvalidState {
        operation,
        phase: state.into(),
    }
}

fn require_winner(
    winning: BinaryOutcome,
    attempted: BinaryOutcome,
) -> Result<(), BinaryMarketError> {
    if winning != attempted {
        return Err(BinaryMarketError::LosingOutcome { winning, attempted });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 200;
    const CP: u64 = 400;

    fn economics() -> BinaryMarketEconomics {
        BinaryMarketEconomics::new(BASE).expect("canonical denomination")
    }

    fn trading(outstanding_pairs: u64) -> BinaryMarketState {
        BinaryMarketState::Trading { outstanding_pairs }
    }

    fn resolved_yes(collateral_unredeemed: u64) -> BinaryMarketState {
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        }
    }

    fn resolved_no(collateral_unredeemed: u64) -> BinaryMarketState {
        BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        }
    }

    fn expired(collateral_unredeemed: u64) -> BinaryMarketState {
        BinaryMarketState::Expired {
            collateral_unredeemed,
        }
    }

    #[test]
    fn slot_words_are_exact_and_round_trip() {
        for (tag, slot) in BinaryMarketSlot::ALL.into_iter().enumerate() {
            let word = slot.storage_word();
            assert_eq!(&word[..30], &[0_u8; 30]);
            assert_eq!(word[30], BINARY_MARKET_STORAGE_VERSION);
            assert_eq!(word[31], u8::try_from(tag).expect("eight tags"));
            assert_eq!(BinaryMarketSlot::from_storage_word(word), Ok(slot));
        }
    }

    #[test]
    fn slot_words_reject_reserved_bytes_versions_and_tags() {
        let mut word = BinaryMarketSlot::DormantYesRt.storage_word();
        word[0] = 1;
        assert_eq!(
            BinaryMarketSlot::from_storage_word(word),
            Err(BinaryMarketSlotError::NonzeroReservedBytes)
        );
        word = BinaryMarketSlot::DormantYesRt.storage_word();
        word[30] = 2;
        assert_eq!(
            BinaryMarketSlot::from_storage_word(word),
            Err(BinaryMarketSlotError::UnsupportedVersion(2))
        );
        word = BinaryMarketSlot::DormantYesRt.storage_word();
        word[31] = 8;
        assert_eq!(
            BinaryMarketSlot::from_storage_word(word),
            Err(BinaryMarketSlotError::UnknownSlot(8))
        );
    }

    #[test]
    fn accepts_every_v1_denomination_and_derives_pair_collateral() {
        for base_payout in BASE_PAYOUTS {
            let economics = BinaryMarketEconomics::new(base_payout).expect("valid payout");
            assert_eq!(economics.base_payout(), base_payout);
            assert_eq!(economics.collateral_per_pair(), base_payout * 2);
        }
    }

    #[test]
    fn rejects_noncanonical_denominations() {
        for base_payout in [0, 1, 99, 101, 9_999_999, u64::MAX] {
            assert_eq!(
                BinaryMarketEconomics::new(base_payout),
                Err(BinaryMarketError::InvalidBasePayout { base_payout })
            );
        }
    }

    #[test]
    fn issuance_from_dormant_and_trading_locks_exact_collateral() {
        let market = economics();
        let initial = market
            .apply(trading(0), BinaryMarketAction::Issue { pairs: 3 })
            .expect("initial issuance");
        assert_eq!(initial.old_state, trading(0));
        assert_eq!(initial.new_state, trading(3));
        assert_eq!(
            initial.transition,
            BinaryMarketTransition::Issued {
                pairs: 3,
                collateral_locked: 1_200,
            }
        );
        let subsequent = market
            .apply(initial.new_state, BinaryMarketAction::Issue { pairs: 2 })
            .expect("subsequent issuance");
        assert_eq!(subsequent.new_state, trading(5));
        assert_eq!(
            subsequent.transition,
            BinaryMarketTransition::Issued {
                pairs: 2,
                collateral_locked: 800,
            }
        );
    }

    #[test]
    fn issuance_rejects_zero_terminal_states_and_checked_overflow() {
        let market = economics();
        assert_eq!(
            market.apply(trading(0), BinaryMarketAction::Issue { pairs: 0 }),
            Err(BinaryMarketError::ZeroQuantity {
                operation: BinaryMarketOperation::Issue,
            })
        );
        for state in [resolved_yes(0), resolved_no(0), expired(0)] {
            assert_eq!(
                market.apply(state, BinaryMarketAction::Issue { pairs: 1 }),
                Err(invalid_state(BinaryMarketOperation::Issue, state))
            );
        }
        let max_valid_pairs = u64::MAX / CP;
        assert_eq!(
            market.apply(
                trading(max_valid_pairs),
                BinaryMarketAction::Issue { pairs: u64::MAX }
            ),
            Err(BinaryMarketError::OutstandingPairsOverflow {
                current: max_valid_pairs,
                added: u64::MAX,
            })
        );
        assert_eq!(
            market.apply(
                trading(max_valid_pairs),
                BinaryMarketAction::Issue { pairs: 1 }
            ),
            Err(BinaryMarketError::AmountOverflow {
                amount: max_valid_pairs + 1,
                unit_payout: CP,
            })
        );
    }

    #[test]
    fn cancellation_supports_partial_and_full_transitions() {
        let market = economics();
        let partial = market
            .apply(trading(5), BinaryMarketAction::Cancel { pairs: 2 })
            .expect("partial cancellation");
        assert_eq!(partial.new_state, trading(3));
        assert_eq!(
            partial.transition,
            BinaryMarketTransition::Cancelled {
                pairs: 2,
                collateral_released: 800,
                full: false,
            }
        );
        let full = market
            .apply(partial.new_state, BinaryMarketAction::Cancel { pairs: 3 })
            .expect("full cancellation");
        assert_eq!(full.new_state, trading(0));
        assert_eq!(
            full.transition,
            BinaryMarketTransition::Cancelled {
                pairs: 3,
                collateral_released: 1_200,
                full: true,
            }
        );
    }

    #[test]
    fn cancellation_rejects_zero_excess_and_terminal_states() {
        let market = economics();
        assert_eq!(
            market.apply(trading(1), BinaryMarketAction::Cancel { pairs: 0 }),
            Err(BinaryMarketError::ZeroQuantity {
                operation: BinaryMarketOperation::Cancel,
            })
        );
        assert_eq!(
            market.apply(trading(1), BinaryMarketAction::Cancel { pairs: 2 }),
            Err(BinaryMarketError::CancellationExceedsOutstanding {
                requested: 2,
                outstanding: 1,
            })
        );
        for state in [resolved_yes(CP), resolved_no(CP), expired(CP)] {
            assert_eq!(
                market.apply(state, BinaryMarketAction::Cancel { pairs: 1 }),
                Err(invalid_state(BinaryMarketOperation::Cancel, state))
            );
        }
    }

    #[test]
    fn resolution_moves_all_collateral_and_dormant_resolution_is_terminal() {
        let market = economics();
        for (outcome, expected) in [
            (BinaryOutcome::Yes, resolved_yes(1_200)),
            (BinaryOutcome::No, resolved_no(1_200)),
        ] {
            let applied = market
                .apply(trading(3), BinaryMarketAction::Resolve { outcome })
                .expect("resolution");
            assert_eq!(applied.new_state, expected);
            assert_eq!(
                applied.transition,
                BinaryMarketTransition::Resolved {
                    outcome,
                    collateral_retained: 1_200,
                }
            );
        }
        assert_eq!(
            market
                .apply(
                    trading(0),
                    BinaryMarketAction::Resolve {
                        outcome: BinaryOutcome::Yes,
                    }
                )
                .expect("dormant resolution")
                .new_state,
            resolved_yes(0)
        );
    }

    #[test]
    fn resolution_and_expiry_cannot_follow_terminal_transitions() {
        let market = economics();
        for state in [resolved_yes(CP), resolved_no(CP), expired(CP)] {
            assert_eq!(
                market.apply(
                    state,
                    BinaryMarketAction::Resolve {
                        outcome: BinaryOutcome::Yes,
                    }
                ),
                Err(invalid_state(BinaryMarketOperation::Resolve, state))
            );
            assert_eq!(
                market.apply(state, BinaryMarketAction::Expire),
                Err(invalid_state(BinaryMarketOperation::Expire, state))
            );
        }
    }

    #[test]
    fn expiry_moves_all_collateral_and_works_while_dormant() {
        let market = economics();
        let active = market
            .apply(trading(3), BinaryMarketAction::Expire)
            .expect("active expiry");
        assert_eq!(active.new_state, expired(1_200));
        assert_eq!(
            active.transition,
            BinaryMarketTransition::Expired {
                collateral_retained: 1_200,
            }
        );
        assert_eq!(
            market
                .apply(trading(0), BinaryMarketAction::Expire)
                .expect("dormant expiry")
                .new_state,
            expired(0)
        );
    }

    #[test]
    fn resolved_redemption_pays_cp_and_preserves_terminal_variant() {
        let market = economics();
        for (state, outcome, expected_partial, expected_complete) in [
            (
                resolved_yes(3 * CP),
                BinaryOutcome::Yes,
                resolved_yes(2 * CP),
                resolved_yes(0),
            ),
            (
                resolved_no(3 * CP),
                BinaryOutcome::No,
                resolved_no(2 * CP),
                resolved_no(0),
            ),
        ] {
            let partial = market
                .apply(state, BinaryMarketAction::Redeem { outcome, tokens: 1 })
                .expect("partial winner redemption");
            assert_eq!(partial.new_state, expected_partial);
            assert_eq!(
                partial.transition,
                BinaryMarketTransition::Redeemed {
                    outcome,
                    tokens: 1,
                    collateral_released: CP,
                    complete: false,
                }
            );
            let complete = market
                .apply(
                    partial.new_state,
                    BinaryMarketAction::Redeem { outcome, tokens: 2 },
                )
                .expect("complete winner redemption");
            assert_eq!(complete.new_state, expected_complete);
            assert!(matches!(
                complete.transition,
                BinaryMarketTransition::Redeemed { complete: true, .. }
            ));
        }
    }

    #[test]
    fn resolved_redemption_rejects_loser_zero_excess_and_trading() {
        let market = economics();
        assert_eq!(
            market.apply(
                resolved_yes(CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                }
            ),
            Err(BinaryMarketError::LosingOutcome {
                winning: BinaryOutcome::Yes,
                attempted: BinaryOutcome::No,
            })
        );
        assert_eq!(
            market.apply(
                resolved_no(CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                }
            ),
            Err(BinaryMarketError::LosingOutcome {
                winning: BinaryOutcome::No,
                attempted: BinaryOutcome::Yes,
            })
        );
        assert_eq!(
            market.apply(
                resolved_yes(CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 0,
                }
            ),
            Err(BinaryMarketError::ZeroQuantity {
                operation: BinaryMarketOperation::Redeem,
            })
        );
        assert_eq!(
            market.apply(
                resolved_yes(CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 2,
                }
            ),
            Err(BinaryMarketError::RedemptionExceedsCollateral {
                requested: 2 * CP,
                available: CP,
            })
        );
        assert_eq!(
            market.apply(
                trading(1),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                }
            ),
            Err(invalid_state(BinaryMarketOperation::Redeem, trading(1)))
        );
    }

    #[test]
    fn expiry_redemption_pays_half_for_either_token_and_can_be_asymmetric() {
        let market = economics();
        let yes = market
            .apply(
                expired(2 * CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                },
            )
            .expect("YES expiry redemption");
        assert_eq!(yes.new_state, expired(2 * CP - BASE));
        let no = market
            .apply(
                yes.new_state,
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                },
            )
            .expect("NO expiry redemption");
        assert_eq!(no.new_state, expired(CP));
        let complete = market
            .apply(
                no.new_state,
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 2,
                },
            )
            .expect("complete expiry redemption");
        assert_eq!(complete.new_state, expired(0));
        assert!(matches!(
            complete.transition,
            BinaryMarketTransition::Redeemed { complete: true, .. }
        ));
    }

    #[test]
    fn expiry_redemption_rejects_excess_and_zero() {
        let market = economics();
        assert_eq!(
            market.apply(
                expired(BASE),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 2,
                }
            ),
            Err(BinaryMarketError::RedemptionExceedsCollateral {
                requested: 2 * BASE,
                available: BASE,
            })
        );
        assert_eq!(
            market.apply(
                expired(BASE),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 0,
                }
            ),
            Err(BinaryMarketError::ZeroQuantity {
                operation: BinaryMarketOperation::Redeem,
            })
        );
    }

    #[test]
    fn rejects_corrupt_or_unrepresentable_materialized_states() {
        let market = economics();
        assert_eq!(
            market.validate_state(resolved_yes(CP + 1)),
            Err(BinaryMarketError::InvalidStateAmount {
                phase: BinaryMarketPhase::ResolvedYes,
                collateral: CP + 1,
                unit_payout: CP,
            })
        );
        assert_eq!(
            market.validate_state(expired(BASE + 1)),
            Err(BinaryMarketError::InvalidStateAmount {
                phase: BinaryMarketPhase::Expired,
                collateral: BASE + 1,
                unit_payout: BASE,
            })
        );
        let too_many_pairs = u64::MAX / CP + 1;
        assert_eq!(
            market.validate_state(trading(too_many_pairs)),
            Err(BinaryMarketError::AmountOverflow {
                amount: too_many_pairs,
                unit_payout: CP,
            })
        );
    }

    #[test]
    fn issue_cancel_and_redemptions_conserve_every_denomination() {
        for base_payout in BASE_PAYOUTS {
            let market = BinaryMarketEconomics::new(base_payout).expect("valid payout");
            let cp = market.collateral_per_pair();
            for pairs in 1..=32 {
                let issued = market
                    .apply(trading(0), BinaryMarketAction::Issue { pairs })
                    .expect("issue");
                assert_eq!(
                    issued.transition,
                    BinaryMarketTransition::Issued {
                        pairs,
                        collateral_locked: pairs * cp,
                    }
                );
                assert_eq!(
                    market
                        .apply(issued.new_state, BinaryMarketAction::Cancel { pairs })
                        .expect("cancel")
                        .new_state,
                    trading(0)
                );
                let resolved = market
                    .apply(
                        trading(pairs),
                        BinaryMarketAction::Resolve {
                            outcome: BinaryOutcome::Yes,
                        },
                    )
                    .expect("resolve");
                assert_eq!(
                    market
                        .apply(
                            resolved.new_state,
                            BinaryMarketAction::Redeem {
                                outcome: BinaryOutcome::Yes,
                                tokens: pairs,
                            },
                        )
                        .expect("winner redemption")
                        .new_state,
                    resolved_yes(0)
                );
                let expired_state = market
                    .apply(trading(pairs), BinaryMarketAction::Expire)
                    .expect("expire")
                    .new_state;
                let after_yes = market
                    .apply(
                        expired_state,
                        BinaryMarketAction::Redeem {
                            outcome: BinaryOutcome::Yes,
                            tokens: pairs,
                        },
                    )
                    .expect("YES expiry redemption")
                    .new_state;
                assert_eq!(
                    market
                        .apply(
                            after_yes,
                            BinaryMarketAction::Redeem {
                                outcome: BinaryOutcome::No,
                                tokens: pairs,
                            },
                        )
                        .expect("NO expiry redemption")
                        .new_state,
                    expired(0)
                );
            }
        }
    }

    #[test]
    fn every_action_kind_is_stable() {
        assert_eq!(
            BinaryMarketAction::Issue { pairs: 1 }.kind(),
            BinaryMarketOperation::Issue
        );
        assert_eq!(
            BinaryMarketAction::Cancel { pairs: 1 }.kind(),
            BinaryMarketOperation::Cancel
        );
        assert_eq!(
            BinaryMarketAction::Resolve {
                outcome: BinaryOutcome::Yes,
            }
            .kind(),
            BinaryMarketOperation::Resolve
        );
        assert_eq!(
            BinaryMarketAction::Expire.kind(),
            BinaryMarketOperation::Expire
        );
        assert_eq!(
            BinaryMarketAction::Redeem {
                outcome: BinaryOutcome::No,
                tokens: 1,
            }
            .kind(),
            BinaryMarketOperation::Redeem
        );
    }
}
