//! Pure binary-market economics and materialized-state transitions.
//!
//! This module deliberately does not inspect transactions. The confirmed-spend
//! interpreter validates a covenant spend and converts it into a
//! [`BinaryMarketAction`]; this state machine then applies the same checked
//! arithmetic used by builders and the node's materialized view.

use crate::recovery::BASE_PAYOUTS;
pub use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use simplex::either::Either;
use simplex::program::WitnessTrait as _;
use simplex::simplicityhl::WitnessValues;
use thiserror::Error;

mod compiled;

pub use crate::artifacts::binary_market::BinaryMarketProgram;
use crate::artifacts::binary_market::derived_binary_market;
pub use compiled::{
    CompiledBinaryMarket, CompiledBinaryMarketError, CompiledBinaryMarketExecutionError,
    CompiledBinaryMarketSlot,
};

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

    /// Stable numeric tag committed by the v1 storage layout and witness ABI.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

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
        Self::try_from(word[31])
    }
}

impl TryFrom<u8> for BinaryMarketSlot {
    type Error = BinaryMarketSlotError;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
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

impl From<BinaryMarketSlot> for u8 {
    fn from(slot: BinaryMarketSlot) -> Self {
        slot.tag()
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

/// The ten stable v1 transaction shapes recognized by the market protocol.
///
/// Paths are derived from the current coordinator role and semantic operation;
/// they are not part of the new Simplicity witness ABI. The numeric tags remain
/// stable for indexing and compatibility with existing materialized history.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BinaryMarketPath {
    InitialIssuance = 0,
    SubsequentIssuance = 1,
    PartialCancellation = 2,
    FullCancellation = 3,
    ActiveResolution = 4,
    DormantResolution = 5,
    ActiveExpiry = 6,
    DormantExpiry = 7,
    ResolvedRedemption = 8,
    ExpiryRedemption = 9,
}

impl BinaryMarketPath {
    pub const ALL: [Self; 10] = [
        Self::InitialIssuance,
        Self::SubsequentIssuance,
        Self::PartialCancellation,
        Self::FullCancellation,
        Self::ActiveResolution,
        Self::DormantResolution,
        Self::ActiveExpiry,
        Self::DormantExpiry,
        Self::ResolvedRedemption,
        Self::ExpiryRedemption,
    ];

    /// Stable numeric tag used by the v1 domain model.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn operation(self) -> BinaryMarketOperation {
        match self {
            Self::InitialIssuance | Self::SubsequentIssuance => BinaryMarketOperation::Issue,
            Self::PartialCancellation | Self::FullCancellation => BinaryMarketOperation::Cancel,
            Self::ActiveResolution | Self::DormantResolution => BinaryMarketOperation::Resolve,
            Self::ActiveExpiry | Self::DormantExpiry => BinaryMarketOperation::Expire,
            Self::ResolvedRedemption | Self::ExpiryRedemption => BinaryMarketOperation::Redeem,
        }
    }
}

impl TryFrom<u8> for BinaryMarketPath {
    type Error = BinaryMarketPathError;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        match tag {
            0 => Ok(Self::InitialIssuance),
            1 => Ok(Self::SubsequentIssuance),
            2 => Ok(Self::PartialCancellation),
            3 => Ok(Self::FullCancellation),
            4 => Ok(Self::ActiveResolution),
            5 => Ok(Self::DormantResolution),
            6 => Ok(Self::ActiveExpiry),
            7 => Ok(Self::DormantExpiry),
            8 => Ok(Self::ResolvedRedemption),
            9 => Ok(Self::ExpiryRedemption),
            tag => Err(BinaryMarketPathError::UnknownTag(tag)),
        }
    }
}

impl From<BinaryMarketPath> for u8 {
    fn from(path: BinaryMarketPath) -> Self {
        path.tag()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BinaryMarketPathError {
    #[error("unknown binary-market path tag {0}")]
    UnknownTag(u8),
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

impl BinaryMarketTransition {
    #[must_use]
    pub const fn operation(self) -> BinaryMarketOperation {
        match self {
            Self::Issued { .. } => BinaryMarketOperation::Issue,
            Self::Cancelled { .. } => BinaryMarketOperation::Cancel,
            Self::Resolved { .. } => BinaryMarketOperation::Resolve,
            Self::Expired { .. } => BinaryMarketOperation::Expire,
            Self::Redeemed { .. } => BinaryMarketOperation::Redeem,
        }
    }
}

/// Old state, new state, and the exact collateral effect of one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedBinaryMarketTransition {
    pub old_state: BinaryMarketState,
    pub new_state: BinaryMarketState,
    pub transition: BinaryMarketTransition,
}

/// The input role that validates a transition for all inputs in its state.
///
/// Trading transitions always coordinate through the YES RT. Terminal states
/// contain only one covenant input, so their collateral slot is the coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryMarketCoordinatorRole {
    DormantYesRt,
    UnresolvedYesRt,
    ResolvedYesCollateral,
    ResolvedNoCollateral,
    ExpiredCollateral,
}

impl BinaryMarketCoordinatorRole {
    #[must_use]
    pub const fn slot(self) -> BinaryMarketSlot {
        match self {
            Self::DormantYesRt => BinaryMarketSlot::DormantYesRt,
            Self::UnresolvedYesRt => BinaryMarketSlot::UnresolvedYesRt,
            Self::ResolvedYesCollateral => BinaryMarketSlot::ResolvedYesCollateral,
            Self::ResolvedNoCollateral => BinaryMarketSlot::ResolvedNoCollateral,
            Self::ExpiredCollateral => BinaryMarketSlot::ExpiredCollateral,
        }
    }

    #[must_use]
    pub const fn for_state(state: BinaryMarketState) -> Self {
        match state {
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            } => Self::DormantYesRt,
            BinaryMarketState::Trading { .. } => Self::UnresolvedYesRt,
            BinaryMarketState::ResolvedYes { .. } => Self::ResolvedYesCollateral,
            BinaryMarketState::ResolvedNo { .. } => Self::ResolvedNoCollateral,
            BinaryMarketState::Expired { .. } => Self::ExpiredCollateral,
        }
    }
}

impl TryFrom<BinaryMarketSlot> for BinaryMarketCoordinatorRole {
    type Error = BinaryMarketLayoutError;

    fn try_from(slot: BinaryMarketSlot) -> Result<Self, Self::Error> {
        match slot {
            BinaryMarketSlot::DormantYesRt => Ok(Self::DormantYesRt),
            BinaryMarketSlot::UnresolvedYesRt => Ok(Self::UnresolvedYesRt),
            BinaryMarketSlot::ResolvedYesCollateral => Ok(Self::ResolvedYesCollateral),
            BinaryMarketSlot::ResolvedNoCollateral => Ok(Self::ResolvedNoCollateral),
            BinaryMarketSlot::ExpiredCollateral => Ok(Self::ExpiredCollateral),
            slot => Err(BinaryMarketLayoutError::FollowerCannotCoordinate { slot }),
        }
    }
}

/// Exact positional role of one covenant input in a market transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BinaryMarketInputRole {
    DormantYesCoordinator,
    DormantNoFollower,
    UnresolvedYesCoordinator,
    UnresolvedNoFollower,
    UnresolvedCollateralFollower,
    ResolvedYesCoordinator,
    ResolvedNoCoordinator,
    ExpiredCoordinator,
}

impl BinaryMarketInputRole {
    #[must_use]
    pub const fn slot(self) -> BinaryMarketSlot {
        match self {
            Self::DormantYesCoordinator => BinaryMarketSlot::DormantYesRt,
            Self::DormantNoFollower => BinaryMarketSlot::DormantNoRt,
            Self::UnresolvedYesCoordinator => BinaryMarketSlot::UnresolvedYesRt,
            Self::UnresolvedNoFollower => BinaryMarketSlot::UnresolvedNoRt,
            Self::UnresolvedCollateralFollower => BinaryMarketSlot::UnresolvedCollateral,
            Self::ResolvedYesCoordinator => BinaryMarketSlot::ResolvedYesCollateral,
            Self::ResolvedNoCoordinator => BinaryMarketSlot::ResolvedNoCollateral,
            Self::ExpiredCoordinator => BinaryMarketSlot::ExpiredCollateral,
        }
    }

    #[must_use]
    pub const fn coordinator_role(self) -> BinaryMarketCoordinatorRole {
        match self {
            Self::DormantYesCoordinator | Self::DormantNoFollower => {
                BinaryMarketCoordinatorRole::DormantYesRt
            }
            Self::UnresolvedYesCoordinator
            | Self::UnresolvedNoFollower
            | Self::UnresolvedCollateralFollower => BinaryMarketCoordinatorRole::UnresolvedYesRt,
            Self::ResolvedYesCoordinator => BinaryMarketCoordinatorRole::ResolvedYesCollateral,
            Self::ResolvedNoCoordinator => BinaryMarketCoordinatorRole::ResolvedNoCollateral,
            Self::ExpiredCoordinator => BinaryMarketCoordinatorRole::ExpiredCollateral,
        }
    }

    #[must_use]
    pub const fn is_coordinator(self) -> bool {
        matches!(
            self,
            Self::DormantYesCoordinator
                | Self::UnresolvedYesCoordinator
                | Self::ResolvedYesCoordinator
                | Self::ResolvedNoCoordinator
                | Self::ExpiredCoordinator
        )
    }

    #[must_use]
    pub const fn is_follower(self) -> bool {
        !self.is_coordinator()
    }
}

impl TryFrom<u8> for BinaryMarketInputRole {
    type Error = BinaryMarketSlotError;

    fn try_from(tag: u8) -> Result<Self, Self::Error> {
        BinaryMarketSlot::try_from(tag).map(Self::from)
    }
}

impl From<BinaryMarketInputRole> for u8 {
    fn from(role: BinaryMarketInputRole) -> Self {
        role.slot().tag()
    }
}

impl From<BinaryMarketInputRole> for BinaryMarketSlot {
    fn from(role: BinaryMarketInputRole) -> Self {
        role.slot()
    }
}

impl From<BinaryMarketCoordinatorRole> for BinaryMarketSlot {
    fn from(role: BinaryMarketCoordinatorRole) -> Self {
        role.slot()
    }
}

impl From<BinaryMarketCoordinatorRole> for u8 {
    fn from(role: BinaryMarketCoordinatorRole) -> Self {
        role.slot().tag()
    }
}

impl From<BinaryMarketInputRole> for BinaryMarketCoordinatorRole {
    fn from(role: BinaryMarketInputRole) -> Self {
        role.coordinator_role()
    }
}

impl BinaryMarketCoordinatorRole {
    #[must_use]
    pub const fn input_role(self) -> BinaryMarketInputRole {
        match self {
            Self::DormantYesRt => BinaryMarketInputRole::DormantYesCoordinator,
            Self::UnresolvedYesRt => BinaryMarketInputRole::UnresolvedYesCoordinator,
            Self::ResolvedYesCollateral => BinaryMarketInputRole::ResolvedYesCoordinator,
            Self::ResolvedNoCollateral => BinaryMarketInputRole::ResolvedNoCoordinator,
            Self::ExpiredCollateral => BinaryMarketInputRole::ExpiredCoordinator,
        }
    }
}

impl From<BinaryMarketSlot> for BinaryMarketInputRole {
    fn from(slot: BinaryMarketSlot) -> Self {
        match slot {
            BinaryMarketSlot::DormantYesRt => Self::DormantYesCoordinator,
            BinaryMarketSlot::DormantNoRt => Self::DormantNoFollower,
            BinaryMarketSlot::UnresolvedYesRt => Self::UnresolvedYesCoordinator,
            BinaryMarketSlot::UnresolvedNoRt => Self::UnresolvedNoFollower,
            BinaryMarketSlot::UnresolvedCollateral => Self::UnresolvedCollateralFollower,
            BinaryMarketSlot::ResolvedYesCollateral => Self::ResolvedYesCoordinator,
            BinaryMarketSlot::ResolvedNoCollateral => Self::ResolvedNoCoordinator,
            BinaryMarketSlot::ExpiredCollateral => Self::ExpiredCoordinator,
        }
    }
}

const DORMANT_INPUT_ROLES: [BinaryMarketInputRole; 2] = [
    BinaryMarketInputRole::DormantYesCoordinator,
    BinaryMarketInputRole::DormantNoFollower,
];
const UNRESOLVED_INPUT_ROLES: [BinaryMarketInputRole; 3] = [
    BinaryMarketInputRole::UnresolvedYesCoordinator,
    BinaryMarketInputRole::UnresolvedNoFollower,
    BinaryMarketInputRole::UnresolvedCollateralFollower,
];
const RESOLVED_YES_INPUT_ROLES: [BinaryMarketInputRole; 1] =
    [BinaryMarketInputRole::ResolvedYesCoordinator];
const RESOLVED_NO_INPUT_ROLES: [BinaryMarketInputRole; 1] =
    [BinaryMarketInputRole::ResolvedNoCoordinator];
const EXPIRED_INPUT_ROLES: [BinaryMarketInputRole; 1] = [BinaryMarketInputRole::ExpiredCoordinator];

/// Checked mapping between semantic operations, protocol paths, and input roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryMarketLayout {
    path: BinaryMarketPath,
    coordinator: BinaryMarketCoordinatorRole,
}

impl BinaryMarketLayout {
    /// Derive the protocol path from the current coordinator and operation.
    /// Cancellation is the one operation whose partial/full shape must first be
    /// inferred from transaction outputs.
    pub fn for_operation(
        coordinator: BinaryMarketCoordinatorRole,
        operation: BinaryMarketOperation,
        full_cancellation: Option<bool>,
    ) -> Result<Self, BinaryMarketLayoutError> {
        if operation == BinaryMarketOperation::Cancel && full_cancellation.is_none() {
            return Err(BinaryMarketLayoutError::MissingCancellationShape);
        }
        if operation != BinaryMarketOperation::Cancel && full_cancellation.is_some() {
            return Err(BinaryMarketLayoutError::UnexpectedCancellationShape { operation });
        }

        let path = match (coordinator, operation, full_cancellation) {
            (BinaryMarketCoordinatorRole::DormantYesRt, BinaryMarketOperation::Issue, None) => {
                BinaryMarketPath::InitialIssuance
            }
            (BinaryMarketCoordinatorRole::UnresolvedYesRt, BinaryMarketOperation::Issue, None) => {
                BinaryMarketPath::SubsequentIssuance
            }
            (
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Cancel,
                Some(false),
            ) => BinaryMarketPath::PartialCancellation,
            (
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Cancel,
                Some(true),
            ) => BinaryMarketPath::FullCancellation,
            (
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Resolve,
                None,
            ) => BinaryMarketPath::ActiveResolution,
            (BinaryMarketCoordinatorRole::DormantYesRt, BinaryMarketOperation::Resolve, None) => {
                BinaryMarketPath::DormantResolution
            }
            (BinaryMarketCoordinatorRole::UnresolvedYesRt, BinaryMarketOperation::Expire, None) => {
                BinaryMarketPath::ActiveExpiry
            }
            (BinaryMarketCoordinatorRole::DormantYesRt, BinaryMarketOperation::Expire, None) => {
                BinaryMarketPath::DormantExpiry
            }
            (
                BinaryMarketCoordinatorRole::ResolvedYesCollateral
                | BinaryMarketCoordinatorRole::ResolvedNoCollateral,
                BinaryMarketOperation::Redeem,
                None,
            ) => BinaryMarketPath::ResolvedRedemption,
            (
                BinaryMarketCoordinatorRole::ExpiredCollateral,
                BinaryMarketOperation::Redeem,
                None,
            ) => BinaryMarketPath::ExpiryRedemption,
            _ => {
                return Err(BinaryMarketLayoutError::InvalidCoordinatorOperation {
                    coordinator,
                    operation,
                });
            }
        };
        Ok(Self { path, coordinator })
    }

    /// Derive and validate a layout from an economics transition.
    pub fn for_transition(
        before: BinaryMarketState,
        action: BinaryMarketAction,
        applied: AppliedBinaryMarketTransition,
    ) -> Result<Self, BinaryMarketLayoutError> {
        if applied.old_state != before {
            return Err(BinaryMarketLayoutError::OldStateMismatch);
        }
        if !transition_matches_action(applied.transition, action) {
            return Err(BinaryMarketLayoutError::TransitionActionMismatch);
        }
        let full_cancellation = match applied.transition {
            BinaryMarketTransition::Cancelled { full, .. } => Some(full),
            _ => None,
        };
        Self::for_operation(
            BinaryMarketCoordinatorRole::for_state(before),
            action.kind(),
            full_cancellation,
        )
    }

    #[must_use]
    pub const fn path(self) -> BinaryMarketPath {
        self.path
    }

    #[must_use]
    pub const fn operation(self) -> BinaryMarketOperation {
        self.path.operation()
    }

    #[must_use]
    pub const fn coordinator_role(self) -> BinaryMarketCoordinatorRole {
        self.coordinator
    }

    #[must_use]
    pub fn input_roles(self) -> &'static [BinaryMarketInputRole] {
        match self.coordinator {
            BinaryMarketCoordinatorRole::DormantYesRt => &DORMANT_INPUT_ROLES,
            BinaryMarketCoordinatorRole::UnresolvedYesRt => &UNRESOLVED_INPUT_ROLES,
            BinaryMarketCoordinatorRole::ResolvedYesCollateral => &RESOLVED_YES_INPUT_ROLES,
            BinaryMarketCoordinatorRole::ResolvedNoCollateral => &RESOLVED_NO_INPUT_ROLES,
            BinaryMarketCoordinatorRole::ExpiredCollateral => &EXPIRED_INPUT_ROLES,
        }
    }

    /// Resolve a slot to its exact input role and reject slots outside this layout.
    pub fn input_role(
        self,
        slot: BinaryMarketSlot,
    ) -> Result<BinaryMarketInputRole, BinaryMarketLayoutError> {
        let role = BinaryMarketInputRole::from(slot);
        if self.input_roles().contains(&role) {
            Ok(role)
        } else {
            Err(BinaryMarketLayoutError::InputRoleNotInLayout {
                path: self.path,
                role,
            })
        }
    }
}

fn transition_matches_action(
    transition: BinaryMarketTransition,
    action: BinaryMarketAction,
) -> bool {
    match (transition, action) {
        (
            BinaryMarketTransition::Issued { pairs: left, .. },
            BinaryMarketAction::Issue { pairs },
        )
        | (
            BinaryMarketTransition::Cancelled { pairs: left, .. },
            BinaryMarketAction::Cancel { pairs },
        ) => left == pairs,
        (
            BinaryMarketTransition::Resolved { outcome: left, .. },
            BinaryMarketAction::Resolve { outcome },
        ) => left == outcome,
        (BinaryMarketTransition::Expired { .. }, BinaryMarketAction::Expire) => true,
        (
            BinaryMarketTransition::Redeemed {
                outcome: left_outcome,
                tokens: left_tokens,
                ..
            },
            BinaryMarketAction::Redeem { outcome, tokens },
        ) => left_outcome == outcome && left_tokens == tokens,
        _ => false,
    }
}

/// Oracle data carried only by a resolution coordinator action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryMarketResolution {
    outcome: BinaryOutcome,
    signature: [u8; 64],
}

impl BinaryMarketResolution {
    #[must_use]
    pub const fn new(outcome: BinaryOutcome, signature: [u8; 64]) -> Self {
        Self { outcome, signature }
    }

    #[must_use]
    pub const fn outcome(self) -> BinaryOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn signature(self) -> [u8; 64] {
        self.signature
    }
}

/// Semantic coordinator action shared verbatim by every input witness.
///
/// Quantities and the expiry-redemption token side are derived from burn
/// outputs by the covenant, so the witness carries only the output window and
/// resolution authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryMarketCoordinatorAction {
    Issue {
        output_base: u32,
    },
    Cancel {
        output_base: u32,
    },
    Resolve {
        output_base: u32,
        resolution: BinaryMarketResolution,
    },
    Expire {
        output_base: u32,
    },
    Redeem {
        output_base: u32,
    },
}

impl BinaryMarketCoordinatorAction {
    /// Construct the unique action variant allowed by `layout`.
    pub fn for_layout(
        layout: BinaryMarketLayout,
        output_base: u32,
        resolution: Option<BinaryMarketResolution>,
    ) -> Result<Self, BinaryMarketLayoutError> {
        match (layout.operation(), resolution) {
            (BinaryMarketOperation::Issue, None) => Ok(Self::Issue { output_base }),
            (BinaryMarketOperation::Cancel, None) => Ok(Self::Cancel { output_base }),
            (BinaryMarketOperation::Resolve, Some(resolution)) => Ok(Self::Resolve {
                output_base,
                resolution,
            }),
            (BinaryMarketOperation::Expire, None) => Ok(Self::Expire { output_base }),
            (BinaryMarketOperation::Redeem, None) => Ok(Self::Redeem { output_base }),
            (BinaryMarketOperation::Resolve, None) => {
                Err(BinaryMarketLayoutError::MissingResolutionAuthorization)
            }
            (operation, Some(_)) => {
                Err(BinaryMarketLayoutError::UnexpectedResolutionAuthorization { operation })
            }
        }
    }

    #[must_use]
    pub const fn operation(self) -> BinaryMarketOperation {
        match self {
            Self::Issue { .. } => BinaryMarketOperation::Issue,
            Self::Cancel { .. } => BinaryMarketOperation::Cancel,
            Self::Resolve { .. } => BinaryMarketOperation::Resolve,
            Self::Expire { .. } => BinaryMarketOperation::Expire,
            Self::Redeem { .. } => BinaryMarketOperation::Redeem,
        }
    }

    #[must_use]
    pub const fn output_base(self) -> u32 {
        match self {
            Self::Issue { output_base }
            | Self::Cancel { output_base }
            | Self::Resolve { output_base, .. }
            | Self::Expire { output_base }
            | Self::Redeem { output_base } => output_base,
        }
    }

    fn generated(self) -> GeneratedBinaryMarketAction {
        match self {
            Self::Issue { output_base } => Either::Left(Either::Left(output_base)),
            Self::Cancel { output_base } => Either::Left(Either::Right(output_base)),
            Self::Resolve {
                output_base,
                resolution,
            } => Either::Right(Either::Left((
                output_base,
                resolution.outcome == BinaryOutcome::Yes,
                resolution.signature,
            ))),
            Self::Expire { output_base } => Either::Right(Either::Right(Either::Left(output_base))),
            Self::Redeem { output_base } => {
                Either::Right(Either::Right(Either::Right(output_base)))
            }
        }
    }
}

type GeneratedBinaryMarketAction =
    Either<Either<u32, u32>, Either<(u32, bool, [u8; 64]), Either<u32, u32>>>;

/// Checked facade for the generated Simplicity witness representation.
///
/// The raw generated witness and its nested `Either` encoding intentionally do
/// not escape this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryMarketWitness {
    slot: BinaryMarketSlot,
    action: BinaryMarketCoordinatorAction,
}

impl BinaryMarketWitness {
    pub fn new(
        layout: BinaryMarketLayout,
        input_role: BinaryMarketInputRole,
        action: BinaryMarketCoordinatorAction,
    ) -> Result<Self, BinaryMarketLayoutError> {
        if !layout.input_roles().contains(&input_role) {
            return Err(BinaryMarketLayoutError::InputRoleNotInLayout {
                path: layout.path,
                role: input_role,
            });
        }
        if action.operation() != layout.operation() {
            return Err(BinaryMarketLayoutError::ActionLayoutMismatch {
                path: layout.path,
                operation: action.operation(),
            });
        }
        Ok(Self {
            slot: input_role.slot(),
            action,
        })
    }

    pub fn for_slot(
        layout: BinaryMarketLayout,
        slot: BinaryMarketSlot,
        action: BinaryMarketCoordinatorAction,
    ) -> Result<Self, BinaryMarketLayoutError> {
        Self::new(layout, layout.input_role(slot)?, action)
    }

    #[must_use]
    pub const fn slot(self) -> BinaryMarketSlot {
        self.slot
    }

    #[must_use]
    pub const fn action(self) -> BinaryMarketCoordinatorAction {
        self.action
    }

    #[must_use]
    pub fn build_witness(&self) -> WitnessValues {
        derived_binary_market::BinaryMarketWitness {
            slot: self.slot.tag(),
            action: self.action.generated(),
        }
        .build_witness()
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum BinaryMarketLayoutError {
    #[error("market follower slot {slot:?} cannot coordinate a transition")]
    FollowerCannotCoordinate { slot: BinaryMarketSlot },
    #[error("a cancellation layout requires its full/partial transaction shape")]
    MissingCancellationShape,
    #[error("{operation:?} cannot carry a cancellation transaction shape")]
    UnexpectedCancellationShape { operation: BinaryMarketOperation },
    #[error("{coordinator:?} cannot coordinate {operation:?}")]
    InvalidCoordinatorOperation {
        coordinator: BinaryMarketCoordinatorRole,
        operation: BinaryMarketOperation,
    },
    #[error("the applied transition old state does not match the supplied current state")]
    OldStateMismatch,
    #[error("the applied transition does not match the supplied semantic action")]
    TransitionActionMismatch,
    #[error("resolution requires an authorization payload")]
    MissingResolutionAuthorization,
    #[error("{operation:?} cannot carry resolution authorization")]
    UnexpectedResolutionAuthorization { operation: BinaryMarketOperation },
    #[error("input role {role:?} is not present in {path:?}")]
    InputRoleNotInLayout {
        path: BinaryMarketPath,
        role: BinaryMarketInputRole,
    },
    #[error("{path:?} cannot encode a {operation:?} coordinator action")]
    ActionLayoutMismatch {
        path: BinaryMarketPath,
        operation: BinaryMarketOperation,
    },
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
    fn path_tags_are_stable_checked_and_round_trip() {
        for (tag, path) in BinaryMarketPath::ALL.into_iter().enumerate() {
            let tag = u8::try_from(tag).expect("ten tags");
            assert_eq!(path.tag(), tag);
            assert_eq!(u8::from(path), tag);
            assert_eq!(BinaryMarketPath::try_from(tag), Ok(path));
        }
        assert_eq!(
            BinaryMarketPath::try_from(10),
            Err(BinaryMarketPathError::UnknownTag(10))
        );
        assert_eq!(
            BinaryMarketPath::try_from(u8::MAX),
            Err(BinaryMarketPathError::UnknownTag(u8::MAX))
        );
    }

    #[test]
    fn every_transition_derives_its_path_coordinator_and_exact_input_roles() {
        let market = economics();
        let cases = [
            (
                trading(0),
                BinaryMarketAction::Issue { pairs: 1 },
                BinaryMarketPath::InitialIssuance,
                BinaryMarketCoordinatorRole::DormantYesRt,
                &[
                    BinaryMarketSlot::DormantYesRt,
                    BinaryMarketSlot::DormantNoRt,
                ][..],
            ),
            (
                trading(2),
                BinaryMarketAction::Issue { pairs: 1 },
                BinaryMarketPath::SubsequentIssuance,
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                &[
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                    BinaryMarketSlot::UnresolvedCollateral,
                ][..],
            ),
            (
                trading(2),
                BinaryMarketAction::Cancel { pairs: 1 },
                BinaryMarketPath::PartialCancellation,
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                &[
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                    BinaryMarketSlot::UnresolvedCollateral,
                ][..],
            ),
            (
                trading(2),
                BinaryMarketAction::Cancel { pairs: 2 },
                BinaryMarketPath::FullCancellation,
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                &[
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                    BinaryMarketSlot::UnresolvedCollateral,
                ][..],
            ),
            (
                trading(2),
                BinaryMarketAction::Resolve {
                    outcome: BinaryOutcome::Yes,
                },
                BinaryMarketPath::ActiveResolution,
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                &[
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                    BinaryMarketSlot::UnresolvedCollateral,
                ][..],
            ),
            (
                trading(0),
                BinaryMarketAction::Resolve {
                    outcome: BinaryOutcome::No,
                },
                BinaryMarketPath::DormantResolution,
                BinaryMarketCoordinatorRole::DormantYesRt,
                &[
                    BinaryMarketSlot::DormantYesRt,
                    BinaryMarketSlot::DormantNoRt,
                ][..],
            ),
            (
                trading(2),
                BinaryMarketAction::Expire,
                BinaryMarketPath::ActiveExpiry,
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                &[
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                    BinaryMarketSlot::UnresolvedCollateral,
                ][..],
            ),
            (
                trading(0),
                BinaryMarketAction::Expire,
                BinaryMarketPath::DormantExpiry,
                BinaryMarketCoordinatorRole::DormantYesRt,
                &[
                    BinaryMarketSlot::DormantYesRt,
                    BinaryMarketSlot::DormantNoRt,
                ][..],
            ),
            (
                resolved_yes(2 * CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                },
                BinaryMarketPath::ResolvedRedemption,
                BinaryMarketCoordinatorRole::ResolvedYesCollateral,
                &[BinaryMarketSlot::ResolvedYesCollateral][..],
            ),
            (
                resolved_no(2 * CP),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                },
                BinaryMarketPath::ResolvedRedemption,
                BinaryMarketCoordinatorRole::ResolvedNoCollateral,
                &[BinaryMarketSlot::ResolvedNoCollateral][..],
            ),
            (
                expired(2 * BASE),
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                },
                BinaryMarketPath::ExpiryRedemption,
                BinaryMarketCoordinatorRole::ExpiredCollateral,
                &[BinaryMarketSlot::ExpiredCollateral][..],
            ),
        ];

        for (before, action, expected_path, expected_coordinator, expected_slots) in cases {
            let applied = market.apply(before, action).expect("valid transition");
            let layout = BinaryMarketLayout::for_transition(before, action, applied)
                .expect("valid transition layout");
            assert_eq!(layout.path(), expected_path);
            assert_eq!(layout.operation(), action.kind());
            assert_eq!(layout.coordinator_role(), expected_coordinator);

            let roles = layout.input_roles();
            assert!(roles[0].is_coordinator());
            assert!(roles[1..].iter().all(|role| role.is_follower()));
            assert!(
                roles
                    .iter()
                    .all(|role| role.coordinator_role() == expected_coordinator)
            );
            assert_eq!(
                roles.iter().map(|role| role.slot()).collect::<Vec<_>>(),
                expected_slots
            );
            for role in roles {
                assert_eq!(layout.input_role(role.slot()), Ok(*role));
            }
        }
    }

    #[test]
    fn layouts_reject_ambiguous_or_inconsistent_semantics() {
        assert_eq!(
            BinaryMarketLayout::for_operation(
                BinaryMarketCoordinatorRole::UnresolvedYesRt,
                BinaryMarketOperation::Cancel,
                None,
            ),
            Err(BinaryMarketLayoutError::MissingCancellationShape)
        );
        assert_eq!(
            BinaryMarketLayout::for_operation(
                BinaryMarketCoordinatorRole::DormantYesRt,
                BinaryMarketOperation::Issue,
                Some(false),
            ),
            Err(BinaryMarketLayoutError::UnexpectedCancellationShape {
                operation: BinaryMarketOperation::Issue,
            })
        );
        assert_eq!(
            BinaryMarketCoordinatorRole::try_from(BinaryMarketSlot::DormantNoRt),
            Err(BinaryMarketLayoutError::FollowerCannotCoordinate {
                slot: BinaryMarketSlot::DormantNoRt,
            })
        );

        let action = BinaryMarketAction::Issue { pairs: 1 };
        let mut applied = economics().apply(trading(0), action).expect("issuance");
        applied.old_state = trading(1);
        assert_eq!(
            BinaryMarketLayout::for_transition(trading(0), action, applied),
            Err(BinaryMarketLayoutError::OldStateMismatch)
        );
    }

    #[test]
    fn checked_witness_facade_encodes_only_slot_and_nested_action() {
        let resolution = BinaryMarketResolution::new(BinaryOutcome::Yes, [0x55; 64]);
        let cases: [(
            BinaryMarketLayout,
            BinaryMarketCoordinatorAction,
            GeneratedBinaryMarketAction,
        ); 5] = [
            (
                BinaryMarketLayout::for_operation(
                    BinaryMarketCoordinatorRole::DormantYesRt,
                    BinaryMarketOperation::Issue,
                    None,
                )
                .expect("issue layout"),
                BinaryMarketCoordinatorAction::Issue { output_base: 11 },
                Either::Left(Either::Left(11)),
            ),
            (
                BinaryMarketLayout::for_operation(
                    BinaryMarketCoordinatorRole::UnresolvedYesRt,
                    BinaryMarketOperation::Cancel,
                    Some(false),
                )
                .expect("cancel layout"),
                BinaryMarketCoordinatorAction::Cancel { output_base: 12 },
                Either::Left(Either::Right(12)),
            ),
            (
                BinaryMarketLayout::for_operation(
                    BinaryMarketCoordinatorRole::DormantYesRt,
                    BinaryMarketOperation::Resolve,
                    None,
                )
                .expect("resolve layout"),
                BinaryMarketCoordinatorAction::Resolve {
                    output_base: 13,
                    resolution,
                },
                Either::Right(Either::Left((13, true, [0x55; 64]))),
            ),
            (
                BinaryMarketLayout::for_operation(
                    BinaryMarketCoordinatorRole::DormantYesRt,
                    BinaryMarketOperation::Expire,
                    None,
                )
                .expect("expire layout"),
                BinaryMarketCoordinatorAction::Expire { output_base: 14 },
                Either::Right(Either::Right(Either::Left(14))),
            ),
            (
                BinaryMarketLayout::for_operation(
                    BinaryMarketCoordinatorRole::ExpiredCollateral,
                    BinaryMarketOperation::Redeem,
                    None,
                )
                .expect("redeem layout"),
                BinaryMarketCoordinatorAction::Redeem { output_base: 15 },
                Either::Right(Either::Right(Either::Right(15))),
            ),
        ];

        for (layout, action, expected_action) in cases {
            for role in layout.input_roles() {
                let witness = BinaryMarketWitness::new(layout, *role, action).expect("witness");
                let raw = derived_binary_market::BinaryMarketWitness::from_witness(
                    &witness.build_witness(),
                )
                .expect("generated witness round trip");
                assert_eq!(raw.slot, role.slot().tag());
                assert_eq!(raw.action, expected_action);
            }
        }
    }

    #[test]
    fn checked_witness_facade_rejects_wrong_roles_actions_and_authorization() {
        let layout = BinaryMarketLayout::for_operation(
            BinaryMarketCoordinatorRole::DormantYesRt,
            BinaryMarketOperation::Issue,
            None,
        )
        .expect("issue layout");
        assert_eq!(
            layout.input_role(BinaryMarketSlot::UnresolvedYesRt),
            Err(BinaryMarketLayoutError::InputRoleNotInLayout {
                path: BinaryMarketPath::InitialIssuance,
                role: BinaryMarketInputRole::UnresolvedYesCoordinator,
            })
        );
        assert_eq!(
            BinaryMarketWitness::new(
                layout,
                BinaryMarketInputRole::DormantYesCoordinator,
                BinaryMarketCoordinatorAction::Cancel { output_base: 0 },
            ),
            Err(BinaryMarketLayoutError::ActionLayoutMismatch {
                path: BinaryMarketPath::InitialIssuance,
                operation: BinaryMarketOperation::Cancel,
            })
        );

        let resolve_layout = BinaryMarketLayout::for_operation(
            BinaryMarketCoordinatorRole::DormantYesRt,
            BinaryMarketOperation::Resolve,
            None,
        )
        .expect("resolve layout");
        assert_eq!(
            BinaryMarketCoordinatorAction::for_layout(resolve_layout, 0, None),
            Err(BinaryMarketLayoutError::MissingResolutionAuthorization)
        );
        assert_eq!(
            BinaryMarketCoordinatorAction::for_layout(
                layout,
                0,
                Some(BinaryMarketResolution::new(BinaryOutcome::No, [0; 64])),
            ),
            Err(BinaryMarketLayoutError::UnexpectedResolutionAuthorization {
                operation: BinaryMarketOperation::Issue,
            })
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
