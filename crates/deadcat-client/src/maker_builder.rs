//! Wallet-agnostic maker-order PSET construction and covenant finalization.

use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::maker_order::{
    CompiledMakerOrder, MakerOrderError, create, derive_instance_id, derived_maker_order, fill,
};
use deadcat_contracts::recovery::{OrderRecoveryHint, RecoveryError, recovery_txout};
use deadcat_types::{MakerOrderParams, MakerOrderState, OrderDirection};
use elements::confidential::{Asset, Nonce, Value};
use elements::pset::PartiallySignedTransaction;
use elements::{AssetId, OutPoint, TxOut, TxOutWitness};
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakerOrderCreationOutputs {
    pub order: TxOut,
    pub recovery_hint: TxOut,
    pub offered_base_capacity: u64,
}

/// Construct the two canonical outputs contributed by an order creation.
/// Wallet funding/change/fee outputs remain the caller's responsibility.
pub fn maker_order_creation_outputs(
    policy_asset: AssetId,
    creation_input_prevouts: &[OutPoint],
    order_output_index: u32,
    params: MakerOrderParams,
    offered_base_capacity: u64,
    hint: OrderRecoveryHint,
) -> Result<MakerOrderCreationOutputs, MakerBuilderError> {
    let expected_instance_id = derive_instance_id(creation_input_prevouts, order_output_index)?;
    if params.instance_id != expected_instance_id {
        return Err(MakerBuilderError::InstanceIdMismatch);
    }
    if hint.direction != params.direction
        || hint.price != params.price
        || hint.min_active_base != params.min_active_base
        || hint.maker_pubkey != params.maker_pubkey
    {
        return Err(MakerBuilderError::RecoveryHintMismatch);
    }
    let creation = create(params, offered_base_capacity)?;
    let compiled = CompiledMakerOrder::new(params)
        .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
    let held_asset = match params.direction {
        OrderDirection::SellBase => params.base_asset_id,
        OrderDirection::SellQuote => params.quote_asset_id,
    };
    Ok(MakerOrderCreationOutputs {
        order: explicit_txout(
            held_asset,
            creation.locked_amount,
            compiled.script_pubkey().clone(),
        ),
        recovery_hint: recovery_txout(policy_asset, &hint.encode())?,
        offered_base_capacity,
    })
}

/// Mandatory exact outputs and typed state effect for one fill.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakerFillPlan {
    expected_outpoint: OutPoint,
    params: MakerOrderParams,
    input_locked: u64,
    maker_payment: u64,
    remainder_locked: Option<u64>,
    filled_base: u64,
    next_state: MakerOrderState,
}

impl MakerFillPlan {
    pub fn new(
        expected_outpoint: OutPoint,
        params: MakerOrderParams,
        input_locked: u64,
        fill_base: u64,
        prior_total_filled_base: u64,
    ) -> Result<Self, MakerBuilderError> {
        CompiledMakerOrder::new(params)
            .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
        let price = u64::from(params.price);
        let remaining_base = match params.direction {
            OrderDirection::SellBase => input_locked,
            OrderDirection::SellQuote => {
                if price == 0 || !input_locked.is_multiple_of(price) {
                    return Err(MakerBuilderError::NonIntegralSellQuoteInput);
                }
                input_locked / price
            }
        };
        if fill_base > remaining_base {
            return Err(MakerBuilderError::FillExceedsOrder);
        }
        let remainder_base = remaining_base - fill_base;
        let remainder_locked = if remainder_base == 0 {
            None
        } else {
            Some(match params.direction {
                OrderDirection::SellBase => remainder_base,
                OrderDirection::SellQuote => remainder_base
                    .checked_mul(price)
                    .ok_or(MakerBuilderError::ArithmeticOverflow)?,
            })
        };
        let maker_payment = match params.direction {
            OrderDirection::SellBase => fill_base
                .checked_mul(price)
                .ok_or(MakerBuilderError::ArithmeticOverflow)?,
            OrderDirection::SellQuote => fill_base,
        };
        let interpreted = fill(
            params,
            MakerOrderState::Active {
                remaining_base,
                total_filled_base: prior_total_filled_base,
            },
            input_locked,
            maker_payment,
            remainder_locked,
        )?;
        Ok(Self {
            expected_outpoint,
            params,
            input_locked,
            maker_payment,
            remainder_locked,
            filled_base: interpreted.filled_base,
            next_state: interpreted.next_state,
        })
    }

    #[must_use]
    pub const fn filled_base(&self) -> u64 {
        self.filled_base
    }

    #[must_use]
    pub const fn maker_payment(&self) -> u64 {
        self.maker_payment
    }

    #[must_use]
    pub const fn remainder_locked(&self) -> Option<u64> {
        self.remainder_locked
    }

    #[must_use]
    pub const fn next_state(&self) -> MakerOrderState {
        self.next_state
    }

    /// Return `(absolute_output_index, exact_output)` pairs the composer must
    /// install.
    pub fn mandatory_outputs(
        &self,
        payment_index: usize,
        remainder_index: Option<usize>,
    ) -> Result<Vec<(usize, TxOut)>, MakerBuilderError> {
        let compiled = CompiledMakerOrder::new(self.params)
            .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
        let payment_asset = match self.params.direction {
            OrderDirection::SellBase => self.params.quote_asset_id,
            OrderDirection::SellQuote => self.params.base_asset_id,
        };
        let mut outputs = vec![(
            payment_index,
            explicit_txout(
                payment_asset,
                self.maker_payment,
                compiled.maker_receive_spk().clone(),
            ),
        )];
        match (self.remainder_locked, remainder_index) {
            (None, None) => {}
            (Some(amount), Some(index)) if index != payment_index => {
                let held_asset = match self.params.direction {
                    OrderDirection::SellBase => self.params.base_asset_id,
                    OrderDirection::SellQuote => self.params.quote_asset_id,
                };
                outputs.push((
                    index,
                    explicit_txout(held_asset, amount, compiled.script_pubkey().clone()),
                ));
            }
            (Some(_), Some(_)) => return Err(MakerBuilderError::OutputAlias),
            (Some(_), None) => return Err(MakerBuilderError::MissingRemainderIndex),
            (None, Some(_)) => return Err(MakerBuilderError::UnexpectedRemainderIndex),
        }
        Ok(outputs)
    }

    /// Verify the composed PSET at the exact positional anchors, execute the
    /// covenant, and install its final script-path witness.
    pub fn finalize(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_index: usize,
        payment_index: usize,
        remainder_index: Option<usize>,
        network: &SimplicityNetwork,
    ) -> Result<(), MakerBuilderError> {
        let compiled = CompiledMakerOrder::new(self.params)
            .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
        let input = pset
            .inputs()
            .get(input_index)
            .ok_or(MakerBuilderError::InputIndexOutOfBounds)?;
        if OutPoint::new(input.previous_txid, input.previous_output_index) != self.expected_outpoint
        {
            return Err(MakerBuilderError::WrongOrderOutpoint);
        }
        let witness_utxo = input
            .witness_utxo
            .as_ref()
            .ok_or(MakerBuilderError::MissingWitnessUtxo)?;
        let held_asset = match self.params.direction {
            OrderDirection::SellBase => self.params.base_asset_id,
            OrderDirection::SellQuote => self.params.quote_asset_id,
        };
        if witness_utxo.script_pubkey != *compiled.script_pubkey()
            || witness_utxo.asset != Asset::Explicit(held_asset)
            || witness_utxo.value != Value::Explicit(self.input_locked)
        {
            return Err(MakerBuilderError::WrongOrderInput);
        }

        for (index, expected) in self.mandatory_outputs(payment_index, remainder_index)? {
            let actual = pset
                .outputs()
                .get(index)
                .ok_or(MakerBuilderError::OutputIndexOutOfBounds)?
                .to_txout();
            if actual != expected {
                return Err(MakerBuilderError::MandatoryOutputMismatch { index });
            }
        }
        if pset
            .inputs()
            .iter()
            .any(|input| input.witness_utxo.is_none())
        {
            return Err(MakerBuilderError::MissingWitnessUtxo);
        }

        let witness = derived_maker_order::MakerOrderWitness {
            payment_index: u32::try_from(payment_index)
                .map_err(|_| MakerBuilderError::OutputIndexOutOfBounds)?,
            is_partial: self.remainder_locked.is_some(),
            remainder_index: match remainder_index {
                Some(index) => {
                    u32::try_from(index).map_err(|_| MakerBuilderError::OutputIndexOutOfBounds)?
                }
                None if payment_index == 0 => 1,
                None => 0,
            },
        };
        let stack = compiled
            .program()
            .as_ref()
            .finalize(pset, &witness.build_witness(), input_index, network)
            .map_err(|error| MakerBuilderError::Covenant(error.to_string()))?;
        let stack = crate::simplicity::ensure_budget(stack).map_err(MakerBuilderError::Covenant)?;
        pset.inputs_mut()[input_index].final_script_witness = Some(stack);
        Ok(())
    }
}

fn explicit_txout(asset: AssetId, value: u64, script_pubkey: elements::Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

#[derive(Debug, Error)]
pub enum MakerBuilderError {
    #[error("maker-order economics error: {0}")]
    Economics(#[from] MakerOrderError),
    #[error("recovery encoding error: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("maker-order identity derivation failed: {0}")]
    Identity(#[from] deadcat_contracts::maker_order::MakerOrderIdentityError),
    #[error("contract compilation failed: {0}")]
    Compilation(String),
    #[error("maker-order parameters do not match the canonical creation inputs and vout")]
    InstanceIdMismatch,
    #[error("recovery hint economics disagree with order parameters")]
    RecoveryHintMismatch,
    #[error("SellQuote input is not an exact multiple of price")]
    NonIntegralSellQuoteInput,
    #[error("fill exceeds remaining order capacity")]
    FillExceedsOrder,
    #[error("checked monetary arithmetic overflowed")]
    ArithmeticOverflow,
    #[error("partial fill requires a remainder output index")]
    MissingRemainderIndex,
    #[error("full fill must not supply a remainder output index")]
    UnexpectedRemainderIndex,
    #[error("maker payment and remainder outputs cannot alias")]
    OutputAlias,
    #[error("order input index is out of bounds")]
    InputIndexOutOfBounds,
    #[error("PSET input is missing witness_utxo evidence")]
    MissingWitnessUtxo,
    #[error("PSET order input does not match the compiled covenant and explicit amount")]
    WrongOrderInput,
    #[error("PSET order input does not spend the fill plan's exact live outpoint")]
    WrongOrderOutpoint,
    #[error("mandatory output index is out of bounds")]
    OutputIndexOutOfBounds,
    #[error("mandatory covenant output at index {index} does not match the plan")]
    MandatoryOutputMismatch { index: usize },
    #[error("Simplicity covenant finalization failed: {0}")]
    Covenant(String),
}

#[cfg(test)]
mod tests {
    use deadcat_types::{ContractId, OrderDirection, OrderSide};
    use elements::hashes::Hash as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput};
    use elements::secp256k1_zkp::{Keypair, Secp256k1};
    use elements::{OutPoint, Txid};

    use super::*;

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn params(direction: OrderDirection, instance_id: [u8; 32]) -> MakerOrderParams {
        MakerOrderParams {
            base_asset_id: asset(0x11),
            quote_asset_id: asset(0x22),
            price: 7,
            min_active_base: 3,
            direction,
            instance_id,
            maker_pubkey: Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32])
                .expect("key")
                .x_only_public_key()
                .0
                .serialize(),
        }
    }

    #[test]
    fn creation_outputs_are_exact_and_recoverable() {
        let inputs = [OutPoint::new(Txid::from_byte_array([0x66; 32]), 1)];
        let order_output_index = 4;
        let params = params(
            OrderDirection::SellQuote,
            derive_instance_id(&inputs, order_output_index).expect("instance"),
        );
        let hint = OrderRecoveryHint {
            side: OrderSide::Yes,
            direction: params.direction,
            masked_order_index: 42,
            parent_market: ContractId::new(OutPoint::new(Txid::from_byte_array([0x77; 32]), 2))
                .into(),
            price: params.price,
            min_active_base: params.min_active_base,
            maker_pubkey: params.maker_pubkey,
        };
        let outputs = maker_order_creation_outputs(
            asset(0x99),
            &inputs,
            order_output_index,
            params,
            10,
            hint,
        )
        .expect("outputs");
        assert_eq!(outputs.order.asset, Asset::Explicit(params.quote_asset_id));
        assert_eq!(outputs.order.value, Value::Explicit(70));
        assert_eq!(
            OrderRecoveryHint::decode(
                deadcat_contracts::recovery::validate_recovery_txout(
                    &outputs.recovery_hint,
                    asset(0x99),
                )
                .expect("envelope")
            )
            .expect("hint"),
            hint
        );

        let mut noncanonical = params;
        noncanonical.instance_id = [0x42; 32];
        assert!(matches!(
            maker_order_creation_outputs(
                asset(0x99),
                &inputs,
                order_output_index,
                noncanonical,
                10,
                hint
            ),
            Err(MakerBuilderError::InstanceIdMismatch)
        ));
    }

    #[test]
    fn partial_fill_plan_finalizes_real_covenant_witness() {
        let live_outpoint = OutPoint::new(Txid::from_byte_array([0x88; 32]), 0);
        let params = params(OrderDirection::SellBase, [0x55; 32]);
        let plan = MakerFillPlan::new(live_outpoint, params, 10, 4, 9).expect("plan");
        assert_eq!(plan.maker_payment(), 28);
        assert_eq!(plan.remainder_locked(), Some(6));
        assert_eq!(
            plan.next_state(),
            MakerOrderState::Active {
                remaining_base: 6,
                total_filled_base: 13,
            }
        );

        let compiled = CompiledMakerOrder::new(params).expect("compile");
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = PsetInput::from_prevout(live_outpoint);
        input.witness_utxo = Some(explicit_txout(
            params.base_asset_id,
            10,
            compiled.script_pubkey().clone(),
        ));
        pset.add_input(input);
        for (_, output) in plan.mandatory_outputs(0, Some(1)).expect("outputs") {
            pset.add_output(PsetOutput::from_txout(output));
        }
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.quote_asset_id,
        };
        plan.finalize(&mut pset, 0, 0, Some(1), &network)
            .expect("finalize");
        assert_eq!(
            pset.inputs()[0]
                .final_script_witness
                .as_ref()
                .expect("witness")
                .len(),
            4
        );
    }

    #[test]
    fn plan_rejects_dust_and_output_aliasing() {
        let outpoint = OutPoint::new(Txid::from_byte_array([0x99; 32]), 3);
        let params = params(OrderDirection::SellBase, [0x55; 32]);
        assert!(matches!(
            MakerFillPlan::new(outpoint, params, 10, 8, 0),
            Err(MakerBuilderError::Economics(
                MakerOrderError::RemainderBelowMinimum
            ))
        ));
        let plan = MakerFillPlan::new(outpoint, params, 10, 4, 0).expect("plan");
        assert!(matches!(
            plan.mandatory_outputs(0, Some(0)),
            Err(MakerBuilderError::OutputAlias)
        ));
    }

    #[test]
    fn fill_plan_is_bound_to_the_exact_live_outpoint() {
        let expected = OutPoint::new(Txid::from_byte_array([0xaa; 32]), 1);
        let wrong = OutPoint::new(Txid::from_byte_array([0xbb; 32]), 1);
        let params = params(OrderDirection::SellBase, [0x55; 32]);
        let plan = MakerFillPlan::new(expected, params, 10, 4, 0).expect("plan");
        let compiled = CompiledMakerOrder::new(params).expect("compile");
        let mut pset = PartiallySignedTransaction::new_v2();
        let mut input = PsetInput::from_prevout(wrong);
        input.witness_utxo = Some(explicit_txout(
            params.base_asset_id,
            10,
            compiled.script_pubkey().clone(),
        ));
        pset.add_input(input);
        for (_, output) in plan.mandatory_outputs(0, Some(1)).expect("outputs") {
            pset.add_output(PsetOutput::from_txout(output));
        }
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.quote_asset_id,
        };
        assert!(matches!(
            plan.finalize(&mut pset, 0, 0, Some(1), &network),
            Err(MakerBuilderError::WrongOrderOutpoint)
        ));
    }
}
