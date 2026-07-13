//! Wallet-agnostic maker-order PSET construction and covenant finalization.

use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::maker_order::{
    CompiledMakerOrder, MakerOrderError, create, derived_maker_order, fill,
};
use deadcat_contracts::recovery::{OrderRecoveryHint, RecoveryError, recovery_txout};
use deadcat_types::{MakerOrderParams, MakerOrderState, OrderDirection};
use elements::confidential::{Asset, Nonce, Value};
use elements::pset::PartiallySignedTransaction;
use elements::{AssetId, Script, TxOut, TxOutWitness};
use sha2::{Digest as _, Sha256};
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
    params: MakerOrderParams,
    offered_base_capacity: u64,
    maker_receive_spk: &Script,
    hint: OrderRecoveryHint,
) -> Result<MakerOrderCreationOutputs, MakerBuilderError> {
    ensure_receive_script(params, maker_receive_spk)?;
    if hint.direction != params.direction
        || hint.price != params.price
        || hint.min_active_base != params.min_active_base
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
    params: MakerOrderParams,
    maker_receive_spk: Script,
    input_locked: u64,
    maker_payment: u64,
    remainder_locked: Option<u64>,
    filled_base: u64,
    next_state: MakerOrderState,
}

impl MakerFillPlan {
    pub fn new(
        params: MakerOrderParams,
        maker_receive_spk: Script,
        input_locked: u64,
        fill_base: u64,
        prior_total_filled_base: u64,
    ) -> Result<Self, MakerBuilderError> {
        ensure_receive_script(params, &maker_receive_spk)?;
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
            params,
            maker_receive_spk,
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
    /// install. Maker payment is anchored to the order input index.
    pub fn mandatory_outputs(
        &self,
        input_index: usize,
        remainder_index: Option<usize>,
    ) -> Result<Vec<(usize, TxOut)>, MakerBuilderError> {
        let payment_asset = match self.params.direction {
            OrderDirection::SellBase => self.params.quote_asset_id,
            OrderDirection::SellQuote => self.params.base_asset_id,
        };
        let mut outputs = vec![(
            input_index,
            explicit_txout(
                payment_asset,
                self.maker_payment,
                self.maker_receive_spk.clone(),
            ),
        )];
        match (self.remainder_locked, remainder_index) {
            (None, None) => {}
            (Some(amount), Some(index)) if index != input_index => {
                let held_asset = match self.params.direction {
                    OrderDirection::SellBase => self.params.base_asset_id,
                    OrderDirection::SellQuote => self.params.quote_asset_id,
                };
                let compiled = CompiledMakerOrder::new(self.params)
                    .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
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
        remainder_index: Option<usize>,
        network: &SimplicityNetwork,
    ) -> Result<(), MakerBuilderError> {
        let compiled = CompiledMakerOrder::new(self.params)
            .map_err(|error| MakerBuilderError::Compilation(error.to_string()))?;
        let input = pset
            .inputs()
            .get(input_index)
            .ok_or(MakerBuilderError::InputIndexOutOfBounds)?;
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

        for (index, expected) in self.mandatory_outputs(input_index, remainder_index)? {
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
            remainder_index: u32::try_from(remainder_index.unwrap_or(0))
                .map_err(|_| MakerBuilderError::OutputIndexOutOfBounds)?,
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

fn explicit_txout(asset: AssetId, value: u64, script_pubkey: Script) -> TxOut {
    TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness::default(),
    }
}

fn ensure_receive_script(
    params: MakerOrderParams,
    maker_receive_spk: &Script,
) -> Result<(), MakerBuilderError> {
    let hash: [u8; 32] = Sha256::digest(maker_receive_spk.as_bytes()).into();
    if hash != params.maker_receive_spk_hash {
        return Err(MakerBuilderError::ReceiveScriptMismatch);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum MakerBuilderError {
    #[error("maker-order economics error: {0}")]
    Economics(#[from] MakerOrderError),
    #[error("recovery encoding error: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("contract compilation failed: {0}")]
    Compilation(String),
    #[error("maker receive script does not match committed hash")]
    ReceiveScriptMismatch,
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
    #[error("mandatory output index is out of bounds")]
    OutputIndexOutOfBounds,
    #[error("mandatory covenant output at index {index} does not match the plan")]
    MandatoryOutputMismatch { index: usize },
    #[error("Simplicity covenant finalization failed: {0}")]
    Covenant(String),
}

#[cfg(test)]
mod tests {
    use deadcat_types::{OrderDirection, OrderSide};
    use elements::hashes::Hash as _;
    use elements::pset::{Input as PsetInput, Output as PsetOutput};
    use elements::secp256k1_zkp::{Keypair, Secp256k1};
    use elements::{OutPoint, Txid};

    use super::*;

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn receive_script() -> Script {
        Script::from(
            vec![0x51, 0x20]
                .into_iter()
                .chain([0x44; 32])
                .collect::<Vec<_>>(),
        )
    }

    fn params(direction: OrderDirection) -> MakerOrderParams {
        let receive = receive_script();
        MakerOrderParams {
            base_asset_id: asset(0x11),
            quote_asset_id: asset(0x22),
            price: 7,
            min_active_base: 3,
            direction,
            maker_receive_spk_hash: Sha256::digest(receive.as_bytes()).into(),
            maker_pubkey: Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32])
                .expect("key")
                .x_only_public_key()
                .0
                .serialize(),
        }
    }

    #[test]
    fn creation_outputs_are_exact_and_recoverable() {
        let params = params(OrderDirection::SellQuote);
        let hint = OrderRecoveryHint {
            side: OrderSide::Yes,
            direction: params.direction,
            masked_order_index: 42,
            market_creation_txid: Txid::from_byte_array([0x77; 32]),
            price: params.price,
            min_active_base: params.min_active_base,
        };
        let outputs =
            maker_order_creation_outputs(asset(0x99), params, 10, &receive_script(), hint)
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
    }

    #[test]
    fn partial_fill_plan_finalizes_real_covenant_witness() {
        let params = params(OrderDirection::SellBase);
        let plan = MakerFillPlan::new(params, receive_script(), 10, 4, 9).expect("plan");
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
        let mut input =
            PsetInput::from_prevout(OutPoint::new(Txid::from_byte_array([0x88; 32]), 0));
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
        plan.finalize(&mut pset, 0, Some(1), &network)
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
        let params = params(OrderDirection::SellBase);
        assert!(matches!(
            MakerFillPlan::new(params, receive_script(), 10, 8, 0),
            Err(MakerBuilderError::Economics(
                MakerOrderError::RemainderBelowMinimum
            ))
        ));
        let plan = MakerFillPlan::new(params, receive_script(), 10, 4, 0).expect("plan");
        assert!(matches!(
            plan.mandatory_outputs(0, Some(0)),
            Err(MakerBuilderError::OutputAlias)
        ));
    }
}
