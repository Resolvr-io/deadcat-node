//! Wallet-agnostic binary-market creation and lifecycle PSET construction.
//!
//! The builders own the covenant-constrained transaction surface: issuance
//! fields, deterministic confidential RT outputs, exact output windows, and
//! final Simplicity witnesses. Wallet funding, token delivery, collateral
//! refunds/payouts, fees, change, signing, and broadcasting remain local to the
//! caller.

use deadcat_contracts::SimplicityNetwork;
use deadcat_contracts::binary_market::{
    AppliedBinaryMarketTransition, BinaryMarketAction, BinaryMarketEconomics, BinaryMarketError,
    BinaryMarketSlot, BinaryMarketTransition, BinaryOutcome, CompiledBinaryMarket,
    derived_binary_market,
};
use deadcat_contracts::interpret::BinaryMarketPath;
use deadcat_contracts::market_crypto::{
    BinaryOutcome as OracleOutcome, derive_issuance_assets, oracle_message,
};
use deadcat_contracts::recovery::{
    MarketCollateral, MarketRecoveryHint, RecoveryError, recovery_txout,
};
use deadcat_contracts::rt::{
    RtCommitmentError, RtFactors, RtLeg, RtSide, commitments, factors, infer_side, tagged_hash,
};
use deadcat_types::{BinaryMarketParams, BinaryMarketState};
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::hashes::Hash as _;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::{
    Message, Secp256k1, SecretKey, SurjectionProof, Tweak, XOnlyPublicKey, ZERO_TWEAK,
    schnorr::Signature,
};
use elements::{
    AssetId, ContractHash, LockTime, OutPoint, RangeProofMessage, Script, Sequence, TxOut,
    TxOutSecrets, TxOutWitness,
};
use rand::SeedableRng as _;
use rand::rngs::StdRng;
use simplex::program::{ProgramTrait as _, WitnessTrait as _};
use thiserror::Error;

/// Network-known assets needed to verify a compact market recovery hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketCreationContext {
    pub policy_asset: AssetId,
    /// Set only when the active network assigns v1 collateral index 1.
    pub liquid_mainnet_usdt: Option<AssetId>,
}

/// The final issuance entropies required by later reissuance transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarketIssuanceEntropies {
    pub yes: [u8; 32],
    pub no: [u8; 32],
}

impl MarketIssuanceEntropies {
    /// Derive and validate the v1 zero-contract-hash issuance entropies.
    pub fn from_defining_outpoints(
        params: BinaryMarketParams,
        yes: OutPoint,
        no: OutPoint,
    ) -> Result<Self, MarketBuilderError> {
        let derived = derive_issuance_assets(yes, no);
        if derived.yes_token != params.yes_token_asset_id
            || derived.no_token != params.no_token_asset_id
            || derived.yes_reissuance_token != params.yes_reissuance_token_id
            || derived.no_reissuance_token != params.no_reissuance_token_id
        {
            return Err(MarketBuilderError::IssuanceAssetsMismatch);
        }
        let contract_hash = ContractHash::from_byte_array([0; 32]);
        Ok(Self {
            yes: AssetId::generate_asset_entropy(yes, contract_hash).to_byte_array(),
            no: AssetId::generate_asset_entropy(no, contract_hash).to_byte_array(),
        })
    }
}

/// A canonical standalone market-creation proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMarketCreationPlan {
    params: BinaryMarketParams,
    yes_defining_outpoint: OutPoint,
    no_defining_outpoint: OutPoint,
    entropies: MarketIssuanceEntropies,
    yes_factors: RtFactors,
    no_factors: RtFactors,
    outputs: [TxOut; 3],
}

impl BinaryMarketCreationPlan {
    pub fn new(
        context: MarketCreationContext,
        params: BinaryMarketParams,
        hint: MarketRecoveryHint,
        yes_defining_outpoint: OutPoint,
        no_defining_outpoint: OutPoint,
    ) -> Result<Self, MarketBuilderError> {
        validate_market_hint(context, params, hint)?;
        let compiled = compile(params)?;
        let entropies = MarketIssuanceEntropies::from_defining_outpoints(
            params,
            yes_defining_outpoint,
            no_defining_outpoint,
        )?;
        let yes_factors = factors(RtLeg::Yes, RtSide::A);
        let no_factors = factors(RtLeg::No, RtSide::A);
        let yes = confidential_rt_output_skeleton(
            params.yes_reissuance_token_id,
            yes_factors,
            compiled
                .slot(BinaryMarketSlot::DormantYesRt)
                .script_pubkey()
                .clone(),
        )?;
        let no = confidential_rt_output_skeleton(
            params.no_reissuance_token_id,
            no_factors,
            compiled
                .slot(BinaryMarketSlot::DormantNoRt)
                .script_pubkey()
                .clone(),
        )?;
        let recovery = recovery_txout(context.policy_asset, &hint.encode()?)?;
        Ok(Self {
            params,
            yes_defining_outpoint,
            no_defining_outpoint,
            entropies,
            yes_factors,
            no_factors,
            outputs: [yes, no, recovery],
        })
    }

    #[must_use]
    pub const fn params(&self) -> BinaryMarketParams {
        self.params
    }

    #[must_use]
    pub const fn entropies(&self) -> MarketIssuanceEntropies {
        self.entropies
    }

    #[must_use]
    pub const fn yes_factors(&self) -> RtFactors {
        self.yes_factors
    }

    #[must_use]
    pub const fn no_factors(&self) -> RtFactors {
        self.no_factors
    }

    #[must_use]
    pub const fn outputs(&self) -> &[TxOut; 3] {
        &self.outputs
    }

    /// Construct the canonical standalone proposal. The caller may append
    /// wallet change and an explicit policy-asset fee output before signing.
    pub fn build_pset(
        &self,
        mut yes_input: PsetInput,
        mut no_input: PsetInput,
    ) -> Result<PartiallySignedTransaction, MarketBuilderError> {
        if pset_outpoint(&yes_input) != self.yes_defining_outpoint
            || pset_outpoint(&no_input) != self.no_defining_outpoint
        {
            return Err(MarketBuilderError::WrongDefiningInput);
        }
        configure_new_issuance(&mut yes_input);
        configure_new_issuance(&mut no_input);
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(yes_input);
        pset.add_input(no_input);
        for output in &self.outputs {
            pset.add_output(PsetOutput::from_txout(output.clone()));
        }
        Ok(pset)
    }

    /// Complete deterministic RT surjection proofs after all wallet inputs
    /// have been added. Proof domains commit to the final input order, so a
    /// proof must be regenerated if a composer later changes that order.
    pub fn finalize_rt_proofs(
        &self,
        pset: &mut PartiallySignedTransaction,
    ) -> Result<(), MarketBuilderError> {
        let mut staged = pset.clone();
        if staged.inputs().len() < 2
            || pset_outpoint(&staged.inputs()[0]) != self.yes_defining_outpoint
            || pset_outpoint(&staged.inputs()[1]) != self.no_defining_outpoint
        {
            return Err(MarketBuilderError::WrongDefiningInput);
        }
        verify_new_issuance(&staged.inputs()[0], self.params.yes_reissuance_token_id)?;
        verify_new_issuance(&staged.inputs()[1], self.params.no_reissuance_token_id)?;
        if staged.inputs()[2..].iter().any(PsetInput::has_issuance) {
            return Err(MarketBuilderError::UnexpectedIssuance);
        }
        for (index, expected) in self.outputs.iter().enumerate() {
            let actual = staged
                .outputs()
                .get(index)
                .ok_or(MarketBuilderError::OutputIndexOutOfBounds)?
                .to_txout();
            if !output_matches_skeleton(&actual, expected) {
                return Err(MarketBuilderError::MandatoryOutputMismatch { index });
            }
        }
        install_rt_surjection_proof(
            &mut staged,
            0,
            self.params.yes_reissuance_token_id,
            self.yes_factors,
            &[],
        )?;
        install_rt_surjection_proof(
            &mut staged,
            1,
            self.params.no_reissuance_token_id,
            self.no_factors,
            &[],
        )?;
        *pset = staged;
        Ok(())
    }
}

/// One live RT backed by the exact raw chain output.
///
/// The A/B side is deliberately not trusted as caller-provided metadata. It is
/// inferred from `txout` whenever a transition plan is constructed and checked
/// again against the PSET's `witness_utxo` during finalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarketRtInput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

/// Exact live market outpoints used by a lifecycle plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BinaryMarketLiveInputs {
    pub yes_rt: Option<MarketRtInput>,
    pub no_rt: Option<MarketRtInput>,
    pub collateral: Option<OutPoint>,
}

/// Oracle authorization for a resolution transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleAttestation {
    pub outcome: BinaryOutcome,
    pub signature: [u8; 64],
}

/// Exact covenant contribution for one binary-market lifecycle operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryMarketTransitionPlan {
    params: BinaryMarketParams,
    before: BinaryMarketState,
    applied: AppliedBinaryMarketTransition,
    path: BinaryMarketPath,
    live: BinaryMarketLiveInputs,
    output_templates: Vec<TxOut>,
    yes_output_factors: Option<RtFactors>,
    no_output_factors: Option<RtFactors>,
    oracle_signature: [u8; 64],
    tokens_burned: u64,
    redeem_yes: bool,
}

impl BinaryMarketTransitionPlan {
    pub fn new(
        params: BinaryMarketParams,
        before: BinaryMarketState,
        action: BinaryMarketAction,
        live: BinaryMarketLiveInputs,
        attestation: Option<OracleAttestation>,
    ) -> Result<Self, MarketBuilderError> {
        let compiled = compile(params)?;
        let economics = BinaryMarketEconomics::new(params.base_payout)?;
        let applied = economics.apply(before, action)?;
        let path = select_path(before, action, applied)?;
        validate_live_shape(&compiled, params, before, path, &live)?;
        let oracle_signature = validate_attestation(params, action, attestation)?;
        let (tokens_burned, redeem_yes) = match action {
            BinaryMarketAction::Redeem { outcome, tokens } => {
                (tokens, outcome == BinaryOutcome::Yes)
            }
            _ => (0, false),
        };

        let mut yes_output_factors = None;
        let mut no_output_factors = None;
        let mut output_templates = Vec::new();
        if path_consumes_rt(path) {
            let yes = live
                .yes_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingYesRt)?;
            let no = live.no_rt.as_ref().ok_or(MarketBuilderError::MissingNoRt)?;
            let yes_side = infer_rt_side(yes, RtLeg::Yes, params.yes_reissuance_token_id)?;
            let no_side = infer_rt_side(no, RtLeg::No, params.no_reissuance_token_id)?;
            if yes_side != no_side {
                return Err(MarketBuilderError::MismatchedRtSides);
            }
            let yes_out = factors(RtLeg::Yes, yes_side.flip());
            let no_out = factors(RtLeg::No, no_side.flip());
            yes_output_factors = Some(yes_out);
            no_output_factors = Some(no_out);
            let (yes_slot, no_slot) = match path {
                BinaryMarketPath::InitialIssuance
                | BinaryMarketPath::SubsequentIssuance
                | BinaryMarketPath::PartialCancellation => (
                    BinaryMarketSlot::UnresolvedYesRt,
                    BinaryMarketSlot::UnresolvedNoRt,
                ),
                BinaryMarketPath::FullCancellation => (
                    BinaryMarketSlot::DormantYesRt,
                    BinaryMarketSlot::DormantNoRt,
                ),
                BinaryMarketPath::ActiveResolution
                | BinaryMarketPath::DormantResolution
                | BinaryMarketPath::ActiveExpiry
                | BinaryMarketPath::DormantExpiry => {
                    // Burns preserve CBF in the official builder.
                    output_templates.push(confidential_rt_output_skeleton(
                        params.yes_reissuance_token_id,
                        yes_out,
                        bare_op_return(),
                    )?);
                    output_templates.push(confidential_rt_output_skeleton(
                        params.no_reissuance_token_id,
                        no_out,
                        bare_op_return(),
                    )?);
                    (
                        BinaryMarketSlot::DormantYesRt,
                        BinaryMarketSlot::DormantNoRt,
                    )
                }
                BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption => {
                    unreachable!("redemption paths do not consume RTs")
                }
            };
            if !matches!(
                path,
                BinaryMarketPath::ActiveResolution
                    | BinaryMarketPath::DormantResolution
                    | BinaryMarketPath::ActiveExpiry
                    | BinaryMarketPath::DormantExpiry
            ) {
                output_templates.push(confidential_rt_output_skeleton(
                    params.yes_reissuance_token_id,
                    yes_out,
                    compiled.slot(yes_slot).script_pubkey().clone(),
                )?);
                output_templates.push(confidential_rt_output_skeleton(
                    params.no_reissuance_token_id,
                    no_out,
                    compiled.slot(no_slot).script_pubkey().clone(),
                )?);
            }
        }

        append_non_rt_outputs(
            &mut output_templates,
            &compiled,
            params,
            path,
            applied,
            tokens_burned,
            redeem_yes,
        );
        Ok(Self {
            params,
            before,
            applied,
            path,
            live,
            output_templates,
            yes_output_factors,
            no_output_factors,
            oracle_signature,
            tokens_burned,
            redeem_yes,
        })
    }

    #[must_use]
    pub const fn path(&self) -> BinaryMarketPath {
        self.path
    }

    #[must_use]
    pub const fn before(&self) -> BinaryMarketState {
        self.before
    }

    #[must_use]
    pub const fn after(&self) -> BinaryMarketState {
        self.applied.new_state
    }

    #[must_use]
    pub const fn transition(&self) -> BinaryMarketTransition {
        self.applied.transition
    }

    #[must_use]
    pub fn mandatory_output_templates(&self) -> &[TxOut] {
        &self.output_templates
    }

    /// Return the exact contiguous covenant output window at `output_base`.
    /// Confidential RT outputs are deterministic skeletons whose surjection
    /// proofs are installed by [`Self::finalize`] against the final input set.
    pub fn mandatory_outputs(
        &self,
        output_base: usize,
    ) -> Result<Vec<(usize, TxOut)>, MarketBuilderError> {
        self.output_templates
            .iter()
            .cloned()
            .enumerate()
            .map(|(offset, output)| {
                output_base
                    .checked_add(offset)
                    .map(|index| (index, output))
                    .ok_or(MarketBuilderError::IndexOverflow)
            })
            .collect()
    }

    /// Install the two exact explicit reissuances for an issuance plan.
    pub fn configure_reissuance_inputs(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_base: usize,
        entropies: MarketIssuanceEntropies,
    ) -> Result<(), MarketBuilderError> {
        let pairs = match self.applied.transition {
            BinaryMarketTransition::Issued { pairs, .. } => pairs,
            _ => return Err(MarketBuilderError::NotIssuancePath),
        };
        validate_entropies(self.params, entropies)?;
        let yes = self
            .live
            .yes_rt
            .as_ref()
            .ok_or(MarketBuilderError::MissingYesRt)?;
        let no = self
            .live
            .no_rt
            .as_ref()
            .ok_or(MarketBuilderError::MissingNoRt)?;
        let yes_side = infer_rt_side(yes, RtLeg::Yes, self.params.yes_reissuance_token_id)?;
        let no_side = infer_rt_side(no, RtLeg::No, self.params.no_reissuance_token_id)?;
        if yes_side != no_side {
            return Err(MarketBuilderError::MismatchedRtSides);
        }
        let no_index = add_index(input_base, 1)?;
        if no_index >= pset.inputs().len() {
            return Err(MarketBuilderError::InputIndexOutOfBounds);
        }
        configure_reissuance(
            &mut pset.inputs_mut()[input_base],
            pairs,
            entropies.yes,
            yes_side.abf(),
        )?;
        configure_reissuance(
            &mut pset.inputs_mut()[no_index],
            pairs,
            entropies.no,
            no_side.abf(),
        )?;
        Ok(())
    }

    /// Set the exact v1 expiry lock height and activate locktime on covenant
    /// inputs. Other wallet inputs may use any non-final sequence.
    pub fn prepare_expiry(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_base: usize,
    ) -> Result<(), MarketBuilderError> {
        if !matches!(
            self.path,
            BinaryMarketPath::ActiveExpiry | BinaryMarketPath::DormantExpiry
        ) {
            return Err(MarketBuilderError::NotExpiryPath);
        }
        pset.global.tx_data.fallback_locktime = Some(
            LockTime::from_height(self.params.expiry_height)
                .map_err(|_| MarketBuilderError::InvalidExpiryHeight)?,
        );
        for index in self.contract_input_indices(input_base)? {
            let input = pset
                .inputs_mut()
                .get_mut(index)
                .ok_or(MarketBuilderError::InputIndexOutOfBounds)?;
            input.sequence = Some(Sequence(0xffff_fffe));
        }
        Ok(())
    }

    /// Verify the composed PSET, execute every covenant input, and install all
    /// final script-path witnesses atomically.
    pub fn finalize(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_base: usize,
        output_base: usize,
        network: &SimplicityNetwork,
    ) -> Result<(), MarketBuilderError> {
        let mut staged = pset.clone();
        self.finalize_staged(&mut staged, input_base, output_base, network)?;
        *pset = staged;
        Ok(())
    }

    fn finalize_staged(
        &self,
        pset: &mut PartiallySignedTransaction,
        input_base: usize,
        output_base: usize,
        network: &SimplicityNetwork,
    ) -> Result<(), MarketBuilderError> {
        if pset
            .inputs()
            .iter()
            .any(|input| input.witness_utxo.is_none())
        {
            return Err(MarketBuilderError::MissingWitnessUtxo);
        }
        self.verify_inputs(pset, input_base)?;
        self.verify_expiry(pset, input_base)?;
        for (index, expected) in self.mandatory_outputs(output_base)? {
            let actual = pset
                .outputs()
                .get(index)
                .ok_or(MarketBuilderError::OutputIndexOutOfBounds)?
                .to_txout();
            if !output_matches_skeleton(&actual, &expected) {
                return Err(MarketBuilderError::MandatoryOutputMismatch { index });
            }
        }

        if path_consumes_rt(self.path) {
            let yes = self
                .live
                .yes_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingYesRt)?;
            let no = self
                .live
                .no_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingNoRt)?;
            let yes_side = infer_rt_side(yes, RtLeg::Yes, self.params.yes_reissuance_token_id)?;
            let no_side = infer_rt_side(no, RtLeg::No, self.params.no_reissuance_token_id)?;
            if yes_side != no_side {
                return Err(MarketBuilderError::MismatchedRtSides);
            }
            let known = [
                (
                    input_base,
                    self.params.yes_reissuance_token_id,
                    factors(RtLeg::Yes, yes_side),
                ),
                (
                    add_index(input_base, 1)?,
                    self.params.no_reissuance_token_id,
                    factors(RtLeg::No, no_side),
                ),
            ];
            install_rt_surjection_proof(
                pset,
                output_base,
                self.params.yes_reissuance_token_id,
                self.yes_output_factors
                    .ok_or(MarketBuilderError::MissingYesRt)?,
                &known,
            )?;
            install_rt_surjection_proof(
                pset,
                add_index(output_base, 1)?,
                self.params.no_reissuance_token_id,
                self.no_output_factors
                    .ok_or(MarketBuilderError::MissingNoRt)?,
                &known,
            )?;
        }

        let compiled = compile(self.params)?;
        let output_base_u32 =
            u32::try_from(output_base).map_err(|_| MarketBuilderError::IndexOverflow)?;
        let input_slots = self.input_slots();
        let mut finalized = Vec::with_capacity(input_slots.len());
        for (offset, slot) in input_slots.iter().copied().enumerate() {
            let input_index = add_index(input_base, offset)?;
            let oracle_outcome_yes = self.redeem_yes
                || matches!(
                    self.applied.transition,
                    BinaryMarketTransition::Resolved {
                        outcome: BinaryOutcome::Yes,
                        ..
                    }
                );
            let witness = derived_binary_market::BinaryMarketWitness {
                path: self.path as u8,
                slot: slot as u8,
                output_base: output_base_u32,
                oracle_outcome_yes,
                oracle_signature: self.oracle_signature,
                tokens_burned: self.tokens_burned,
                redeem_yes: self.redeem_yes,
            };
            let stack = compiled
                .program(slot)
                .as_ref()
                .finalize(pset, &witness.build_witness(), input_index, network)
                .map_err(|error| MarketBuilderError::Covenant(error.to_string()))?;
            let stack =
                crate::simplicity::ensure_budget(stack).map_err(MarketBuilderError::Covenant)?;
            finalized.push((input_index, stack));
        }
        for (input_index, stack) in finalized {
            pset.inputs_mut()[input_index].final_script_witness = Some(stack);
        }
        Ok(())
    }

    fn verify_inputs(
        &self,
        pset: &PartiallySignedTransaction,
        input_base: usize,
    ) -> Result<(), MarketBuilderError> {
        let compiled = compile(self.params)?;
        let slots = self.input_slots();
        let indices = self.contract_input_indices(input_base)?;
        for (index, slot) in indices.iter().copied().zip(slots.iter().copied()) {
            let input = pset
                .inputs()
                .get(index)
                .ok_or(MarketBuilderError::InputIndexOutOfBounds)?;
            let expected_outpoint = match slot {
                BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                    self.live
                        .yes_rt
                        .as_ref()
                        .ok_or(MarketBuilderError::MissingYesRt)?
                        .outpoint
                }
                BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => {
                    self.live
                        .no_rt
                        .as_ref()
                        .ok_or(MarketBuilderError::MissingNoRt)?
                        .outpoint
                }
                _ => self
                    .live
                    .collateral
                    .ok_or(MarketBuilderError::MissingCollateral)?,
            };
            if pset_outpoint(input) != expected_outpoint {
                return Err(MarketBuilderError::WrongContractInput);
            }
            let utxo = input
                .witness_utxo
                .as_ref()
                .ok_or(MarketBuilderError::MissingWitnessUtxo)?;
            if utxo.script_pubkey != *compiled.slot(slot).script_pubkey() {
                return Err(MarketBuilderError::WrongContractInput);
            }
            match slot {
                BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                    let live = self
                        .live
                        .yes_rt
                        .as_ref()
                        .ok_or(MarketBuilderError::MissingYesRt)?;
                    if utxo != &live.txout {
                        return Err(MarketBuilderError::WrongContractInput);
                    }
                    infer_rt_side(live, RtLeg::Yes, self.params.yes_reissuance_token_id)?;
                }
                BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => {
                    let live = self
                        .live
                        .no_rt
                        .as_ref()
                        .ok_or(MarketBuilderError::MissingNoRt)?;
                    if utxo != &live.txout {
                        return Err(MarketBuilderError::WrongContractInput);
                    }
                    infer_rt_side(live, RtLeg::No, self.params.no_reissuance_token_id)?;
                }
                _ => {
                    let amount = collateral_amount(self.params, self.before)?;
                    if utxo.asset != Asset::Explicit(self.params.collateral_asset_id)
                        || utxo.value != Value::Explicit(amount)
                    {
                        return Err(MarketBuilderError::WrongContractInput);
                    }
                }
            }
        }
        self.verify_issuance_fields(pset, input_base)
    }

    fn verify_issuance_fields(
        &self,
        pset: &PartiallySignedTransaction,
        input_base: usize,
    ) -> Result<(), MarketBuilderError> {
        let indices = self.contract_input_indices(input_base)?;
        if let BinaryMarketTransition::Issued { pairs, .. } = self.applied.transition {
            let yes = &pset.inputs()[indices[0]];
            let no = &pset.inputs()[indices[1]];
            let yes_rt = self
                .live
                .yes_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingYesRt)?;
            let no_rt = self
                .live
                .no_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingNoRt)?;
            let yes_side = infer_rt_side(yes_rt, RtLeg::Yes, self.params.yes_reissuance_token_id)?;
            let no_side = infer_rt_side(no_rt, RtLeg::No, self.params.no_reissuance_token_id)?;
            if yes_side != no_side {
                return Err(MarketBuilderError::MismatchedRtSides);
            }
            verify_reissuance(
                yes,
                pairs,
                yes_side.abf(),
                self.params.yes_token_asset_id,
                self.params.yes_reissuance_token_id,
            )?;
            verify_reissuance(
                no,
                pairs,
                no_side.abf(),
                self.params.no_token_asset_id,
                self.params.no_reissuance_token_id,
            )?;
            for index in indices.into_iter().skip(2) {
                if pset.inputs()[index].has_issuance() {
                    return Err(MarketBuilderError::UnexpectedIssuance);
                }
            }
        } else if indices
            .into_iter()
            .any(|index| pset.inputs()[index].has_issuance())
        {
            return Err(MarketBuilderError::UnexpectedIssuance);
        }
        Ok(())
    }

    fn verify_expiry(
        &self,
        pset: &PartiallySignedTransaction,
        input_base: usize,
    ) -> Result<(), MarketBuilderError> {
        if !matches!(
            self.path,
            BinaryMarketPath::ActiveExpiry | BinaryMarketPath::DormantExpiry
        ) {
            return Ok(());
        }
        let locktime = pset
            .global
            .tx_data
            .fallback_locktime
            .ok_or(MarketBuilderError::MissingExpiryLocktime)?;
        if locktime.to_consensus_u32() < self.params.expiry_height {
            return Err(MarketBuilderError::MissingExpiryLocktime);
        }
        if self
            .contract_input_indices(input_base)?
            .into_iter()
            .any(|index| {
                pset.inputs()[index]
                    .sequence
                    .is_none_or(|sequence| sequence == Sequence::MAX)
            })
        {
            return Err(MarketBuilderError::FinalExpirySequence);
        }
        Ok(())
    }

    fn input_slots(&self) -> Vec<BinaryMarketSlot> {
        match self.path {
            BinaryMarketPath::InitialIssuance
            | BinaryMarketPath::DormantResolution
            | BinaryMarketPath::DormantExpiry => vec![
                BinaryMarketSlot::DormantYesRt,
                BinaryMarketSlot::DormantNoRt,
            ],
            BinaryMarketPath::SubsequentIssuance
            | BinaryMarketPath::PartialCancellation
            | BinaryMarketPath::FullCancellation
            | BinaryMarketPath::ActiveResolution
            | BinaryMarketPath::ActiveExpiry => vec![
                BinaryMarketSlot::UnresolvedYesRt,
                BinaryMarketSlot::UnresolvedNoRt,
                BinaryMarketSlot::UnresolvedCollateral,
            ],
            BinaryMarketPath::ResolvedRedemption => vec![match self.before {
                BinaryMarketState::ResolvedYes { .. } => BinaryMarketSlot::ResolvedYesCollateral,
                BinaryMarketState::ResolvedNo { .. } => BinaryMarketSlot::ResolvedNoCollateral,
                _ => unreachable!("path selection validates resolved state"),
            }],
            BinaryMarketPath::ExpiryRedemption => vec![BinaryMarketSlot::ExpiredCollateral],
        }
    }

    fn contract_input_indices(&self, input_base: usize) -> Result<Vec<usize>, MarketBuilderError> {
        (0..self.input_slots().len())
            .map(|offset| add_index(input_base, offset))
            .collect()
    }
}

fn confidential_rt_output_skeleton(
    asset_id: AssetId,
    factors: RtFactors,
    script_pubkey: Script,
) -> Result<TxOut, MarketBuilderError> {
    let (asset, value) = commitments(asset_id, factors)?;
    let abf = AssetBlindingFactor::from_slice(&factors.abf)
        .map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
    let vbf = ValueBlindingFactor::from_slice(&factors.vbf)
        .map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
    let secp = Secp256k1::new();
    let message = RangeProofMessage {
        asset: asset_id,
        bf: abf,
    };
    let rewind = deterministic_secret(
        "deadcat/rt_rangeproof_rewind",
        &proof_context(asset_id, factors, &script_pubkey),
    )?;
    let (proved_value, rangeproof) = Value::Explicit(1)
        .blind_with_shared_secret(&secp, vbf, rewind, &script_pubkey, &message)
        .map_err(|error| MarketBuilderError::Confidential(error.to_string()))?;
    if proved_value != value {
        return Err(MarketBuilderError::CommitmentMismatch);
    }
    Ok(TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey,
        witness: TxOutWitness {
            surjection_proof: None,
            rangeproof: Some(Box::new(rangeproof)),
        },
    })
}

fn install_rt_surjection_proof(
    pset: &mut PartiallySignedTransaction,
    output_index: usize,
    asset_id: AssetId,
    factors: RtFactors,
    known_inputs: &[(usize, AssetId, RtFactors)],
) -> Result<(), MarketBuilderError> {
    use std::collections::HashMap;

    let mut secrets = HashMap::new();
    for (index, asset, factors) in known_inputs {
        let abf = AssetBlindingFactor::from_slice(&factors.abf)
            .map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
        let vbf = ValueBlindingFactor::from_slice(&factors.vbf)
            .map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
        secrets.insert(*index, TxOutSecrets::new(*asset, abf, 1, vbf));
    }
    let secp = Secp256k1::new();
    let domain = pset
        .surjection_inputs(&secrets)
        .map_err(|error| MarketBuilderError::Confidential(error.to_string()))?
        .into_iter()
        .enumerate()
        .map(|(index, input)| {
            input
                .surjection_target(&secp)
                .map_err(|error| MarketBuilderError::SurjectionInput {
                    index,
                    reason: error.to_string(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let output = pset
        .outputs()
        .get(output_index)
        .ok_or(MarketBuilderError::OutputIndexOutOfBounds)?
        .to_txout();
    let mut context = proof_context(asset_id, factors, &output.script_pubkey);
    for (generator, _, _) in &domain {
        context.extend_from_slice(&generator.serialize());
    }
    let mut rng = StdRng::from_seed(tagged_hash("deadcat/rt_surjection_proof", &context));
    let output_tweak =
        Tweak::from_inner(factors.abf).map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
    let proof = SurjectionProof::new(&secp, &mut rng, asset_id.into_tag(), output_tweak, &domain)
        .map_err(|error| MarketBuilderError::Confidential(error.to_string()))?;
    pset.outputs_mut()[output_index].asset_surjection_proof = Some(Box::new(proof));
    Ok(())
}

fn output_matches_skeleton(actual: &TxOut, expected: &TxOut) -> bool {
    actual.asset == expected.asset
        && actual.value == expected.value
        && actual.nonce == expected.nonce
        && actual.script_pubkey == expected.script_pubkey
        && actual.witness.rangeproof == expected.witness.rangeproof
        && (expected.witness.surjection_proof.is_none()
            || actual.witness.surjection_proof == expected.witness.surjection_proof)
}

fn proof_context(asset: AssetId, factors: RtFactors, script: &Script) -> Vec<u8> {
    let mut context = Vec::with_capacity(32 * 4 + script.len());
    context.extend_from_slice(&asset.into_inner().to_byte_array());
    context.extend_from_slice(&factors.abf);
    context.extend_from_slice(&factors.vbf);
    context.extend_from_slice(&factors.cbf);
    context.extend_from_slice(script.as_bytes());
    context
}

fn deterministic_secret(domain: &str, context: &[u8]) -> Result<SecretKey, MarketBuilderError> {
    for counter in 0_u32..=u32::MAX {
        let mut message = Vec::with_capacity(context.len() + 4);
        message.extend_from_slice(context);
        message.extend_from_slice(&counter.to_be_bytes());
        if let Ok(secret) = SecretKey::from_slice(&tagged_hash(domain, &message)) {
            return Ok(secret);
        }
    }
    Err(MarketBuilderError::InvalidDerivedSecret)
}

fn append_non_rt_outputs(
    outputs: &mut Vec<TxOut>,
    compiled: &CompiledBinaryMarket,
    params: BinaryMarketParams,
    path: BinaryMarketPath,
    applied: AppliedBinaryMarketTransition,
    tokens: u64,
    redeem_yes: bool,
) {
    match path {
        BinaryMarketPath::InitialIssuance | BinaryMarketPath::SubsequentIssuance => {
            outputs.push(explicit_txout(
                params.collateral_asset_id,
                trading_collateral(params, applied.new_state),
                compiled
                    .slot(BinaryMarketSlot::UnresolvedCollateral)
                    .script_pubkey()
                    .clone(),
            ));
        }
        BinaryMarketPath::PartialCancellation => {
            outputs.push(explicit_txout(
                params.collateral_asset_id,
                trading_collateral(params, applied.new_state),
                compiled
                    .slot(BinaryMarketSlot::UnresolvedCollateral)
                    .script_pubkey()
                    .clone(),
            ));
            outputs.push(explicit_txout(
                params.yes_token_asset_id,
                tokens_from_cancel(applied),
                bare_op_return(),
            ));
            outputs.push(explicit_txout(
                params.no_token_asset_id,
                tokens_from_cancel(applied),
                bare_op_return(),
            ));
        }
        BinaryMarketPath::FullCancellation => {
            outputs.push(explicit_txout(
                params.yes_token_asset_id,
                tokens_from_cancel(applied),
                bare_op_return(),
            ));
            outputs.push(explicit_txout(
                params.no_token_asset_id,
                tokens_from_cancel(applied),
                bare_op_return(),
            ));
        }
        BinaryMarketPath::ActiveResolution => {
            let slot = match applied.new_state {
                BinaryMarketState::ResolvedYes { .. } => BinaryMarketSlot::ResolvedYesCollateral,
                BinaryMarketState::ResolvedNo { .. } => BinaryMarketSlot::ResolvedNoCollateral,
                _ => unreachable!("resolution state"),
            };
            outputs.push(explicit_txout(
                params.collateral_asset_id,
                terminal_collateral(applied.new_state),
                compiled.slot(slot).script_pubkey().clone(),
            ));
        }
        BinaryMarketPath::ActiveExpiry => outputs.push(explicit_txout(
            params.collateral_asset_id,
            terminal_collateral(applied.new_state),
            compiled
                .slot(BinaryMarketSlot::ExpiredCollateral)
                .script_pubkey()
                .clone(),
        )),
        BinaryMarketPath::DormantResolution | BinaryMarketPath::DormantExpiry => {}
        BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption => {
            let (slot, remaining) = match applied.new_state {
                BinaryMarketState::ResolvedYes {
                    collateral_unredeemed,
                } => (
                    BinaryMarketSlot::ResolvedYesCollateral,
                    collateral_unredeemed,
                ),
                BinaryMarketState::ResolvedNo {
                    collateral_unredeemed,
                } => (
                    BinaryMarketSlot::ResolvedNoCollateral,
                    collateral_unredeemed,
                ),
                BinaryMarketState::Expired {
                    collateral_unredeemed,
                } => (BinaryMarketSlot::ExpiredCollateral, collateral_unredeemed),
                BinaryMarketState::Trading { .. } => unreachable!("redemption state"),
            };
            let asset = if redeem_yes {
                params.yes_token_asset_id
            } else {
                params.no_token_asset_id
            };
            if remaining > 0 {
                outputs.push(explicit_txout(
                    params.collateral_asset_id,
                    remaining,
                    compiled.slot(slot).script_pubkey().clone(),
                ));
            }
            outputs.push(explicit_txout(asset, tokens, bare_op_return()));
        }
    }
}

fn select_path(
    before: BinaryMarketState,
    action: BinaryMarketAction,
    applied: AppliedBinaryMarketTransition,
) -> Result<BinaryMarketPath, MarketBuilderError> {
    Ok(match action {
        BinaryMarketAction::Issue { .. } => match before {
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            } => BinaryMarketPath::InitialIssuance,
            BinaryMarketState::Trading { .. } => BinaryMarketPath::SubsequentIssuance,
            _ => return Err(MarketBuilderError::UnsupportedTransition),
        },
        BinaryMarketAction::Cancel { .. } => match applied.transition {
            BinaryMarketTransition::Cancelled { full: true, .. } => {
                BinaryMarketPath::FullCancellation
            }
            BinaryMarketTransition::Cancelled { full: false, .. } => {
                BinaryMarketPath::PartialCancellation
            }
            _ => return Err(MarketBuilderError::UnsupportedTransition),
        },
        BinaryMarketAction::Resolve { .. } => match before {
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            } => BinaryMarketPath::DormantResolution,
            BinaryMarketState::Trading { .. } => BinaryMarketPath::ActiveResolution,
            _ => return Err(MarketBuilderError::UnsupportedTransition),
        },
        BinaryMarketAction::Expire => match before {
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            } => BinaryMarketPath::DormantExpiry,
            BinaryMarketState::Trading { .. } => BinaryMarketPath::ActiveExpiry,
            _ => return Err(MarketBuilderError::UnsupportedTransition),
        },
        BinaryMarketAction::Redeem { .. } => match before {
            BinaryMarketState::ResolvedYes { .. } | BinaryMarketState::ResolvedNo { .. } => {
                BinaryMarketPath::ResolvedRedemption
            }
            BinaryMarketState::Expired { .. } => BinaryMarketPath::ExpiryRedemption,
            BinaryMarketState::Trading { .. } => {
                return Err(MarketBuilderError::UnsupportedTransition);
            }
        },
    })
}

fn validate_live_shape(
    compiled: &CompiledBinaryMarket,
    params: BinaryMarketParams,
    before: BinaryMarketState,
    path: BinaryMarketPath,
    live: &BinaryMarketLiveInputs,
) -> Result<(), MarketBuilderError> {
    BinaryMarketEconomics::new(params.base_payout)?.validate_state(before)?;
    match path {
        BinaryMarketPath::InitialIssuance
        | BinaryMarketPath::DormantResolution
        | BinaryMarketPath::DormantExpiry => {
            let yes = live
                .yes_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingYesRt)?;
            let no = live.no_rt.as_ref().ok_or(MarketBuilderError::MissingNoRt)?;
            if live.collateral.is_some() || yes.outpoint.txid != no.outpoint.txid {
                return Err(MarketBuilderError::InvalidSiblingGroup);
            }
            validate_rt_pair(
                compiled,
                params,
                yes,
                no,
                BinaryMarketSlot::DormantYesRt,
                BinaryMarketSlot::DormantNoRt,
            )?;
        }
        BinaryMarketPath::SubsequentIssuance
        | BinaryMarketPath::PartialCancellation
        | BinaryMarketPath::FullCancellation
        | BinaryMarketPath::ActiveResolution
        | BinaryMarketPath::ActiveExpiry => {
            let yes = live
                .yes_rt
                .as_ref()
                .ok_or(MarketBuilderError::MissingYesRt)?;
            let no = live.no_rt.as_ref().ok_or(MarketBuilderError::MissingNoRt)?;
            let collateral = live
                .collateral
                .ok_or(MarketBuilderError::MissingCollateral)?;
            if yes.outpoint.txid != no.outpoint.txid
                || yes.outpoint.txid != collateral.txid
                || no.outpoint.vout
                    != yes
                        .outpoint
                        .vout
                        .checked_add(1)
                        .ok_or(MarketBuilderError::IndexOverflow)?
                || collateral.vout
                    != yes
                        .outpoint
                        .vout
                        .checked_add(2)
                        .ok_or(MarketBuilderError::IndexOverflow)?
            {
                return Err(MarketBuilderError::InvalidSiblingGroup);
            }
            validate_rt_pair(
                compiled,
                params,
                yes,
                no,
                BinaryMarketSlot::UnresolvedYesRt,
                BinaryMarketSlot::UnresolvedNoRt,
            )?;
        }
        BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption => {
            if live.yes_rt.is_some() || live.no_rt.is_some() || live.collateral.is_none() {
                return Err(MarketBuilderError::InvalidSiblingGroup);
            }
        }
    }
    Ok(())
}

fn validate_rt_pair(
    compiled: &CompiledBinaryMarket,
    params: BinaryMarketParams,
    yes: &MarketRtInput,
    no: &MarketRtInput,
    yes_slot: BinaryMarketSlot,
    no_slot: BinaryMarketSlot,
) -> Result<(), MarketBuilderError> {
    if yes.txout.script_pubkey != *compiled.slot(yes_slot).script_pubkey()
        || no.txout.script_pubkey != *compiled.slot(no_slot).script_pubkey()
    {
        return Err(MarketBuilderError::WrongContractInput);
    }
    let yes_side = infer_rt_side(yes, RtLeg::Yes, params.yes_reissuance_token_id)?;
    let no_side = infer_rt_side(no, RtLeg::No, params.no_reissuance_token_id)?;
    if yes_side != no_side {
        return Err(MarketBuilderError::MismatchedRtSides);
    }
    Ok(())
}

fn infer_rt_side(
    input: &MarketRtInput,
    leg: RtLeg,
    asset_id: AssetId,
) -> Result<RtSide, MarketBuilderError> {
    infer_side(leg, asset_id, input.txout.asset, input.txout.value)
        .map_err(|_| MarketBuilderError::WrongContractInput)
}

fn validate_attestation(
    params: BinaryMarketParams,
    action: BinaryMarketAction,
    attestation: Option<OracleAttestation>,
) -> Result<[u8; 64], MarketBuilderError> {
    let BinaryMarketAction::Resolve { outcome } = action else {
        if attestation.is_some() {
            return Err(MarketBuilderError::UnexpectedOracleAttestation);
        }
        return Ok([0; 64]);
    };
    let attestation = attestation.ok_or(MarketBuilderError::MissingOracleAttestation)?;
    if attestation.outcome != outcome {
        return Err(MarketBuilderError::OracleOutcomeMismatch);
    }
    let public_key = XOnlyPublicKey::from_slice(&params.oracle_public_key)
        .map_err(|_| MarketBuilderError::InvalidOracleAttestation)?;
    let signature = Signature::from_slice(&attestation.signature)
        .map_err(|_| MarketBuilderError::InvalidOracleAttestation)?;
    let outcome = match outcome {
        BinaryOutcome::Yes => OracleOutcome::Yes,
        BinaryOutcome::No => OracleOutcome::No,
    };
    let message = Message::from_digest(oracle_message(
        params.yes_token_asset_id,
        params.no_token_asset_id,
        outcome,
    ));
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &message, &public_key)
        .map_err(|_| MarketBuilderError::InvalidOracleAttestation)?;
    Ok(attestation.signature)
}

fn validate_market_hint(
    context: MarketCreationContext,
    params: BinaryMarketParams,
    hint: MarketRecoveryHint,
) -> Result<(), MarketBuilderError> {
    let hinted_collateral = match hint.collateral {
        MarketCollateral::PolicyAsset => context.policy_asset,
        MarketCollateral::LiquidMainnetUsdt => context
            .liquid_mainnet_usdt
            .ok_or(MarketBuilderError::UnavailableCollateralIndex)?,
        MarketCollateral::Asset(asset) => asset,
    };
    if hint.oracle_public_key != params.oracle_public_key
        || hinted_collateral != params.collateral_asset_id
        || hint.base_payout != params.base_payout
        || hint.expiry_height != params.expiry_height
    {
        return Err(MarketBuilderError::RecoveryHintMismatch);
    }
    Ok(())
}

fn configure_new_issuance(input: &mut PsetInput) {
    input.issuance_value_amount = None;
    input.issuance_value_comm = None;
    input.issuance_inflation_keys = Some(1);
    input.issuance_inflation_keys_comm = None;
    input.issuance_blinding_nonce = Some(ZERO_TWEAK);
    input.issuance_asset_entropy = Some([0; 32]);
    input.blinded_issuance = Some(0);
}

fn verify_new_issuance(input: &PsetInput, expected_rt: AssetId) -> Result<(), MarketBuilderError> {
    if input.issuance_value_amount.is_some()
        || input.issuance_value_comm.is_some()
        || input.issuance_inflation_keys != Some(1)
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_blinding_nonce != Some(ZERO_TWEAK)
        || input.issuance_asset_entropy != Some([0; 32])
        || input.issuance_ids().1 != expected_rt
    {
        return Err(MarketBuilderError::WrongNewIssuance);
    }
    Ok(())
}

fn configure_reissuance(
    input: &mut PsetInput,
    pairs: u64,
    entropy: [u8; 32],
    abf: [u8; 32],
) -> Result<(), MarketBuilderError> {
    input.issuance_value_amount = Some(pairs);
    input.issuance_value_comm = None;
    input.issuance_inflation_keys = None;
    input.issuance_inflation_keys_comm = None;
    input.issuance_blinding_nonce =
        Some(Tweak::from_inner(abf).map_err(|_| MarketBuilderError::InvalidBlindingFactor)?);
    input.issuance_asset_entropy = Some(entropy);
    input.blinded_issuance = Some(0);
    Ok(())
}

fn verify_reissuance(
    input: &PsetInput,
    amount: u64,
    abf: [u8; 32],
    expected_asset: AssetId,
    expected_rt: AssetId,
) -> Result<(), MarketBuilderError> {
    let expected_tweak =
        Tweak::from_inner(abf).map_err(|_| MarketBuilderError::InvalidBlindingFactor)?;
    if input.issuance_value_amount != Some(amount)
        || input.issuance_value_comm.is_some()
        || input.issuance_inflation_keys.is_some()
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_blinding_nonce != Some(expected_tweak)
        || input.issuance_asset_entropy.is_none()
        || input.issuance_ids() != (expected_asset, expected_rt)
    {
        return Err(MarketBuilderError::WrongReissuance);
    }
    Ok(())
}

fn validate_entropies(
    params: BinaryMarketParams,
    entropies: MarketIssuanceEntropies,
) -> Result<(), MarketBuilderError> {
    let yes = elements::hashes::sha256::Midstate::from_byte_array(entropies.yes);
    let no = elements::hashes::sha256::Midstate::from_byte_array(entropies.no);
    if AssetId::from_entropy(yes) != params.yes_token_asset_id
        || AssetId::reissuance_token_from_entropy(yes, false) != params.yes_reissuance_token_id
        || AssetId::from_entropy(no) != params.no_token_asset_id
        || AssetId::reissuance_token_from_entropy(no, false) != params.no_reissuance_token_id
    {
        return Err(MarketBuilderError::IssuanceAssetsMismatch);
    }
    Ok(())
}

fn collateral_amount(
    params: BinaryMarketParams,
    state: BinaryMarketState,
) -> Result<u64, MarketBuilderError> {
    Ok(match state {
        BinaryMarketState::Trading { outstanding_pairs } => {
            BinaryMarketEconomics::new(params.base_payout)?
                .collateral_for_pairs(outstanding_pairs)?
        }
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        }
        | BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        }
        | BinaryMarketState::Expired {
            collateral_unredeemed,
        } => collateral_unredeemed,
    })
}

fn trading_collateral(params: BinaryMarketParams, state: BinaryMarketState) -> u64 {
    collateral_amount(params, state).expect("validated transition collateral")
}

fn terminal_collateral(state: BinaryMarketState) -> u64 {
    match state {
        BinaryMarketState::ResolvedYes {
            collateral_unredeemed,
        }
        | BinaryMarketState::ResolvedNo {
            collateral_unredeemed,
        }
        | BinaryMarketState::Expired {
            collateral_unredeemed,
        } => collateral_unredeemed,
        BinaryMarketState::Trading { .. } => unreachable!("terminal state"),
    }
}

fn tokens_from_cancel(applied: AppliedBinaryMarketTransition) -> u64 {
    match applied.transition {
        BinaryMarketTransition::Cancelled { pairs, .. } => pairs,
        _ => unreachable!("cancellation transition"),
    }
}

const fn path_consumes_rt(path: BinaryMarketPath) -> bool {
    !matches!(
        path,
        BinaryMarketPath::ResolvedRedemption | BinaryMarketPath::ExpiryRedemption
    )
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

fn bare_op_return() -> Script {
    Script::from(vec![0x6a])
}

fn pset_outpoint(input: &PsetInput) -> OutPoint {
    OutPoint::new(input.previous_txid, input.previous_output_index)
}

fn add_index(base: usize, offset: usize) -> Result<usize, MarketBuilderError> {
    base.checked_add(offset)
        .ok_or(MarketBuilderError::IndexOverflow)
}

fn compile(params: BinaryMarketParams) -> Result<CompiledBinaryMarket, MarketBuilderError> {
    CompiledBinaryMarket::new(params)
        .map_err(|error| MarketBuilderError::Compilation(error.to_string()))
}

#[derive(Debug, Error)]
pub enum MarketBuilderError {
    #[error("binary-market economics error: {0}")]
    Economics(#[from] BinaryMarketError),
    #[error("recovery encoding error: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("RT commitment error: {0}")]
    RtCommitment(#[from] RtCommitmentError),
    #[error("contract compilation failed: {0}")]
    Compilation(String),
    #[error("market recovery hint disagrees with the supplied parameters")]
    RecoveryHintMismatch,
    #[error("the recovery hint uses a collateral index unavailable on this network")]
    UnavailableCollateralIndex,
    #[error("the YES/NO issuance assets do not match their defining outpoints/entropies")]
    IssuanceAssetsMismatch,
    #[error("market creation inputs do not match the defining outpoints")]
    WrongDefiningInput,
    #[error("missing live YES RT")]
    MissingYesRt,
    #[error("missing live NO RT")]
    MissingNoRt,
    #[error("missing live collateral output")]
    MissingCollateral,
    #[error("market live outpoints do not form the required sibling group")]
    InvalidSiblingGroup,
    #[error("the live YES and NO RTs are on different A/B sides")]
    MismatchedRtSides,
    #[error("unsupported state/action transition")]
    UnsupportedTransition,
    #[error("resolution requires an oracle attestation")]
    MissingOracleAttestation,
    #[error("an oracle attestation was supplied for a non-resolution path")]
    UnexpectedOracleAttestation,
    #[error("oracle attestation outcome disagrees with the requested resolution")]
    OracleOutcomeMismatch,
    #[error("oracle attestation signature is invalid")]
    InvalidOracleAttestation,
    #[error("invalid deterministic confidential blinding factor")]
    InvalidBlindingFactor,
    #[error("failed to derive a valid deterministic rangeproof secret")]
    InvalidDerivedSecret,
    #[error("confidential proof construction failed: {0}")]
    Confidential(String),
    #[error("constructed rangeproof commitment disagrees with protocol commitments")]
    CommitmentMismatch,
    #[error("this operation is not an issuance path")]
    NotIssuancePath,
    #[error("this operation is not an expiry path")]
    NotExpiryPath,
    #[error("invalid v1 expiry height")]
    InvalidExpiryHeight,
    #[error("input or output index overflow")]
    IndexOverflow,
    #[error("PSET input index is out of bounds")]
    InputIndexOutOfBounds,
    #[error("PSET output index is out of bounds")]
    OutputIndexOutOfBounds,
    #[error("PSET is missing witness_utxo evidence")]
    MissingWitnessUtxo,
    #[error("PSET contract input does not match the plan")]
    WrongContractInput,
    #[error("PSET reissuance fields do not match the plan")]
    WrongReissuance,
    #[error("PSET new-issuance fields do not match the standalone creation plan")]
    WrongNewIssuance,
    #[error("surjection input {index} is unusable: {reason}")]
    SurjectionInput { index: usize, reason: String },
    #[error("non-issuance path has issuance attached to a covenant input")]
    UnexpectedIssuance,
    #[error("expiry PSET is missing the required lock height")]
    MissingExpiryLocktime,
    #[error("expiry PSET uses a final sequence on a covenant input")]
    FinalExpirySequence,
    #[error("mandatory covenant output at index {index} does not match the plan")]
    MandatoryOutputMismatch { index: usize },
    #[error("Simplicity covenant finalization failed: {0}")]
    Covenant(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use deadcat_contracts::recovery::{MarketRecoveryHint, validate_recovery_txout};
    use elements::hashes::Hash as _;
    use elements::pset::Input as PsetInput;
    use elements::secp256k1_zkp::{Keypair, RangeProof, SecretKey};
    use elements::{Txid, confidential::AssetBlindingFactor};

    use super::*;

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn oracle_keypair() -> Keypair {
        Keypair::from_seckey_slice(&Secp256k1::new(), &[0x31; 32]).expect("oracle key")
    }

    fn defining_outpoints() -> (OutPoint, OutPoint) {
        (
            OutPoint::new(Txid::from_byte_array([0x11; 32]), 3),
            OutPoint::new(Txid::from_byte_array([0x22; 32]), 4),
        )
    }

    fn params() -> BinaryMarketParams {
        let (yes, no) = defining_outpoints();
        let ids = derive_issuance_assets(yes, no);
        BinaryMarketParams {
            oracle_public_key: oracle_keypair().x_only_public_key().0.serialize(),
            collateral_asset_id: asset(0x51),
            yes_token_asset_id: ids.yes_token,
            no_token_asset_id: ids.no_token,
            yes_reissuance_token_id: ids.yes_reissuance_token,
            no_reissuance_token_id: ids.no_reissuance_token,
            base_payout: 100,
            expiry_height: 500,
        }
    }

    fn hint(params: BinaryMarketParams) -> MarketRecoveryHint {
        MarketRecoveryHint {
            oracle_public_key: params.oracle_public_key,
            collateral: MarketCollateral::Asset(params.collateral_asset_id),
            base_payout: params.base_payout,
            expiry_height: params.expiry_height,
        }
    }

    fn input(outpoint: OutPoint, witness_utxo: TxOut) -> PsetInput {
        let mut input = PsetInput::from_prevout(outpoint);
        input.witness_utxo = Some(witness_utxo);
        input
    }

    fn rt_input_txout(asset_id: AssetId, factors: RtFactors, script_pubkey: Script) -> TxOut {
        let (asset, value) = commitments(asset_id, factors).expect("RT commitments");
        TxOut {
            asset,
            value,
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        }
    }

    fn verify_surjection(
        pset: &PartiallySignedTransaction,
        output_index: usize,
        known: &[(usize, AssetId, RtFactors)],
    ) {
        let secp = Secp256k1::new();
        let mut secrets = HashMap::new();
        for (index, asset, factors) in known {
            secrets.insert(
                *index,
                TxOutSecrets::new(
                    *asset,
                    AssetBlindingFactor::from_slice(&factors.abf).expect("ABF"),
                    1,
                    ValueBlindingFactor::from_slice(&factors.vbf).expect("VBF"),
                ),
            );
        }
        let domain = pset
            .surjection_inputs(&secrets)
            .expect("surjection domain")
            .into_iter()
            .map(|input| input.surjection_target(&secp).expect("target").0)
            .collect::<Vec<_>>();
        let output = pset.outputs()[output_index].to_txout();
        output
            .witness
            .surjection_proof
            .as_ref()
            .expect("surjection proof")
            .verify(
                &secp,
                output.asset.commitment().expect("asset generator"),
                &domain,
            )
            .then_some(())
            .expect("valid surjection proof");
    }

    #[test]
    fn standalone_creation_builds_exact_issuances_and_final_input_domain_proofs() {
        let params = params();
        let (yes, no) = defining_outpoints();
        let context = MarketCreationContext {
            policy_asset: asset(0x99),
            liquid_mainnet_usdt: None,
        };
        let plan = BinaryMarketCreationPlan::new(context, params, hint(params), yes, no)
            .expect("creation plan");
        assert!(plan.outputs()[0].witness.surjection_proof.is_none());
        assert!(plan.outputs()[0].witness.rangeproof.is_some());

        let funding = explicit_txout(context.policy_asset, 10_000, Script::from(vec![0x51]));
        let mut pset = plan
            .build_pset(input(yes, funding.clone()), input(no, funding.clone()))
            .expect("creation PSET");
        pset.add_input(input(
            OutPoint::new(Txid::from_byte_array([0x33; 32]), 7),
            funding,
        ));
        let mut second = pset.clone();
        plan.finalize_rt_proofs(&mut pset).expect("proofs");
        plan.finalize_rt_proofs(&mut second).expect("proofs");
        assert_eq!(pset.outputs()[0].to_txout(), second.outputs()[0].to_txout());
        assert_eq!(pset.outputs()[1].to_txout(), second.outputs()[1].to_txout());
        verify_surjection(&pset, 0, &[]);
        verify_surjection(&pset, 1, &[]);

        let yes_output = pset.outputs()[0].to_txout();
        let rangeproof: &RangeProof = yes_output
            .witness
            .rangeproof
            .as_deref()
            .expect("rangeproof");
        let range = rangeproof
            .verify(
                &Secp256k1::new(),
                yes_output.value.commitment().expect("value commitment"),
                yes_output.script_pubkey.as_bytes(),
                yes_output.asset.commitment().expect("asset commitment"),
            )
            .expect("valid rangeproof");
        assert!(range.contains(&1));
        assert_eq!(pset.inputs()[0].issuance_value_amount, None);
        assert_eq!(pset.inputs()[0].issuance_inflation_keys, Some(1));
        assert_eq!(
            pset.inputs()[0].issuance_ids().1,
            params.yes_reissuance_token_id
        );
        let recovery_output = pset.outputs()[2].to_txout();
        let payload = validate_recovery_txout(&recovery_output, context.policy_asset)
            .expect("recovery envelope");
        assert_eq!(
            MarketRecoveryHint::decode(payload).expect("hint"),
            hint(params)
        );
    }

    fn sign_attestation(params: BinaryMarketParams, outcome: BinaryOutcome) -> OracleAttestation {
        let outcome_message = match outcome {
            BinaryOutcome::Yes => OracleOutcome::Yes,
            BinaryOutcome::No => OracleOutcome::No,
        };
        let digest = oracle_message(
            params.yes_token_asset_id,
            params.no_token_asset_id,
            outcome_message,
        );
        let signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(digest), &oracle_keypair());
        OracleAttestation {
            outcome,
            signature: signature.serialize(),
        }
    }

    fn live_for_state(state: BinaryMarketState) -> BinaryMarketLiveInputs {
        let params = params();
        let compiled = CompiledBinaryMarket::new(params).expect("compile");
        match state {
            BinaryMarketState::Trading {
                outstanding_pairs: 0,
            } => BinaryMarketLiveInputs {
                yes_rt: Some(MarketRtInput {
                    outpoint: OutPoint::new(Txid::from_byte_array([0x70; 32]), 2),
                    txout: rt_input_txout(
                        params.yes_reissuance_token_id,
                        factors(RtLeg::Yes, RtSide::A),
                        compiled
                            .slot(BinaryMarketSlot::DormantYesRt)
                            .script_pubkey()
                            .clone(),
                    ),
                }),
                no_rt: Some(MarketRtInput {
                    outpoint: OutPoint::new(Txid::from_byte_array([0x70; 32]), 9),
                    txout: rt_input_txout(
                        params.no_reissuance_token_id,
                        factors(RtLeg::No, RtSide::A),
                        compiled
                            .slot(BinaryMarketSlot::DormantNoRt)
                            .script_pubkey()
                            .clone(),
                    ),
                }),
                collateral: None,
            },
            BinaryMarketState::Trading { .. } => BinaryMarketLiveInputs {
                yes_rt: Some(MarketRtInput {
                    outpoint: OutPoint::new(Txid::from_byte_array([0x71; 32]), 4),
                    txout: rt_input_txout(
                        params.yes_reissuance_token_id,
                        factors(RtLeg::Yes, RtSide::B),
                        compiled
                            .slot(BinaryMarketSlot::UnresolvedYesRt)
                            .script_pubkey()
                            .clone(),
                    ),
                }),
                no_rt: Some(MarketRtInput {
                    outpoint: OutPoint::new(Txid::from_byte_array([0x71; 32]), 5),
                    txout: rt_input_txout(
                        params.no_reissuance_token_id,
                        factors(RtLeg::No, RtSide::B),
                        compiled
                            .slot(BinaryMarketSlot::UnresolvedNoRt)
                            .script_pubkey()
                            .clone(),
                    ),
                }),
                collateral: Some(OutPoint::new(Txid::from_byte_array([0x71; 32]), 6)),
            },
            BinaryMarketState::ResolvedYes { .. }
            | BinaryMarketState::ResolvedNo { .. }
            | BinaryMarketState::Expired { .. } => BinaryMarketLiveInputs {
                collateral: Some(OutPoint::new(Txid::from_byte_array([0x72; 32]), 8)),
                ..BinaryMarketLiveInputs::default()
            },
        }
    }

    fn pset_for_plan(
        plan: &BinaryMarketTransitionPlan,
        input_base: usize,
        output_base: usize,
    ) -> PartiallySignedTransaction {
        let params = plan.params;
        let compiled = CompiledBinaryMarket::new(params).expect("compile");
        let mut pset = PartiallySignedTransaction::new_v2();
        for index in 0..input_base {
            pset.add_input(input(
                OutPoint::new(Txid::from_byte_array([0x80; 32]), index as u32),
                explicit_txout(params.collateral_asset_id, 1, Script::from(vec![0x51])),
            ));
        }
        for slot in plan.input_slots() {
            let (outpoint, txout) = match slot {
                BinaryMarketSlot::DormantYesRt | BinaryMarketSlot::UnresolvedYesRt => {
                    let live = plan.live.yes_rt.as_ref().expect("YES live");
                    (live.outpoint, live.txout.clone())
                }
                BinaryMarketSlot::DormantNoRt | BinaryMarketSlot::UnresolvedNoRt => {
                    let live = plan.live.no_rt.as_ref().expect("NO live");
                    (live.outpoint, live.txout.clone())
                }
                _ => (
                    plan.live.collateral.expect("collateral live"),
                    explicit_txout(
                        params.collateral_asset_id,
                        collateral_amount(params, plan.before).expect("collateral"),
                        compiled.slot(slot).script_pubkey().clone(),
                    ),
                ),
            };
            pset.add_input(input(outpoint, txout));
        }
        while pset.outputs().len() < output_base {
            pset.add_output(PsetOutput::from_txout(explicit_txout(
                params.collateral_asset_id,
                1,
                Script::from(vec![0x51]),
            )));
        }
        for (_, output) in plan.mandatory_outputs(output_base).expect("outputs") {
            pset.add_output(PsetOutput::from_txout(output));
        }
        pset
    }

    #[test]
    fn every_market_path_finalizes_real_simplicity_witnesses() {
        let params = params();
        let cp = params.base_payout * 2;
        let cases = [
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
                BinaryMarketAction::Issue { pairs: 2 },
                None,
                BinaryMarketPath::InitialIssuance,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 3,
                },
                BinaryMarketAction::Issue { pairs: 2 },
                None,
                BinaryMarketPath::SubsequentIssuance,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 5,
                },
                BinaryMarketAction::Cancel { pairs: 2 },
                None,
                BinaryMarketPath::PartialCancellation,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 5,
                },
                BinaryMarketAction::Cancel { pairs: 5 },
                None,
                BinaryMarketPath::FullCancellation,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 3,
                },
                BinaryMarketAction::Resolve {
                    outcome: BinaryOutcome::Yes,
                },
                Some(sign_attestation(params, BinaryOutcome::Yes)),
                BinaryMarketPath::ActiveResolution,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
                BinaryMarketAction::Resolve {
                    outcome: BinaryOutcome::No,
                },
                Some(sign_attestation(params, BinaryOutcome::No)),
                BinaryMarketPath::DormantResolution,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 3,
                },
                BinaryMarketAction::Expire,
                None,
                BinaryMarketPath::ActiveExpiry,
            ),
            (
                BinaryMarketState::Trading {
                    outstanding_pairs: 0,
                },
                BinaryMarketAction::Expire,
                None,
                BinaryMarketPath::DormantExpiry,
            ),
            (
                BinaryMarketState::ResolvedYes {
                    collateral_unredeemed: 3 * cp,
                },
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                },
                None,
                BinaryMarketPath::ResolvedRedemption,
            ),
            (
                BinaryMarketState::ResolvedNo {
                    collateral_unredeemed: cp,
                },
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                },
                None,
                BinaryMarketPath::ResolvedRedemption,
            ),
            (
                BinaryMarketState::Expired {
                    collateral_unredeemed: 3 * params.base_payout,
                },
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::Yes,
                    tokens: 1,
                },
                None,
                BinaryMarketPath::ExpiryRedemption,
            ),
            (
                BinaryMarketState::Expired {
                    collateral_unredeemed: params.base_payout,
                },
                BinaryMarketAction::Redeem {
                    outcome: BinaryOutcome::No,
                    tokens: 1,
                },
                None,
                BinaryMarketPath::ExpiryRedemption,
            ),
        ];
        let entropies = MarketIssuanceEntropies::from_defining_outpoints(
            params,
            defining_outpoints().0,
            defining_outpoints().1,
        )
        .expect("entropies");
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };
        for (before, action, attestation, expected_path) in cases {
            let plan = BinaryMarketTransitionPlan::new(
                params,
                before,
                action,
                live_for_state(before),
                attestation,
            )
            .expect("transition plan");
            assert_eq!(plan.path(), expected_path);
            let input_base = 1;
            let output_base = 1;
            let mut pset = pset_for_plan(&plan, input_base, output_base);
            if matches!(
                expected_path,
                BinaryMarketPath::InitialIssuance | BinaryMarketPath::SubsequentIssuance
            ) {
                plan.configure_reissuance_inputs(&mut pset, input_base, entropies)
                    .expect("reissuance");
            }
            if matches!(
                expected_path,
                BinaryMarketPath::ActiveExpiry | BinaryMarketPath::DormantExpiry
            ) {
                plan.prepare_expiry(&mut pset, input_base)
                    .expect("expiry lock");
            }
            plan.finalize(&mut pset, input_base, output_base, &network)
                .unwrap_or_else(|error| panic!("{expected_path:?}: {error}"));
            for index in plan.contract_input_indices(input_base).expect("indices") {
                let stack = pset.inputs()[index]
                    .final_script_witness
                    .as_ref()
                    .expect("final witness");
                let (core, annex) = deadcat_contracts::interpret::strip_taproot_annex(stack);
                assert_eq!(core.len(), 4);
                assert!(
                    annex.is_none_or(|padding| padding.first() == Some(&0x50)),
                    "budget padding must be a Taproot annex"
                );
            }
            if path_consumes_rt(expected_path) {
                let yes = plan.live.yes_rt.as_ref().expect("yes");
                let no = plan.live.no_rt.as_ref().expect("no");
                let yes_side = infer_rt_side(yes, RtLeg::Yes, params.yes_reissuance_token_id)
                    .expect("YES side");
                let no_side =
                    infer_rt_side(no, RtLeg::No, params.no_reissuance_token_id).expect("NO side");
                let known = [
                    (
                        input_base,
                        params.yes_reissuance_token_id,
                        factors(RtLeg::Yes, yes_side),
                    ),
                    (
                        input_base + 1,
                        params.no_reissuance_token_id,
                        factors(RtLeg::No, no_side),
                    ),
                ];
                verify_surjection(&pset, output_base, &known);
                verify_surjection(&pset, output_base + 1, &known);
            }
        }
    }

    #[test]
    fn finalization_is_atomic_and_rejects_tampering_and_bad_expiry() {
        let params = params();
        let before = BinaryMarketState::Trading {
            outstanding_pairs: 3,
        };
        let mut mismatched = live_for_state(before);
        let no = mismatched.no_rt.as_mut().expect("live NO RT");
        let (asset, value) =
            commitments(params.no_reissuance_token_id, factors(RtLeg::No, RtSide::A))
                .expect("side-A NO commitments");
        no.txout.asset = asset;
        no.txout.value = value;
        assert!(matches!(
            BinaryMarketTransitionPlan::new(
                params,
                before,
                BinaryMarketAction::Expire,
                mismatched,
                None,
            ),
            Err(MarketBuilderError::MismatchedRtSides)
        ));

        let expiry = BinaryMarketTransitionPlan::new(
            params,
            before,
            BinaryMarketAction::Expire,
            live_for_state(before),
            None,
        )
        .expect("expiry plan");
        let network = SimplicityNetwork::ElementsRegtest {
            policy_asset: params.collateral_asset_id,
        };
        let mut pset = pset_for_plan(&expiry, 0, 0);
        let untouched = pset.clone();
        assert!(matches!(
            expiry.finalize(&mut pset, 0, 0, &network),
            Err(MarketBuilderError::MissingExpiryLocktime)
        ));
        assert_eq!(pset, untouched);

        expiry.prepare_expiry(&mut pset, 0).expect("prepare expiry");
        pset.outputs_mut()[2].amount = Some(599);
        let tampered = pset.clone();
        assert!(matches!(
            expiry.finalize(&mut pset, 0, 0, &network),
            Err(MarketBuilderError::MandatoryOutputMismatch { index: 2 })
        ));
        assert_eq!(pset, tampered);

        let bad = OracleAttestation {
            outcome: BinaryOutcome::Yes,
            signature: Signature::from_slice(&[1; 64])
                .unwrap_or_else(|_| {
                    Secp256k1::new().sign_schnorr_no_aux_rand(
                        &Message::from_digest([1; 32]),
                        &Keypair::from_secret_key(
                            &Secp256k1::new(),
                            &SecretKey::from_slice(&[2; 32]).expect("key"),
                        ),
                    )
                })
                .serialize(),
        };
        assert!(matches!(
            BinaryMarketTransitionPlan::new(
                params,
                before,
                BinaryMarketAction::Resolve {
                    outcome: BinaryOutcome::Yes
                },
                live_for_state(before),
                Some(bad),
            ),
            Err(MarketBuilderError::InvalidOracleAttestation)
        ));

        let dormant = BinaryMarketState::Trading {
            outstanding_pairs: 0,
        };
        let issuance = BinaryMarketTransitionPlan::new(
            params,
            dormant,
            BinaryMarketAction::Issue { pairs: 1 },
            live_for_state(dormant),
            None,
        )
        .expect("issuance plan");
        let mut issuance_pset = pset_for_plan(&issuance, 0, 0);
        let entropies = MarketIssuanceEntropies::from_defining_outpoints(
            params,
            defining_outpoints().0,
            defining_outpoints().1,
        )
        .expect("entropies");
        issuance
            .configure_reissuance_inputs(&mut issuance_pset, 0, entropies)
            .expect("reissuance fields");
        // Reissuance semantically exposes a zero token amount to Simplicity,
        // while the PSET must still reject a raw inflation-key field.
        issuance_pset.inputs_mut()[0].issuance_inflation_keys = Some(1);
        assert!(matches!(
            issuance.finalize(&mut issuance_pset, 0, 0, &network),
            Err(MarketBuilderError::WrongReissuance)
        ));
    }
}
