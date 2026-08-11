//! Provisional, venue-neutral transaction composition.
//!
//! Venue adapters contribute narrow symbolic input and output specifications,
//! never independently assembled PSETs. The composer allocates every global
//! position once, resolves blinder input references, appends the sole network
//! fee output, and returns an unblinded-structure manifest.
//!
//! The manifest freezes transaction-body fields and the clear asset/amount
//! metadata from which ordinary confidential outputs are blinded. It is not a
//! signing authorization check: after blinding, each signer must additionally
//! validate its sighash policy, commitment disclosures, consensus proofs, and
//! recipient openings. Venue-specific covenant finalizers remain responsible
//! for their own witnesses and proof domains.
//!
//! This first seam intentionally supports native-witness, non-issuing inputs,
//! exact exclusive outputs, trusted client-local covenant output templates,
//! absolute locktime requirements, and non-RBF sequences. Output aggregation,
//! relative timelocks, issuance, peg-ins, and arbitrary ordering constraints
//! require concrete venue designs and are not guessed here.

use std::collections::BTreeMap;

use elements::bitcoin::PublicKey;
use elements::pset::{Input as PsetInput, Output as PsetOutput, PartiallySignedTransaction};
use elements::{AssetId, LockTime, OutPoint, Script, Sequence, TxOut};
use thiserror::Error;

/// Contribution-local symbolic identity for one transaction input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InputId(u64);

impl InputId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Contribution-local symbolic identity for one transaction output claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputId(u64);

impl OutputId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Input responsible for blinding one ordinary confidential output.
///
/// Local references are resolved within the output's own contribution.
/// External references use an exact outpoint, avoiding numeric-ID coordination
/// between independently prepared contributions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlinderRef {
    Local(InputId),
    External(OutPoint),
}

/// Exact sequence profiles supported by the first composer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputSequence {
    /// Final input; does not activate transaction locktime.
    Final,
    /// Non-final and non-RBF input used to activate absolute locktime.
    LocktimeEnabled,
}

impl InputSequence {
    #[must_use]
    pub const fn to_sequence(self) -> Sequence {
        match self {
            Self::Final => Sequence::MAX,
            Self::LocktimeEnabled => Sequence(0xffff_fffe),
        }
    }
}

/// Narrow specification for an ordinary input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputSpec {
    id: InputId,
    outpoint: OutPoint,
    witness_utxo: TxOut,
    sequence: InputSequence,
}

impl InputSpec {
    #[must_use]
    pub const fn new(
        id: InputId,
        outpoint: OutPoint,
        witness_utxo: TxOut,
        sequence: InputSequence,
    ) -> Self {
        Self {
            id,
            outpoint,
            witness_utxo,
            sequence,
        }
    }

    #[must_use]
    pub const fn id(&self) -> InputId {
        self.id
    }

    #[must_use]
    pub const fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    #[must_use]
    pub const fn witness_utxo(&self) -> &TxOut {
        &self.witness_utxo
    }

    #[must_use]
    pub const fn sequence(&self) -> InputSequence {
        self.sequence
    }
}

/// Exact output kind supported by the first composer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputSpec {
    /// Confidential recipient output, assigned to one symbolic blinder input.
    Confidential {
        id: OutputId,
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
        blinding_key: PublicKey,
        blinder: BlinderRef,
    },
    /// Explicit non-fee output. Empty scripts are reserved for the sole fee.
    Explicit {
        id: OutputId,
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
    },
    /// Exact committed output produced only by a trusted client-local covenant
    /// builder. The private template type prevents remote venue data from
    /// entering the composer as an arbitrary PSET output.
    Covenant {
        id: OutputId,
        template: CovenantOutputTemplate,
    },
}

/// Exact covenant output body with no public constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CovenantOutputTemplate(TxOut);

impl CovenantOutputTemplate {
    pub(crate) fn trusted(txout: TxOut) -> Self {
        Self(txout)
    }

    #[must_use]
    pub const fn txout(&self) -> &TxOut {
        &self.0
    }
}

impl OutputSpec {
    #[must_use]
    pub const fn confidential(
        id: OutputId,
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
        blinding_key: PublicKey,
        blinder: BlinderRef,
    ) -> Self {
        Self::Confidential {
            id,
            asset,
            amount,
            script_pubkey,
            blinding_key,
            blinder,
        }
    }

    #[must_use]
    pub const fn explicit(
        id: OutputId,
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
    ) -> Self {
        Self::Explicit {
            id,
            asset,
            amount,
            script_pubkey,
        }
    }

    #[must_use]
    pub const fn id(&self) -> OutputId {
        match self {
            Self::Confidential { id, .. }
            | Self::Explicit { id, .. }
            | Self::Covenant { id, .. } => *id,
        }
    }

    #[must_use]
    pub const fn asset_amount(&self) -> Option<(AssetId, u64)> {
        match self {
            Self::Confidential { asset, amount, .. } | Self::Explicit { asset, amount, .. } => {
                Some((*asset, *amount))
            }
            Self::Covenant { .. } => None,
        }
    }

    #[must_use]
    pub const fn confidential_recipient(&self) -> Option<(&Script, PublicKey)> {
        match self {
            Self::Confidential {
                script_pubkey,
                blinding_key,
                ..
            } => Some((script_pubkey, *blinding_key)),
            Self::Explicit { .. } | Self::Covenant { .. } => None,
        }
    }

    #[must_use]
    pub const fn blinder(&self) -> Option<BlinderRef> {
        match self {
            Self::Confidential { blinder, .. } => Some(*blinder),
            Self::Explicit { .. } | Self::Covenant { .. } => None,
        }
    }

    pub(crate) fn covenant(id: OutputId, txout: TxOut) -> Self {
        Self::Covenant {
            id,
            template: CovenantOutputTemplate::trusted(txout),
        }
    }
}

/// Absolute transaction-locktime requirement contributed by one participant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LockTimeConstraint {
    #[default]
    Unconstrained,
    /// The final transaction locktime must be at least this value.
    AtLeast(LockTime),
    /// The final transaction locktime must equal this value.
    Exact(LockTime),
}

/// One deterministic, contiguous input/output contribution.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransactionContribution {
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
    locktime: LockTimeConstraint,
}

impl TransactionContribution {
    #[must_use]
    pub fn new(
        inputs: Vec<InputSpec>,
        outputs: Vec<OutputSpec>,
        locktime: LockTimeConstraint,
    ) -> Self {
        Self {
            inputs,
            outputs,
            locktime,
        }
    }

    #[must_use]
    pub fn inputs(&self) -> &[InputSpec] {
        &self.inputs
    }

    #[must_use]
    pub fn outputs(&self) -> &[OutputSpec] {
        &self.outputs
    }

    #[must_use]
    pub const fn locktime(&self) -> LockTimeConstraint {
        self.locktime
    }
}

/// Hard local bounds applied before proof generation or signing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompositionLimits {
    pub max_contributions: usize,
    pub max_inputs: usize,
    pub max_outputs: usize,
    pub max_script_pubkey_bytes: usize,
    pub max_unblinded_pset_bytes: usize,
}

impl Default for CompositionLimits {
    fn default() -> Self {
        Self {
            max_contributions: 8,
            max_inputs: 32,
            max_outputs: 32,
            max_script_pubkey_bytes: 10_000,
            max_unblinded_pset_bytes: 1_000_000,
        }
    }
}

/// Exact explicit Liquid network fee created only by the composer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkFee {
    policy_asset: AssetId,
    amount: u64,
}

impl NetworkFee {
    pub fn new(policy_asset: AssetId, amount: u64) -> Result<Self, CompositionError> {
        if amount == 0 {
            return Err(CompositionError::ZeroNetworkFee);
        }
        Ok(Self {
            policy_asset,
            amount,
        })
    }

    #[must_use]
    pub const fn policy_asset(self) -> AssetId {
        self.policy_asset
    }

    #[must_use]
    pub const fn amount(self) -> u64 {
        self.amount
    }
}

/// Opaque handle returned when a contribution is appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContributionHandle(usize);

/// Final contiguous placement for one contribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContributionPlacement {
    input_base: usize,
    input_count: usize,
    output_base: usize,
    output_count: usize,
}

impl ContributionPlacement {
    #[must_use]
    pub const fn input_base(self) -> usize {
        self.input_base
    }

    #[must_use]
    pub const fn input_count(self) -> usize {
        self.input_count
    }

    #[must_use]
    pub const fn output_base(self) -> usize {
        self.output_base
    }

    #[must_use]
    pub const fn output_count(self) -> usize {
        self.output_count
    }

    #[must_use]
    pub fn input_index(self, local_index: usize) -> Option<usize> {
        (local_index < self.input_count).then(|| self.input_base + local_index)
    }

    #[must_use]
    pub fn output_index(self, local_index: usize) -> Option<usize> {
        (local_index < self.output_count).then(|| self.output_base + local_index)
    }
}

/// Symbolic-to-physical position map for a completed composition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompositionLayout {
    input_indices: BTreeMap<(ContributionHandle, InputId), usize>,
    output_indices: BTreeMap<(ContributionHandle, OutputId), usize>,
    outpoint_indices: BTreeMap<OutPoint, usize>,
    placements: Vec<ContributionPlacement>,
    fee_output_index: usize,
}

impl CompositionLayout {
    #[must_use]
    pub fn input_index(&self, handle: ContributionHandle, id: InputId) -> Option<usize> {
        self.input_indices.get(&(handle, id)).copied()
    }

    #[must_use]
    pub fn output_index(&self, handle: ContributionHandle, id: OutputId) -> Option<usize> {
        self.output_indices.get(&(handle, id)).copied()
    }

    #[must_use]
    pub fn outpoint_index(&self, outpoint: OutPoint) -> Option<usize> {
        self.outpoint_indices.get(&outpoint).copied()
    }

    #[must_use]
    pub fn placement(&self, handle: ContributionHandle) -> Option<ContributionPlacement> {
        self.placements.get(handle.0).copied()
    }

    #[must_use]
    pub const fn fee_output_index(&self) -> usize {
        self.fee_output_index
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManifestInput {
    outpoint: OutPoint,
    witness_utxo: TxOut,
    sequence: Sequence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ManifestOutput {
    Confidential {
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
        blinding_key: PublicKey,
        blinder_index: u32,
    },
    Explicit {
        asset: AssetId,
        amount: u64,
        script_pubkey: Script,
    },
    Covenant(CovenantOutputTemplate),
    Fee(NetworkFee),
}

/// Frozen unblinded transaction-structure expectations.
///
/// This deliberately ignores participant signing metadata, collaborative
/// blinding scalar state, and—for ordinary confidential outputs—post-blinding
/// commitments and proofs. It is therefore necessary but not sufficient before
/// signing. A signer must also run its own complete sighash, proof, and
/// recipient-opening validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnblindedStructureManifest {
    inputs: Vec<ManifestInput>,
    outputs: Vec<ManifestOutput>,
    locktime: LockTime,
}

impl UnblindedStructureManifest {
    /// Revalidate the transaction body and original clear output declarations.
    ///
    /// This is not a signing-intent or post-blinding proof validator.
    pub fn validate(&self, pset: &PartiallySignedTransaction) -> Result<(), CompositionError> {
        if pset.global.version != 2 || pset.global.tx_data.version != 2 {
            return Err(CompositionError::UnexpectedVersion);
        }
        if pset.global.tx_data.tx_modifiable.unwrap_or(0) != 0
            || pset.global.elements_tx_modifiable_flag.unwrap_or(0) != 0
        {
            return Err(CompositionError::TransactionModifiable);
        }
        if !pset.global.xpub.is_empty()
            || !pset.global.proprietary.is_empty()
            || !pset.global.unknown.is_empty()
        {
            return Err(CompositionError::UnexpectedGlobalMetadata);
        }
        if pset
            .global
            .tx_data
            .fallback_locktime
            .unwrap_or(LockTime::ZERO)
            != self.locktime
        {
            return Err(CompositionError::LockTimeMismatch);
        }
        if pset.inputs().len() != self.inputs.len() || pset.outputs().len() != self.outputs.len() {
            return Err(CompositionError::ShapeMismatch);
        }

        for (index, (actual, expected)) in pset.inputs().iter().zip(&self.inputs).enumerate() {
            let actual_outpoint = OutPoint::new(actual.previous_txid, actual.previous_output_index);
            if actual_outpoint != expected.outpoint {
                return Err(CompositionError::InputMismatch { index });
            }
            let Some(actual_utxo) = actual.witness_utxo.as_ref() else {
                return Err(CompositionError::InputMismatch { index });
            };
            if !same_prevout_body(actual_utxo, &expected.witness_utxo)
                || actual.in_utxo_rangeproof != expected.witness_utxo.witness.rangeproof
                || actual.sequence.unwrap_or(Sequence::MAX) != expected.sequence
                || actual.required_height_locktime.is_some()
                || actual.required_time_locktime.is_some()
                || actual.final_script_sig.is_some()
                || has_issuance_metadata(actual)
                || has_pegin(actual)
                || !actual.proprietary.is_empty()
                || !actual.unknown.is_empty()
            {
                return Err(CompositionError::InputMismatch { index });
            }
        }

        for (index, (actual, expected)) in pset.outputs().iter().zip(&self.outputs).enumerate() {
            if !actual.proprietary.is_empty() || !actual.unknown.is_empty() {
                return Err(CompositionError::OutputMismatch { index });
            }
            match expected {
                ManifestOutput::Confidential {
                    asset,
                    amount,
                    script_pubkey,
                    blinding_key,
                    blinder_index,
                } => {
                    if actual.asset != Some(*asset)
                        || actual.amount != Some(*amount)
                        || actual.script_pubkey != *script_pubkey
                        || actual.blinding_key != Some(*blinding_key)
                        || actual.blinder_index != Some(*blinder_index)
                    {
                        return Err(CompositionError::OutputMismatch { index });
                    }
                }
                ManifestOutput::Explicit {
                    asset,
                    amount,
                    script_pubkey,
                } => {
                    if !is_exact_explicit_output(actual, *asset, *amount, script_pubkey) {
                        return Err(CompositionError::OutputMismatch { index });
                    }
                }
                ManifestOutput::Covenant(template) => {
                    if !matches_covenant_template(actual, template.txout()) {
                        return Err(CompositionError::OutputMismatch { index });
                    }
                }
                ManifestOutput::Fee(fee) => {
                    if !is_exact_explicit_output(
                        actual,
                        fee.policy_asset,
                        fee.amount,
                        &Script::new(),
                    ) {
                        return Err(CompositionError::OutputMismatch { index });
                    }
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn locktime(&self) -> LockTime {
        self.locktime
    }
}

/// Complete unblinded PSET, its symbolic layout, and its frozen manifest.
#[derive(Clone, Debug)]
pub struct ComposedTransaction {
    pset: PartiallySignedTransaction,
    layout: CompositionLayout,
    manifest: UnblindedStructureManifest,
}

impl ComposedTransaction {
    #[must_use]
    pub const fn pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    #[must_use]
    pub const fn layout(&self) -> &CompositionLayout {
        &self.layout
    }

    #[must_use]
    pub const fn manifest(&self) -> &UnblindedStructureManifest {
        &self.manifest
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PartiallySignedTransaction,
        CompositionLayout,
        UnblindedStructureManifest,
    ) {
        (self.pset, self.layout, self.manifest)
    }
}

/// Deterministic append-only transaction composer.
#[derive(Clone, Debug)]
pub struct TransactionComposer {
    limits: CompositionLimits,
    fee: NetworkFee,
    contributions: Vec<TransactionContribution>,
}

impl TransactionComposer {
    #[must_use]
    pub const fn new(limits: CompositionLimits, fee: NetworkFee) -> Self {
        Self {
            limits,
            fee,
            contributions: Vec::new(),
        }
    }

    pub fn push(
        &mut self,
        contribution: TransactionContribution,
    ) -> Result<ContributionHandle, CompositionError> {
        if self.contributions.len() >= self.limits.max_contributions {
            return Err(CompositionError::TooManyContributions);
        }
        let handle = ContributionHandle(self.contributions.len());
        self.contributions.push(contribution);
        Ok(handle)
    }

    pub fn finish(self) -> Result<ComposedTransaction, CompositionError> {
        if self.contributions.is_empty() {
            return Err(CompositionError::NoContributions);
        }
        let input_count = self
            .contributions
            .iter()
            .try_fold(0_usize, |total, contribution| {
                total.checked_add(contribution.inputs.len())
            })
            .ok_or(CompositionError::LimitOverflow)?;
        let non_fee_output_count = self
            .contributions
            .iter()
            .try_fold(0_usize, |total, contribution| {
                total.checked_add(contribution.outputs.len())
            })
            .ok_or(CompositionError::LimitOverflow)?;
        let output_count = non_fee_output_count
            .checked_add(1)
            .ok_or(CompositionError::LimitOverflow)?;
        if input_count == 0 {
            return Err(CompositionError::NoInputs);
        }
        if input_count > self.limits.max_inputs {
            return Err(CompositionError::TooManyInputs);
        }
        if output_count > self.limits.max_outputs {
            return Err(CompositionError::TooManyOutputs);
        }

        let locktime = resolve_locktime(
            self.contributions
                .iter()
                .map(TransactionContribution::locktime),
        )?;
        // Absolute nLockTime is activated transaction-wide: any non-final
        // input is sufficient, even when a different contribution requires
        // the lock. Checking a designated input would recreate H-1's bug.
        let has_non_final = self
            .contributions
            .iter()
            .flat_map(TransactionContribution::inputs)
            .any(|input| input.sequence().to_sequence() != Sequence::MAX);
        if locktime != LockTime::ZERO && !has_non_final {
            return Err(CompositionError::InactiveLockTime);
        }

        let mut pset = PartiallySignedTransaction::new_v2();
        pset.global.tx_data.fallback_locktime = Some(locktime);
        pset.global.tx_data.tx_modifiable = Some(0);
        pset.global.elements_tx_modifiable_flag = Some(0);
        let mut input_indices = BTreeMap::new();
        let mut output_indices = BTreeMap::new();
        let mut outpoint_indices = BTreeMap::new();
        let mut placements = Vec::with_capacity(self.contributions.len());
        let mut manifest_inputs = Vec::with_capacity(input_count);

        for (contribution_index, contribution) in self.contributions.iter().enumerate() {
            let handle = ContributionHandle(contribution_index);
            let input_base = pset.inputs().len();
            for input in contribution.inputs() {
                let input_index = pset.inputs().len();
                if input_indices
                    .insert((handle, input.id()), input_index)
                    .is_some()
                {
                    return Err(CompositionError::DuplicateInputId(input.id()));
                }
                if input.outpoint().is_null() || input.outpoint().vout & 0xc000_0000 != 0 {
                    return Err(CompositionError::UnsupportedOutpoint(input.outpoint()));
                }
                if !input.witness_utxo().script_pubkey.is_witness_program() {
                    return Err(CompositionError::NonWitnessInput(input.outpoint()));
                }
                if input.witness_utxo().script_pubkey.len() > self.limits.max_script_pubkey_bytes {
                    return Err(CompositionError::ScriptPubkeyTooLarge);
                }
                if outpoint_indices
                    .insert(input.outpoint(), input_index)
                    .is_some()
                {
                    return Err(CompositionError::DuplicateOutpoint(input.outpoint()));
                }
                let mut pset_input = PsetInput::from_prevout(input.outpoint());
                pset_input.witness_utxo = Some(input.witness_utxo().clone());
                // TxOut witnesses are not encoded inside PSET_IN_WITNESS_UTXO.
                // Preserve the input rangeproof in its dedicated Elements
                // field so a serialized handoff carries the complete proof.
                pset_input.in_utxo_rangeproof = input.witness_utxo().witness.rangeproof.clone();
                pset_input.sequence = Some(input.sequence().to_sequence());
                pset.add_input(pset_input);
                manifest_inputs.push(ManifestInput {
                    outpoint: input.outpoint(),
                    witness_utxo: input.witness_utxo().clone(),
                    sequence: input.sequence().to_sequence(),
                });
            }
            placements.push(ContributionPlacement {
                input_base,
                input_count: contribution.inputs().len(),
                output_base: 0,
                output_count: contribution.outputs().len(),
            });
        }

        let mut manifest_outputs = Vec::with_capacity(output_count);
        for (contribution_index, contribution) in self.contributions.iter().enumerate() {
            let handle = ContributionHandle(contribution_index);
            let output_base = pset.outputs().len();
            placements[contribution_index].output_base = output_base;
            for output in contribution.outputs() {
                let output_index = pset.outputs().len();
                if output_indices
                    .insert((handle, output.id()), output_index)
                    .is_some()
                {
                    return Err(CompositionError::DuplicateOutputId(output.id()));
                }
                match output {
                    OutputSpec::Confidential {
                        asset,
                        amount,
                        script_pubkey,
                        blinding_key,
                        blinder,
                        ..
                    } => {
                        validate_ordinary_output(
                            *amount,
                            script_pubkey,
                            self.limits.max_script_pubkey_bytes,
                        )?;
                        let blinder_index = match blinder {
                            BlinderRef::Local(input_id) => input_indices
                                .get(&(handle, *input_id))
                                .copied()
                                .ok_or(CompositionError::UnknownLocalBlinder(*input_id))?,
                            BlinderRef::External(outpoint) => outpoint_indices
                                .get(outpoint)
                                .copied()
                                .ok_or(CompositionError::UnknownExternalBlinder(*outpoint))?,
                        };
                        let blinder_index = u32::try_from(blinder_index)
                            .map_err(|_| CompositionError::BlinderIndexOverflow)?;
                        let mut pset_output = PsetOutput::new_explicit(
                            script_pubkey.clone(),
                            *amount,
                            *asset,
                            Some(*blinding_key),
                        );
                        pset_output.blinder_index = Some(blinder_index);
                        pset.add_output(pset_output);
                        manifest_outputs.push(ManifestOutput::Confidential {
                            asset: *asset,
                            amount: *amount,
                            script_pubkey: script_pubkey.clone(),
                            blinding_key: *blinding_key,
                            blinder_index,
                        });
                    }
                    OutputSpec::Explicit {
                        asset,
                        amount,
                        script_pubkey,
                        ..
                    } => {
                        validate_ordinary_output(
                            *amount,
                            script_pubkey,
                            self.limits.max_script_pubkey_bytes,
                        )?;
                        pset.add_output(PsetOutput::new_explicit(
                            script_pubkey.clone(),
                            *amount,
                            *asset,
                            None,
                        ));
                        manifest_outputs.push(ManifestOutput::Explicit {
                            asset: *asset,
                            amount: *amount,
                            script_pubkey: script_pubkey.clone(),
                        });
                    }
                    OutputSpec::Covenant { template, .. } => {
                        validate_covenant_template(
                            template.txout(),
                            self.limits.max_script_pubkey_bytes,
                        )?;
                        pset.add_output(PsetOutput::from_txout(template.txout().clone()));
                        manifest_outputs.push(ManifestOutput::Covenant(template.clone()));
                    }
                }
            }
        }

        let fee_output_index = pset.outputs().len();
        pset.add_output(PsetOutput::from_txout(TxOut::new_fee(
            self.fee.amount,
            self.fee.policy_asset,
        )));
        manifest_outputs.push(ManifestOutput::Fee(self.fee));
        let layout = CompositionLayout {
            input_indices,
            output_indices,
            outpoint_indices,
            placements,
            fee_output_index,
        };
        if elements::encode::serialize(&pset).len() > self.limits.max_unblinded_pset_bytes {
            return Err(CompositionError::UnblindedPsetTooLarge);
        }
        let manifest = UnblindedStructureManifest {
            inputs: manifest_inputs,
            outputs: manifest_outputs,
            locktime,
        };
        manifest.validate(&pset)?;
        Ok(ComposedTransaction {
            pset,
            layout,
            manifest,
        })
    }
}

fn validate_ordinary_output(
    amount: u64,
    script_pubkey: &Script,
    max_script_pubkey_bytes: usize,
) -> Result<(), CompositionError> {
    if amount == 0 {
        return Err(CompositionError::ZeroOutputAmount);
    }
    if script_pubkey.is_empty() {
        return Err(CompositionError::ReservedFeeScript);
    }
    if script_pubkey.is_provably_unspendable() {
        return Err(CompositionError::UnspendableOrdinaryOutput);
    }
    if script_pubkey.len() > max_script_pubkey_bytes {
        return Err(CompositionError::ScriptPubkeyTooLarge);
    }
    Ok(())
}

fn validate_covenant_template(
    template: &TxOut,
    max_script_pubkey_bytes: usize,
) -> Result<(), CompositionError> {
    if template.script_pubkey.is_empty() {
        return Err(CompositionError::ReservedFeeScript);
    }
    if template.script_pubkey.len() > max_script_pubkey_bytes {
        return Err(CompositionError::ScriptPubkeyTooLarge);
    }
    Ok(())
}

fn resolve_locktime(
    constraints: impl IntoIterator<Item = LockTimeConstraint>,
) -> Result<LockTime, CompositionError> {
    let mut minimum: Option<LockTime> = None;
    let mut exact: Option<LockTime> = None;
    for constraint in constraints {
        match constraint {
            LockTimeConstraint::Unconstrained => {}
            LockTimeConstraint::AtLeast(candidate) => {
                if candidate == LockTime::ZERO {
                    continue;
                }
                minimum = Some(match minimum {
                    None => candidate,
                    Some(current) if current.is_same_unit(candidate) => {
                        if current.to_consensus_u32() >= candidate.to_consensus_u32() {
                            current
                        } else {
                            candidate
                        }
                    }
                    Some(_) => return Err(CompositionError::IncompatibleLockTimeUnits),
                });
            }
            LockTimeConstraint::Exact(candidate) => {
                if exact.is_some_and(|current| current != candidate) {
                    return Err(CompositionError::IncompatibleExactLockTimes);
                }
                exact = Some(candidate);
            }
        }
    }
    if let Some(exact) = exact {
        if let Some(minimum) = minimum
            && (!exact.is_same_unit(minimum)
                || exact.to_consensus_u32() < minimum.to_consensus_u32())
        {
            return Err(CompositionError::ExactLockTimeBelowMinimum);
        }
        return Ok(exact);
    }
    Ok(minimum.unwrap_or(LockTime::ZERO))
}

fn same_prevout_body(actual: &TxOut, expected: &TxOut) -> bool {
    actual.asset == expected.asset
        && actual.value == expected.value
        && actual.nonce == expected.nonce
        && actual.script_pubkey == expected.script_pubkey
}

fn has_pegin(input: &PsetInput) -> bool {
    input.is_pegin()
        || input.pegin_tx.is_some()
        || input.pegin_txout_proof.is_some()
        || input.pegin_genesis_hash.is_some()
        || input.pegin_claim_script.is_some()
        || input.pegin_value.is_some()
        || input.pegin_witness.is_some()
}

fn has_issuance_metadata(input: &PsetInput) -> bool {
    input.has_issuance()
        || input.issuance_value_amount.is_some()
        || input.issuance_value_comm.is_some()
        || input.issuance_inflation_keys.is_some()
        || input.issuance_inflation_keys_comm.is_some()
        || input.issuance_value_rangeproof.is_some()
        || input.issuance_keys_rangeproof.is_some()
        || input.issuance_blinding_nonce.is_some()
        || input.issuance_asset_entropy.is_some()
        || input.in_issuance_blind_value_proof.is_some()
        || input.in_issuance_blind_inflation_keys_proof.is_some()
        || input.blinded_issuance.is_some()
}

fn matches_covenant_template(output: &PsetOutput, expected: &TxOut) -> bool {
    let actual = output.to_txout();
    actual.asset == expected.asset
        && actual.value == expected.value
        && actual.nonce == expected.nonce
        && actual.script_pubkey == expected.script_pubkey
        && actual.witness.rangeproof == expected.witness.rangeproof
        && (expected.witness.surjection_proof.is_none()
            || actual.witness.surjection_proof == expected.witness.surjection_proof)
}

fn is_exact_explicit_output(
    output: &PsetOutput,
    asset: AssetId,
    amount: u64,
    script_pubkey: &Script,
) -> bool {
    output.asset == Some(asset)
        && output.amount == Some(amount)
        && output.script_pubkey == *script_pubkey
        && output.asset_comm.is_none()
        && output.amount_comm.is_none()
        && output.blinding_key.is_none()
        && output.ecdh_pubkey.is_none()
        && output.blinder_index.is_none()
        && output.value_rangeproof.is_none()
        && output.asset_surjection_proof.is_none()
        && output.blind_value_proof.is_none()
        && output.blind_asset_proof.is_none()
}

/// Composition failures are fail-closed before any proof or signature work.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CompositionError {
    #[error("the network fee must be positive")]
    ZeroNetworkFee,
    #[error("at least one contribution is required")]
    NoContributions,
    #[error("at least one input is required")]
    NoInputs,
    #[error("the contribution limit was exceeded")]
    TooManyContributions,
    #[error("the input limit was exceeded")]
    TooManyInputs,
    #[error("the output limit was exceeded")]
    TooManyOutputs,
    #[error("composition limit arithmetic overflowed")]
    LimitOverflow,
    #[error("duplicate symbolic input id {0:?}")]
    DuplicateInputId(InputId),
    #[error("duplicate transaction outpoint {0}")]
    DuplicateOutpoint(OutPoint),
    #[error("ordinary inputs cannot use null, peg-in, or issuance outpoint flags: {0}")]
    UnsupportedOutpoint(OutPoint),
    #[error("ordinary input {0} does not spend a native witness output")]
    NonWitnessInput(OutPoint),
    #[error("duplicate symbolic output id {0:?}")]
    DuplicateOutputId(OutputId),
    #[error("output refers to unknown local blinder input {0:?}")]
    UnknownLocalBlinder(InputId),
    #[error("output refers to missing external blinder outpoint {0}")]
    UnknownExternalBlinder(OutPoint),
    #[error("the resolved blinder index does not fit in PSET v2")]
    BlinderIndexOverflow,
    #[error("ordinary contribution outputs must have positive amounts")]
    ZeroOutputAmount,
    #[error("an empty script is reserved for the composer-created fee output")]
    ReservedFeeScript,
    #[error("ordinary outputs cannot use provably unspendable scripts")]
    UnspendableOrdinaryOutput,
    #[error("an output script exceeds the configured byte limit")]
    ScriptPubkeyTooLarge,
    #[error("the unblinded PSET exceeds the configured byte limit")]
    UnblindedPsetTooLarge,
    #[error("height and time locktime requirements cannot be combined")]
    IncompatibleLockTimeUnits,
    #[error("exact locktime requirements disagree")]
    IncompatibleExactLockTimes,
    #[error("the exact locktime does not satisfy every minimum")]
    ExactLockTimeBelowMinimum,
    #[error("nonzero locktime is ineffective because every input is final")]
    InactiveLockTime,
    #[error("unexpected PSET or transaction version")]
    UnexpectedVersion,
    #[error("the transaction remains marked modifiable")]
    TransactionModifiable,
    #[error("unexpected proprietary or unknown global metadata")]
    UnexpectedGlobalMetadata,
    #[error("the transaction locktime no longer matches the frozen manifest")]
    LockTimeMismatch,
    #[error("the transaction input/output shape no longer matches the frozen manifest")]
    ShapeMismatch,
    #[error("input {index} no longer matches the frozen manifest")]
    InputMismatch { index: usize },
    #[error("output {index} no longer matches the frozen manifest")]
    OutputMismatch { index: usize },
}

#[cfg(test)]
mod tests {
    use elements::bitcoin::PublicKey as BitcoinPublicKey;
    use elements::confidential::{Asset, Nonce, Value};
    use elements::hashes::Hash as _;
    use elements::secp256k1_zkp::{PublicKey, Secp256k1, SecretKey};
    use elements::{AssetId, TxOutWitness, Txid};

    use super::*;

    fn asset(byte: u8) -> AssetId {
        AssetId::from_slice(&[byte; 32]).expect("asset")
    }

    fn outpoint(byte: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid::from_byte_array([byte; 32]), vout)
    }

    fn script(byte: u8) -> Script {
        let mut bytes = vec![0x00, 0x14];
        bytes.extend([byte; 20]);
        Script::from(bytes)
    }

    fn blinding_key(byte: u8) -> BitcoinPublicKey {
        BitcoinPublicKey::new(PublicKey::from_secret_key(
            &Secp256k1::new(),
            &SecretKey::from_slice(&[byte; 32]).expect("secret"),
        ))
    }

    fn explicit_utxo(asset: AssetId, amount: u64, script_pubkey: Script) -> TxOut {
        TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(amount),
            nonce: Nonce::Null,
            script_pubkey,
            witness: TxOutWitness::default(),
        }
    }

    fn input(id: u64, txid_byte: u8, vout: u32, sequence: InputSequence) -> InputSpec {
        InputSpec::new(
            InputId::new(id),
            outpoint(txid_byte, vout),
            explicit_utxo(asset(1), 10_000, script(txid_byte)),
            sequence,
        )
    }

    fn output(id: u64, amount: u64, blinder: u64) -> OutputSpec {
        OutputSpec::confidential(
            OutputId::new(id),
            asset(2),
            amount,
            script(u8::try_from(id).expect("small test id")),
            blinding_key(3),
            BlinderRef::Local(InputId::new(blinder)),
        )
    }

    fn fee() -> NetworkFee {
        NetworkFee::new(asset(1), 100).expect("fee")
    }

    #[test]
    fn composition_is_deterministic_and_resolves_nonzero_symbolic_positions() {
        let wallet = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Unconstrained,
        );
        let venue = TransactionContribution::new(
            vec![input(2, 20, 0, InputSequence::Final)],
            vec![output(20, 2_000, 2), output(21, 3_000, 2)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        let wallet_handle = composer.push(wallet.clone()).expect("wallet contribution");
        let venue_handle = composer.push(venue.clone()).expect("venue contribution");
        let composed = composer.finish().expect("composition");
        let mut second = TransactionComposer::new(CompositionLimits::default(), fee());
        second.push(wallet).expect("wallet contribution");
        second.push(venue).expect("venue contribution");
        let second = second.finish().expect("second composition");
        assert_eq!(composed.pset(), second.pset());
        assert_eq!(composed.layout(), second.layout());
        assert_eq!(composed.manifest(), second.manifest());

        assert_eq!(
            composed
                .layout()
                .input_index(wallet_handle, InputId::new(1)),
            Some(0)
        );
        assert_eq!(
            composed.layout().input_index(venue_handle, InputId::new(2)),
            Some(1)
        );
        assert_eq!(
            composed
                .layout()
                .output_index(wallet_handle, OutputId::new(10)),
            Some(0)
        );
        assert_eq!(
            composed
                .layout()
                .output_index(venue_handle, OutputId::new(20)),
            Some(1)
        );
        assert_eq!(
            composed
                .layout()
                .output_index(venue_handle, OutputId::new(21)),
            Some(2)
        );
        assert_eq!(composed.layout().fee_output_index(), 3);
        assert_eq!(
            composed.layout().placement(wallet_handle),
            Some(ContributionPlacement {
                input_base: 0,
                input_count: 1,
                output_base: 0,
                output_count: 1,
            })
        );
        assert_eq!(
            composed.layout().placement(venue_handle),
            Some(ContributionPlacement {
                input_base: 1,
                input_count: 1,
                output_base: 1,
                output_count: 2,
            })
        );
        assert_eq!(composed.pset().outputs()[1].blinder_index, Some(1));
        composed
            .manifest()
            .validate(composed.pset())
            .expect("manifest");
    }

    #[test]
    fn duplicate_dependencies_and_symbolic_ids_fail_closed() {
        let first = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Unconstrained,
        );
        let duplicate_outpoint = TransactionContribution::new(
            vec![input(2, 10, 0, InputSequence::Final)],
            vec![output(20, 2_000, 2)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(first).expect("first");
        composer.push(duplicate_outpoint).expect("second");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::DuplicateOutpoint(_))
        ));

        let duplicate_input_id = TransactionContribution::new(
            vec![
                input(1, 11, 0, InputSequence::Final),
                input(1, 12, 0, InputSequence::Final),
            ],
            vec![output(20, 2_000, 1)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(duplicate_input_id).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::DuplicateInputId(InputId(1)))
        ));

        let duplicate_output_id = TransactionContribution::new(
            vec![input(2, 11, 0, InputSequence::Final)],
            vec![output(10, 2_000, 2), output(10, 3_000, 2)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(duplicate_output_id).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::DuplicateOutputId(OutputId(10)))
        ));
    }

    #[test]
    fn identical_exclusive_outputs_never_alias() {
        let duplicate = OutputSpec::confidential(
            OutputId::new(10),
            asset(2),
            1_000,
            script(10),
            blinding_key(3),
            BlinderRef::External(outpoint(10, 0)),
        );
        let same_bytes_different_claim = match duplicate.clone() {
            OutputSpec::Confidential {
                asset,
                amount,
                script_pubkey,
                blinding_key,
                blinder,
                ..
            } => OutputSpec::confidential(
                OutputId::new(11),
                asset,
                amount,
                script_pubkey,
                blinding_key,
                blinder,
            ),
            OutputSpec::Explicit { .. } | OutputSpec::Covenant { .. } => unreachable!(),
        };
        let first = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![duplicate],
            LockTimeConstraint::Unconstrained,
        );
        let second = TransactionContribution::new(
            // Contribution-local IDs may safely repeat across independent
            // fragments without any global namespace coordination.
            vec![input(1, 20, 0, InputSequence::Final)],
            vec![same_bytes_different_claim],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        let first_handle = composer.push(first).expect("first contribution");
        let second_handle = composer.push(second).expect("second contribution");
        let composed = composer.finish().expect("composition");
        let first = composed
            .layout()
            .output_index(first_handle, OutputId::new(10))
            .expect("first output");
        let second = composed
            .layout()
            .output_index(second_handle, OutputId::new(11))
            .expect("second output");
        assert_ne!(first, second);
        assert_eq!(composed.pset().outputs()[0], composed.pset().outputs()[1]);
    }

    #[test]
    fn blinder_references_and_fee_ownership_are_closed_world() {
        let missing_blinder = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 99)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(missing_blinder).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::UnknownLocalBlinder(InputId(99)))
        ));

        let missing_outpoint = outpoint(99, 0);
        let external_blinder = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![OutputSpec::confidential(
                OutputId::new(10),
                asset(2),
                1_000,
                script(10),
                blinding_key(3),
                BlinderRef::External(missing_outpoint),
            )],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(external_blinder).expect("contribution");
        assert_eq!(
            composer.finish().expect_err("missing external blinder"),
            CompositionError::UnknownExternalBlinder(missing_outpoint)
        );

        let fake_fee = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![OutputSpec::explicit(
                OutputId::new(10),
                asset(1),
                1,
                Script::new(),
            )],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(fake_fee).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::ReservedFeeScript)
        ));
    }

    #[test]
    fn locktime_constraints_intersect_and_activate_globally() {
        let required = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::AtLeast(LockTime::from_height(100).expect("height")),
        );
        let unrelated_activator = TransactionContribution::new(
            vec![input(2, 20, 0, InputSequence::LocktimeEnabled)],
            vec![output(20, 1_000, 2)],
            LockTimeConstraint::AtLeast(LockTime::from_height(120).expect("height")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(required).expect("required");
        composer.push(unrelated_activator).expect("activator");
        let composed = composer.finish().expect("composition");
        assert_eq!(
            composed.manifest().locktime(),
            LockTime::from_height(120).expect("height")
        );
        assert_eq!(composed.pset().inputs()[0].sequence, Some(Sequence::MAX));
        assert_eq!(
            composed.pset().inputs()[1].sequence,
            Some(Sequence(0xffff_fffe))
        );
    }

    #[test]
    fn incompatible_or_inactive_locktime_fails_closed() {
        let all_final = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::AtLeast(LockTime::from_height(100).expect("height")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(all_final.clone()).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::InactiveLockTime)
        ));

        let time = TransactionContribution::new(
            vec![input(2, 20, 0, InputSequence::LocktimeEnabled)],
            vec![output(20, 1_000, 2)],
            LockTimeConstraint::AtLeast(LockTime::from_time(500_000_001).expect("time")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(all_final).expect("height");
        composer.push(time).expect("time");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::IncompatibleLockTimeUnits)
        ));
    }

    #[test]
    fn exact_locktimes_intersect_or_fail_closed() {
        let minimum = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::AtLeast(LockTime::from_height(100).expect("height")),
        );
        let exact = TransactionContribution::new(
            vec![input(1, 20, 0, InputSequence::LocktimeEnabled)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Exact(LockTime::from_height(120).expect("height")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(minimum.clone()).expect("minimum");
        composer.push(exact.clone()).expect("exact");
        assert_eq!(
            composer.finish().expect("compatible").manifest().locktime(),
            LockTime::from_height(120).expect("height")
        );

        let below = TransactionContribution::new(
            vec![input(1, 30, 0, InputSequence::LocktimeEnabled)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Exact(LockTime::from_height(99).expect("height")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(minimum.clone()).expect("minimum");
        composer.push(below).expect("below");
        assert_eq!(
            composer.finish().expect_err("below minimum"),
            CompositionError::ExactLockTimeBelowMinimum
        );

        let conflicting = TransactionContribution::new(
            vec![input(1, 40, 0, InputSequence::LocktimeEnabled)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Exact(LockTime::from_height(121).expect("height")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(exact).expect("exact");
        composer.push(conflicting).expect("conflicting");
        assert_eq!(
            composer.finish().expect_err("conflicting exact values"),
            CompositionError::IncompatibleExactLockTimes
        );

        let exact_time = TransactionContribution::new(
            vec![input(1, 50, 0, InputSequence::LocktimeEnabled)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Exact(LockTime::from_time(500_000_001).expect("time")),
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(minimum).expect("minimum");
        composer.push(exact_time).expect("exact time");
        assert_eq!(
            composer.finish().expect_err("mixed units"),
            CompositionError::ExactLockTimeBelowMinimum
        );
    }

    #[test]
    fn manifest_detects_structural_mutations_after_handoff() {
        let contribution = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(contribution).expect("contribution");
        let composed = composer.finish().expect("composition");

        let mut wrong_output = composed.pset().clone();
        wrong_output.outputs_mut()[0].amount = Some(1_001);
        assert_eq!(
            composed.manifest().validate(&wrong_output),
            Err(CompositionError::OutputMismatch { index: 0 })
        );

        let mut wrong_outpoint = composed.pset().clone();
        wrong_outpoint.inputs_mut()[0].previous_output_index = 1;
        assert_eq!(
            composed.manifest().validate(&wrong_outpoint),
            Err(CompositionError::InputMismatch { index: 0 })
        );

        let mut wrong_prevout = composed.pset().clone();
        wrong_prevout.inputs_mut()[0]
            .witness_utxo
            .as_mut()
            .expect("prevout")
            .value = Value::Explicit(9_999);
        assert_eq!(
            composed.manifest().validate(&wrong_prevout),
            Err(CompositionError::InputMismatch { index: 0 })
        );

        let mut wrong_sequence = composed.pset().clone();
        wrong_sequence.inputs_mut()[0].sequence = Some(Sequence::ZERO);
        assert_eq!(
            composed.manifest().validate(&wrong_sequence),
            Err(CompositionError::InputMismatch { index: 0 })
        );

        let mut wrong_locktime = composed.pset().clone();
        wrong_locktime.global.tx_data.fallback_locktime =
            Some(LockTime::from_height(1).expect("height"));
        assert_eq!(
            composed.manifest().validate(&wrong_locktime),
            Err(CompositionError::LockTimeMismatch)
        );

        let mut modifiable = composed.pset().clone();
        modifiable.global.tx_data.tx_modifiable = Some(1);
        assert_eq!(
            composed.manifest().validate(&modifiable),
            Err(CompositionError::TransactionModifiable)
        );

        let mut wrong_recipient = composed.pset().clone();
        wrong_recipient.outputs_mut()[0].script_pubkey = script(9);
        assert_eq!(
            composed.manifest().validate(&wrong_recipient),
            Err(CompositionError::OutputMismatch { index: 0 })
        );

        let mut wrong_blinder = composed.pset().clone();
        wrong_blinder.outputs_mut()[0].blinder_index = Some(9);
        assert_eq!(
            composed.manifest().validate(&wrong_blinder),
            Err(CompositionError::OutputMismatch { index: 0 })
        );

        let mut wrong_fee = composed.pset().clone();
        wrong_fee.outputs_mut()[1].amount = Some(101);
        assert_eq!(
            composed.manifest().validate(&wrong_fee),
            Err(CompositionError::OutputMismatch { index: 1 })
        );

        let mut extra_fee = composed.pset().clone();
        extra_fee.add_output(PsetOutput::from_txout(TxOut::new_fee(1, asset(1))));
        assert_eq!(
            composed.manifest().validate(&extra_fee),
            Err(CompositionError::ShapeMismatch)
        );

        let mut issuance = composed.pset().clone();
        issuance.inputs_mut()[0].issuance_value_amount = Some(1);
        assert_eq!(
            composed.manifest().validate(&issuance),
            Err(CompositionError::InputMismatch { index: 0 })
        );

        // Signing metadata is intentionally outside this structure-only
        // manifest and must be authorized by the participant-specific signer.
        let mut signing_metadata = composed.pset().clone();
        signing_metadata.inputs_mut()[0].sighash_type =
            Some(elements::SchnorrSighashType::All.into());
        composed
            .manifest()
            .validate(&signing_metadata)
            .expect("signing metadata is a separate validation layer");
    }

    #[test]
    fn limits_apply_before_composition() {
        let limits = CompositionLimits {
            max_contributions: 1,
            max_inputs: 1,
            max_outputs: 2,
            ..CompositionLimits::default()
        };
        let contribution = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![output(10, 1_000, 1)],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(limits, fee());
        composer.push(contribution.clone()).expect("first");
        assert_eq!(
            composer.push(contribution),
            Err(CompositionError::TooManyContributions)
        );
    }

    #[test]
    fn empty_flagged_and_oversized_shapes_fail_closed() {
        assert_eq!(
            TransactionComposer::new(CompositionLimits::default(), fee())
                .finish()
                .expect_err("empty composer"),
            CompositionError::NoContributions
        );

        let no_inputs = TransactionContribution::new(
            Vec::new(),
            vec![OutputSpec::explicit(
                OutputId::new(1),
                asset(2),
                1,
                script(1),
            )],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(no_inputs).expect("contribution");
        assert_eq!(
            composer.finish().expect_err("no inputs"),
            CompositionError::NoInputs
        );

        let limits = CompositionLimits {
            max_inputs: 1,
            max_outputs: 1,
            ..CompositionLimits::default()
        };
        let mut too_many_inputs = TransactionComposer::new(limits, fee());
        too_many_inputs
            .push(TransactionContribution::new(
                vec![
                    input(1, 10, 0, InputSequence::Final),
                    input(2, 11, 0, InputSequence::Final),
                ],
                Vec::new(),
                LockTimeConstraint::Unconstrained,
            ))
            .expect("contribution");
        assert_eq!(
            too_many_inputs.finish().expect_err("input limit"),
            CompositionError::TooManyInputs
        );

        let mut fee_inclusive_outputs = TransactionComposer::new(limits, fee());
        fee_inclusive_outputs
            .push(TransactionContribution::new(
                vec![input(1, 10, 0, InputSequence::Final)],
                vec![output(1, 1, 1)],
                LockTimeConstraint::Unconstrained,
            ))
            .expect("contribution");
        assert_eq!(
            fee_inclusive_outputs
                .finish()
                .expect_err("fee counts toward output limit"),
            CompositionError::TooManyOutputs
        );

        let flagged = TransactionContribution::new(
            vec![input(1, 10, 1 << 30, InputSequence::Final)],
            Vec::new(),
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer.push(flagged).expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::UnsupportedOutpoint(_))
        ));

        let legacy_input = InputSpec::new(
            InputId::new(1),
            outpoint(10, 0),
            explicit_utxo(asset(1), 1_000, Script::from(vec![0x51])),
            InputSequence::Final,
        );
        let mut composer = TransactionComposer::new(CompositionLimits::default(), fee());
        composer
            .push(TransactionContribution::new(
                vec![legacy_input],
                Vec::new(),
                LockTimeConstraint::Unconstrained,
            ))
            .expect("contribution");
        assert!(matches!(
            composer.finish(),
            Err(CompositionError::NonWitnessInput(_))
        ));

        let script_limits = CompositionLimits {
            max_script_pubkey_bytes: 10,
            ..CompositionLimits::default()
        };
        let mut oversized_input = TransactionComposer::new(script_limits, fee());
        oversized_input
            .push(TransactionContribution::new(
                vec![input(1, 10, 0, InputSequence::Final)],
                Vec::new(),
                LockTimeConstraint::Unconstrained,
            ))
            .expect("contribution");
        assert_eq!(
            oversized_input.finish().expect_err("input script limit"),
            CompositionError::ScriptPubkeyTooLarge
        );

        let oversized = TransactionContribution::new(
            vec![input(1, 10, 0, InputSequence::Final)],
            vec![OutputSpec::explicit(
                OutputId::new(1),
                asset(2),
                1,
                Script::from(vec![0x51; 11]),
            )],
            LockTimeConstraint::Unconstrained,
        );
        let mut composer = TransactionComposer::new(script_limits, fee());
        composer.push(oversized).expect("contribution");
        assert_eq!(
            composer.finish().expect_err("script limit"),
            CompositionError::ScriptPubkeyTooLarge
        );

        let mut composer = TransactionComposer::new(
            CompositionLimits {
                max_unblinded_pset_bytes: 1,
                ..CompositionLimits::default()
            },
            fee(),
        );
        composer
            .push(TransactionContribution::new(
                vec![input(1, 10, 0, InputSequence::Final)],
                Vec::new(),
                LockTimeConstraint::Unconstrained,
            ))
            .expect("contribution");
        assert_eq!(
            composer.finish().expect_err("PSET byte limit"),
            CompositionError::UnblindedPsetTooLarge
        );
    }
}
