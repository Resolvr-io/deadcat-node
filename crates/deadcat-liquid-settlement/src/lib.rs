//! Narrow, policy-free validation primitives for Liquid settlement protocols.
//!
//! This crate deliberately does not decide who may spend an input, which
//! outputs a venue promised, whether a fee is acceptable, or whether a
//! prevout is authoritative and unspent. Callers must establish those facts
//! before using the cryptographic checks here.

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::{Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::{Message, Secp256k1};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    BlindAssetProofs as _, BlindValueProofs as _, BlockHash, SchnorrSig, SchnorrSighashType,
    Transaction, TxOut,
};
use thiserror::Error;

/// A PSET whose complete byte encoding was bounded, decoded, sanity checked,
/// and proven to be the unique encoding emitted by `elements`.
///
/// Canonical encoding is useful for durable commitments and exact replay, but
/// it is not transaction authorization. Callers must separately validate all
/// PSET fields against their own policy and trusted prevouts.
#[derive(Clone, Debug)]
pub struct CanonicalPset {
    bytes: Vec<u8>,
    pset: PartiallySignedTransaction,
}

impl CanonicalPset {
    /// Decode an exact PSET only after enforcing `maximum_bytes`.
    pub fn decode(bytes: &[u8], maximum_bytes: usize) -> Result<Self, CanonicalPsetError> {
        if bytes.is_empty() {
            return Err(CanonicalPsetError::EmptyPayload);
        }
        if bytes.len() > maximum_bytes {
            return Err(CanonicalPsetError::PayloadTooLarge {
                maximum: maximum_bytes,
                actual: bytes.len(),
            });
        }
        let pset = deserialize::<PartiallySignedTransaction>(bytes)
            .map_err(|error| CanonicalPsetError::InvalidPset(error.to_string()))?;
        pset.sanity_check()
            .map_err(|error| CanonicalPsetError::InvalidPset(error.to_string()))?;
        let canonical = serialize(&pset);
        if canonical != bytes {
            return Err(CanonicalPsetError::NonCanonicalEncoding);
        }
        Ok(Self {
            bytes: canonical,
            pset,
        })
    }

    /// The exact canonical bytes checked by [`Self::decode`].
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The decoded PSET corresponding exactly to [`Self::bytes`].
    #[must_use]
    pub const fn pset(&self) -> &PartiallySignedTransaction {
        &self.pset
    }

    /// Consume this value and return its canonical bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Consume this value and return its decoded PSET.
    #[must_use]
    pub fn into_pset(self) -> PartiallySignedTransaction {
        self.pset
    }

    /// Consume this value and return both representations.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, PartiallySignedTransaction) {
        (self.bytes, self.pset)
    }
}

/// Failure to establish a bounded canonical PSET encoding.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CanonicalPsetError {
    #[error("PSET payload must not be empty")]
    EmptyPayload,
    #[error("PSET payload has {actual} bytes; maximum is {maximum}")]
    PayloadTooLarge { maximum: usize, actual: usize },
    #[error("invalid PSET: {0}")]
    InvalidPset(String),
    #[error("PSET is not canonically encoded")]
    NonCanonicalEncoding,
}

/// Verify one Elements tree-less Taproot key-path signature with an explicit
/// `SIGHASH_ALL` byte.
///
/// `prevouts` must be the trusted, correctly ordered full prevout set for
/// `transaction`. This function verifies that the selected prevout pays the
/// untweaked `internal_key` with no script tree, derives the Elements Taproot
/// sighash using `genesis_hash`, applies the Elements TapTweak, and verifies
/// the Schnorr signature. It intentionally does not trust or inspect PSET
/// signing metadata.
pub fn verify_treeless_p2tr_explicit_all(
    transaction: &Transaction,
    prevouts: &[TxOut],
    input_index: usize,
    signature: SchnorrSig,
    internal_key: elements::secp256k1_zkp::XOnlyPublicKey,
    genesis_hash: BlockHash,
) -> Result<(), P2trVerificationError> {
    if transaction.input.len() != prevouts.len() {
        return Err(P2trVerificationError::PrevoutCount {
            expected: transaction.input.len(),
            actual: prevouts.len(),
        });
    }
    let prevout = prevouts
        .get(input_index)
        .ok_or(P2trVerificationError::InputIndex {
            index: input_index,
            inputs: transaction.input.len(),
        })?;
    if signature.hash_ty != SchnorrSighashType::All {
        return Err(P2trVerificationError::NotExplicitAll);
    }

    let secp = Secp256k1::new();
    if prevout.script_pubkey != elements::Script::new_v1_p2tr(&secp, internal_key, None) {
        return Err(P2trVerificationError::WrongScriptPubkey);
    }
    let sighash = SighashCache::new(transaction)
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            SchnorrSighashType::All,
            genesis_hash,
        )
        .map_err(|error| P2trVerificationError::Sighash(error.to_string()))?;
    let message = Message::from_digest(sighash.to_byte_array());
    let (output_key, _) = internal_key.tap_tweak(&secp, None);
    secp.verify_schnorr(&signature.sig, &message, output_key.as_inner())
        .map_err(|error| P2trVerificationError::InvalidSignature(error.to_string()))
}

/// Failure to verify an exact tree-less P2TR explicit-ALL spend.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum P2trVerificationError {
    #[error("transaction has {expected} inputs but {actual} prevouts were supplied")]
    PrevoutCount { expected: usize, actual: usize },
    #[error("input index {index} is out of range for {inputs} transaction inputs")]
    InputIndex { index: usize, inputs: usize },
    #[error("Taproot signature does not carry explicit SIGHASH_ALL")]
    NotExplicitAll,
    #[error("prevout is not the tree-less P2TR output for the supplied internal key")]
    WrongScriptPubkey,
    #[error("cannot derive Elements Taproot sighash: {0}")]
    Sighash(String),
    #[error("Schnorr signature verification failed: {0}")]
    InvalidSignature(String),
}

impl P2trVerificationError {
    /// The underlying cryptographic detail when available, or this error's
    /// policy-independent description for structural failures.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Sighash(detail) | Self::InvalidSignature(detail) => detail,
            Self::PrevoutCount { .. } => "transaction and prevout counts differ",
            Self::InputIndex { .. } => "input index is out of range",
            Self::NotExplicitAll => "Taproot signature does not carry explicit SIGHASH_ALL",
            Self::WrongScriptPubkey => {
                "prevout is not the tree-less P2TR output for the supplied internal key"
            }
        }
    }
}

/// Verify that the explicit asset and amount disclosed in a PSET output match
/// its confidential asset and value commitments.
///
/// This verifies only the two disclosure proofs. It does not require or check
/// the transaction rangeproof, surjection proof, nonce, blinder assignment,
/// destination, or economic policy. Use [`verify_confidential_proofs_and_balance`]
/// on the extracted transaction for the complete transaction-level proof and
/// balance check.
pub fn verify_output_disclosure(output: &PsetOutput) -> Result<(), DisclosureProofError> {
    let asset = output
        .asset
        .ok_or(DisclosureProofError::MissingField("explicit asset"))?;
    let amount = output
        .amount
        .ok_or(DisclosureProofError::MissingField("explicit amount"))?;
    let asset_commitment = output
        .asset_comm
        .ok_or(DisclosureProofError::MissingField("asset commitment"))?;
    let value_commitment = output
        .amount_comm
        .ok_or(DisclosureProofError::MissingField("value commitment"))?;
    let asset_proof = output
        .blind_asset_proof
        .as_deref()
        .ok_or(DisclosureProofError::MissingField("asset disclosure proof"))?;
    let value_proof = output
        .blind_value_proof
        .as_deref()
        .ok_or(DisclosureProofError::MissingField("value disclosure proof"))?;

    let secp = Secp256k1::new();
    if !asset_proof.blind_asset_proof_verify(&secp, asset, asset_commitment) {
        return Err(DisclosureProofError::InvalidAssetProof);
    }
    if !value_proof.blind_value_proof_verify(&secp, amount, asset_commitment, value_commitment) {
        return Err(DisclosureProofError::InvalidValueProof);
    }
    Ok(())
}

/// Failure to verify a PSET output's explicit-value disclosure proofs.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum DisclosureProofError {
    #[error("missing {0}")]
    MissingField(&'static str),
    #[error("explicit asset does not match its commitment")]
    InvalidAssetProof,
    #[error("explicit amount does not match its commitment")]
    InvalidValueProof,
}

/// Verify all rangeproofs, surjection proofs, and asset/value balance for an
/// extracted Elements transaction.
///
/// The caller remains responsible for obtaining the complete `prevouts` from
/// an authoritative chain view and preserving transaction-input order.
pub fn verify_confidential_proofs_and_balance(
    transaction: &Transaction,
    prevouts: &[TxOut],
) -> Result<(), ConfidentialVerificationError> {
    transaction
        .verify_tx_amt_proofs(&Secp256k1::new(), prevouts)
        .map_err(|error| ConfidentialVerificationError(error.to_string()))
}

/// Failure of transaction-level confidential proof or balance verification.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ConfidentialVerificationError(String);

impl ConfidentialVerificationError {
    /// The underlying `elements` verification detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests;
