use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::serialize;
use elements::hashes::Hash as _;
use elements::pset::{Output as PsetOutput, PartiallySignedTransaction};
use elements::schnorr::TapTweak as _;
use elements::secp256k1_zkp::rand::thread_rng;
use elements::secp256k1_zkp::{Keypair, Message, Secp256k1, SecretKey};
use elements::sighash::{Prevouts, SighashCache};
use elements::{
    AssetId, BlindAssetProofs as _, BlindValueProofs as _, BlockHash, LockTime, OutPoint,
    SchnorrSig, SchnorrSighashType, Script, Transaction, TxIn, TxOut, TxOutWitness, Txid,
};

use super::{
    CanonicalPset, CanonicalPsetError, DisclosureProofError, P2trVerificationError,
    verify_confidential_proofs_and_balance, verify_output_disclosure,
    verify_treeless_p2tr_explicit_all,
};

#[test]
fn canonical_pset_decode_enforces_bound_and_exact_encoding() {
    let encoded = serialize(&PartiallySignedTransaction::new_v2());
    let decoded = CanonicalPset::decode(&encoded, encoded.len()).expect("canonical PSET");
    assert_eq!(decoded.bytes(), encoded);
    assert_eq!(serialize(decoded.pset()), encoded);

    assert_eq!(
        CanonicalPset::decode(&[], encoded.len()).expect_err("empty payload"),
        CanonicalPsetError::EmptyPayload
    );
    assert_eq!(
        CanonicalPset::decode(&encoded, encoded.len() - 1).expect_err("oversized payload"),
        CanonicalPsetError::PayloadTooLarge {
            maximum: encoded.len() - 1,
            actual: encoded.len(),
        }
    );
    assert!(matches!(
        CanonicalPset::decode(b"not a PSET", 64),
        Err(CanonicalPsetError::InvalidPset(_))
    ));

    let reordered = reorder_first_two_global_pairs(&encoded);
    assert!(matches!(
        CanonicalPset::decode(&reordered, reordered.len()),
        Err(CanonicalPsetError::NonCanonicalEncoding)
    ));
}

#[test]
fn treeless_p2tr_verification_requires_elements_explicit_all_signature() {
    let secp = Secp256k1::new();
    let keypair =
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).expect("secret key"));
    let (internal_key, _) = keypair.x_only_public_key();
    let asset = AssetId::from_byte_array([3; 32]);
    let genesis = BlockHash::from_byte_array([4; 32]);
    let prevout = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(10),
        nonce: Nonce::Null,
        script_pubkey: Script::new_v1_p2tr(&secp, internal_key, None),
        witness: TxOutWitness::default(),
    };
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([5; 32]), 0),
            ..TxIn::default()
        }],
        output: vec![TxOut::new_fee(10, asset)],
    };
    let prevouts = vec![prevout];
    let sighash = SighashCache::new(&transaction)
        .taproot_key_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            SchnorrSighashType::All,
            genesis,
        )
        .expect("sighash");
    let tweaked = keypair.tap_tweak(&secp, None);
    let signature = SchnorrSig {
        sig: secp.sign_schnorr(
            &Message::from_digest(sighash.to_byte_array()),
            &tweaked.to_inner(),
        ),
        hash_ty: SchnorrSighashType::All,
    };

    verify_treeless_p2tr_explicit_all(&transaction, &prevouts, 0, signature, internal_key, genesis)
        .expect("valid signature");

    let implicit_default = SchnorrSig {
        hash_ty: SchnorrSighashType::Default,
        ..signature
    };
    assert_eq!(
        verify_treeless_p2tr_explicit_all(
            &transaction,
            &prevouts,
            0,
            implicit_default,
            internal_key,
            genesis,
        )
        .expect_err("implicit sighash must fail"),
        P2trVerificationError::NotExplicitAll
    );

    let wrong_keypair =
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[8; 32]).expect("secret key"));
    let (wrong_internal_key, _) = wrong_keypair.x_only_public_key();
    assert_eq!(
        verify_treeless_p2tr_explicit_all(
            &transaction,
            &prevouts,
            0,
            signature,
            wrong_internal_key,
            genesis,
        )
        .expect_err("wrong key must fail"),
        P2trVerificationError::WrongScriptPubkey
    );

    let mut changed_transaction = transaction.clone();
    changed_transaction.output[0] = TxOut::new_fee(9, asset);
    assert!(matches!(
        verify_treeless_p2tr_explicit_all(
            &changed_transaction,
            &prevouts,
            0,
            signature,
            internal_key,
            genesis,
        ),
        Err(P2trVerificationError::InvalidSignature(_))
    ));
    assert!(matches!(
        verify_treeless_p2tr_explicit_all(
            &transaction,
            &prevouts,
            0,
            signature,
            internal_key,
            BlockHash::from_byte_array([6; 32]),
        ),
        Err(P2trVerificationError::InvalidSignature(_))
    ));
}

#[test]
fn disclosure_proofs_bind_asset_and_amount() {
    let secp = Secp256k1::new();
    let mut rng = thread_rng();
    let asset = AssetId::from_byte_array([9; 32]);
    let amount = 42;
    let asset_blinder = AssetBlindingFactor::from_slice(&[10; 32]).expect("asset blinder");
    let value_blinder = ValueBlindingFactor::from_slice(&[11; 32]).expect("value blinder");
    let asset_commitment = elements::secp256k1_zkp::Generator::new_blinded(
        &secp,
        asset.into_tag(),
        asset_blinder.into_inner(),
    );
    let value_commitment = elements::secp256k1_zkp::PedersenCommitment::new(
        &secp,
        amount,
        value_blinder.into_inner(),
        asset_commitment,
    );
    let blind_asset_proof = Box::new(
        elements::secp256k1_zkp::SurjectionProof::blind_asset_proof(
            &mut rng,
            &secp,
            asset,
            asset_blinder,
        )
        .expect("asset disclosure proof"),
    );
    let blind_value_proof = Box::new(
        elements::secp256k1_zkp::RangeProof::blind_value_proof(
            &mut rng,
            &secp,
            amount,
            value_commitment,
            asset_commitment,
            value_blinder,
        )
        .expect("value disclosure proof"),
    );
    let mut output = PsetOutput {
        asset: Some(asset),
        amount: Some(amount),
        asset_comm: Some(asset_commitment),
        amount_comm: Some(value_commitment),
        blind_asset_proof: Some(blind_asset_proof),
        blind_value_proof: Some(blind_value_proof),
        ..PsetOutput::default()
    };

    verify_output_disclosure(&output).expect("valid disclosures");
    output.asset = Some(AssetId::from_byte_array([14; 32]));
    assert_eq!(
        verify_output_disclosure(&output).expect_err("asset mismatch"),
        DisclosureProofError::InvalidAssetProof
    );
    output.asset = Some(asset);
    output.amount = Some(amount + 1);
    assert_eq!(
        verify_output_disclosure(&output).expect_err("amount mismatch"),
        DisclosureProofError::InvalidValueProof
    );
    output.amount = Some(amount);
    output.blind_asset_proof = None;
    assert_eq!(
        verify_output_disclosure(&output).expect_err("missing proof"),
        DisclosureProofError::MissingField("asset disclosure proof")
    );
}

#[test]
fn transaction_proof_verification_checks_prevout_count_and_balance() {
    let asset = AssetId::from_byte_array([12; 32]);
    let prevout = TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(100),
        nonce: Nonce::Null,
        script_pubkey: Script::new(),
        witness: TxOutWitness::default(),
    };
    let mut transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([13; 32]), 0),
            ..TxIn::default()
        }],
        output: vec![TxOut::new_fee(100, asset)],
    };
    verify_confidential_proofs_and_balance(&transaction, std::slice::from_ref(&prevout))
        .expect("balanced transaction");

    transaction.output[0] = TxOut::new_fee(99, asset);
    assert!(verify_confidential_proofs_and_balance(&transaction, &[prevout]).is_err());
    assert!(verify_confidential_proofs_and_balance(&transaction, &[]).is_err());
}

fn reorder_first_two_global_pairs(canonical: &[u8]) -> Vec<u8> {
    const HEADER_BYTES: usize = 5;
    let mut cursor = HEADER_BYTES;
    let mut pairs = Vec::new();
    while canonical[cursor] != 0 {
        let start = cursor;
        let key_length = usize::from(canonical[cursor]);
        assert!(key_length < 0xfd, "fixture uses one-byte compact sizes");
        cursor += 1 + key_length;
        let value_length = usize::from(canonical[cursor]);
        assert!(value_length < 0xfd, "fixture uses one-byte compact sizes");
        cursor += 1 + value_length;
        pairs.push(canonical[start..cursor].to_vec());
    }
    assert!(pairs.len() >= 2, "fixture has multiple global pairs");
    pairs.swap(0, 1);

    let mut reordered = canonical[..HEADER_BYTES].to_vec();
    for pair in pairs {
        reordered.extend(pair);
    }
    reordered.extend_from_slice(&canonical[cursor..]);
    reordered
}
