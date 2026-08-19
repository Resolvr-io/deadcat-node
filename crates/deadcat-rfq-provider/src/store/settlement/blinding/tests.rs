use std::collections::HashMap;

use elements::BlockHash;
use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::{Output as PsetOutput, PartiallySignedTransaction};
use elements::secp256k1_zkp::Secp256k1;
use elements::secp256k1_zkp::rand::thread_rng;

use super::{ProviderBlindingCoordinator, ProviderBlindingError};
use crate::inventory::InventoryCoordinatorError;
use crate::model::{OwnerId, ReservationAccess, UnixMillis};
use crate::quote::{QuoteBlinderRole, QuoteOutputRole};
use crate::wallet::{InventorySnapshot, WalletScanAnchor};

use super::super::tests::{FixtureBackendError, SettlementFixture, VALIDATION_TIME};
use super::super::{ProviderSettlementValidator, SettlementLayout, SettlementValidationError};

fn settlement_layout(fixture: &SettlementFixture) -> SettlementLayout {
    fixture
        .baseline
        .layout
        .settlement_layout()
        .expect("fixture settlement layout")
}

fn provider_blind(
    fixture: &SettlementFixture,
    pset: &PartiallySignedTransaction,
) -> Result<super::ProviderBlindedPset, ProviderBlindingError<FixtureBackendError>> {
    ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
        fixture.access,
        &settlement_layout(fixture),
        &serialize(pset),
        &VALIDATION_TIME,
        &mut thread_rng(),
    )
}

fn output_is_unblinded(output: &PsetOutput) -> bool {
    output.asset_comm.is_none()
        && output.amount_comm.is_none()
        && output.ecdh_pubkey.is_none()
        && output.value_rangeproof.is_none()
        && output.asset_surjection_proof.is_none()
        && output.blind_value_proof.is_none()
        && output.blind_asset_proof.is_none()
}

fn finish_taker_blinding_and_signing(
    fixture: &SettlementFixture,
    provider_blinded: &[u8],
) -> PartiallySignedTransaction {
    let mut pset =
        deserialize::<PartiallySignedTransaction>(provider_blinded).expect("provider-blinded PSET");
    let mut taker_secrets = HashMap::new();
    taker_secrets.insert(
        fixture.baseline.layout.taker_fee_input,
        fixture.fee_input.secrets,
    );
    taker_secrets.insert(
        fixture.baseline.layout.taker_payment_input,
        fixture.payment_input.secrets,
    );
    pset.blind_last(&mut thread_rng(), &Secp256k1::new(), &taker_secrets)
        .expect("taker final blinding");
    fixture.taker_wallet.sign_input(
        &mut pset,
        fixture.baseline.layout.taker_fee_input,
        fixture.identity.genesis_hash(),
    );
    fixture.taker_wallet.sign_input(
        &mut pset,
        fixture.baseline.layout.taker_payment_input,
        fixture.identity.genesis_hash(),
    );
    deserialize(&serialize(&pset)).expect("canonical taker-signed PSET")
}

#[test]
fn exact_reserved_contribution_is_blinded_and_remains_finally_valid() {
    let fixture = SettlementFixture::new();
    let original = fixture.unblinded_pset.clone();
    let blinded = provider_blind(&fixture, &original).expect("provider blinding");
    let reparsed = deserialize::<PartiallySignedTransaction>(blinded.bytes())
        .expect("canonical provider-blinded PSET");
    let canonical_original = deserialize::<PartiallySignedTransaction>(&serialize(&original))
        .expect("canonical original PSET");

    assert_eq!(serialize(&reparsed), blinded.bytes());
    assert_eq!(reparsed.global.scalars.len(), 1);
    assert_eq!(reparsed.inputs(), canonical_original.inputs());
    for output in fixture.quote.contribution().outputs() {
        let index = fixture.baseline.layout.quote_output(output.id());
        match output.blinder() {
            QuoteBlinderRole::ProviderInput(_) => {
                assert!(!output_is_unblinded(&reparsed.outputs()[index]));
            }
            QuoteBlinderRole::TakerPaymentInput => {
                assert_eq!(
                    reparsed.outputs()[index],
                    canonical_original.outputs()[index]
                );
                assert!(output_is_unblinded(&reparsed.outputs()[index]));
            }
        }
    }
    for index in [
        fixture.baseline.layout.taker_fee_change,
        fixture.baseline.layout.taker_payment_change,
        fixture.baseline.layout.fee_output,
    ] {
        assert_eq!(
            reparsed.outputs()[index],
            canonical_original.outputs()[index]
        );
    }

    let final_pset = finish_taker_blinding_and_signing(&fixture, blinded.bytes());
    ProviderSettlementValidator::new(
        fixture.book(),
        &fixture.baseline.chain,
        &fixture.output_recovery,
    )
    .validate(
        fixture.access,
        &settlement_layout(&fixture),
        &serialize(&final_pset),
    )
    .expect("wallet-backed provider blinding produces a valid final settlement");

    let debug = format!("{blinded:?}");
    assert!(debug.contains(&blinded.bytes().len().to_string()));
    assert_eq!(
        debug,
        format!("ProviderBlindedPset {{ bytes: {} }}", blinded.bytes().len())
    );
}

#[test]
fn every_reserved_input_opening_participates_in_multi_input_blinding() {
    let fixture = SettlementFixture::with_multiple_provider_inputs();
    let blinded =
        provider_blind(&fixture, &fixture.unblinded_pset).expect("multi-input provider blinding");
    let pset =
        deserialize::<PartiallySignedTransaction>(blinded.bytes()).expect("provider-blinded PSET");
    assert_eq!(fixture.quote.contribution().inputs().len(), 2);
    assert_eq!(pset.global.scalars.len(), 1);

    let provider_blinder_id = fixture
        .quote
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.role() == QuoteOutputRole::TakerReceive)
        .expect("taker receive")
        .blinder();
    let QuoteBlinderRole::ProviderInput(provider_blinder_id) = provider_blinder_id else {
        panic!("taker receive must use provider blinding");
    };
    let expected_input = fixture.baseline.layout.provider_input(provider_blinder_id);
    for output in fixture
        .quote
        .contribution()
        .outputs()
        .iter()
        .filter(|output| matches!(output.blinder(), QuoteBlinderRole::ProviderInput(_)))
    {
        assert_eq!(
            pset.outputs()[fixture.baseline.layout.quote_output(output.id())].blinder_index,
            Some(u32::try_from(expected_input).expect("input index"))
        );
    }

    let final_pset = finish_taker_blinding_and_signing(&fixture, blinded.bytes());
    ProviderSettlementValidator::new(
        fixture.book(),
        &fixture.baseline.chain,
        &fixture.output_recovery,
    )
    .validate(
        fixture.access,
        &settlement_layout(&fixture),
        &serialize(&final_pset),
    )
    .expect("multi-input provider blinding balances in the final settlement");
}

#[test]
fn unquoted_output_cannot_use_a_provider_blinding_input() {
    let fixture = SettlementFixture::new();
    let mut pset = fixture.unblinded_pset.clone();
    let provider_input = fixture
        .baseline
        .layout
        .provider_input(fixture.quote.contribution().inputs()[0].id());
    pset.outputs_mut()[fixture.baseline.layout.taker_fee_change].blinder_index =
        Some(u32::try_from(provider_input).expect("provider input index"));

    assert!(matches!(
        provider_blind(&fixture, &pset),
        Err(ProviderBlindingError::UnquotedProviderBlindedOutput(index))
            if index == fixture.baseline.layout.taker_fee_change
    ));
}

#[test]
fn durable_quote_inputs_outputs_and_layout_are_rechecked_before_openings() {
    let fixture = SettlementFixture::new();
    let mut wrong_input = fixture.unblinded_pset.clone();
    let first_provider = fixture.quote.contribution().inputs()[0].id();
    let provider_index = fixture.baseline.layout.provider_input(first_provider);
    let wrong_prevout = wrong_input.inputs()[fixture.baseline.layout.taker_payment_input]
        .witness_utxo
        .clone();
    wrong_input.inputs_mut()[provider_index].witness_utxo = wrong_prevout;
    assert!(matches!(
        provider_blind(&fixture, &wrong_input),
        Err(ProviderBlindingError::Settlement(
            SettlementValidationError::InvalidInput { .. }
        ))
    ));

    let mut wrong_output = fixture.unblinded_pset.clone();
    let receive = fixture
        .quote
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.role() == QuoteOutputRole::TakerReceive)
        .expect("taker receive");
    let receive_index = fixture.baseline.layout.quote_output(receive.id());
    wrong_output.outputs_mut()[receive_index].amount = Some(receive.amount() + 1);
    assert!(matches!(
        provider_blind(&fixture, &wrong_output),
        Err(ProviderBlindingError::Settlement(
            SettlementValidationError::InvalidQuotedOutput { .. }
        ))
    ));

    let mut wrong_layout = settlement_layout(&fixture);
    wrong_layout.provider_inputs[0].transaction_index = fixture.baseline.layout.taker_payment_input;
    assert!(matches!(
        ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
            fixture.access,
            &wrong_layout,
            &serialize(&fixture.unblinded_pset),
            &VALIDATION_TIME,
            &mut thread_rng(),
        ),
        Err(ProviderBlindingError::Settlement(
            SettlementValidationError::LayoutInputMismatch
        ))
    ));
}

#[test]
fn wrong_owner_expired_and_committed_reservations_cannot_blind() {
    let fixture = SettlementFixture::new();
    let wrong_access = ReservationAccess::new(fixture.reservation.id(), OwnerId::new([0x91; 32]));
    assert!(matches!(
        ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
            wrong_access,
            &settlement_layout(&fixture),
            &serialize(&fixture.unblinded_pset),
            &VALIDATION_TIME,
            &mut thread_rng(),
        ),
        Err(ProviderBlindingError::Provider(
            crate::store::ProviderError::ReservationOwnerMismatch(_)
        ))
    ));

    assert!(matches!(
        ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
            fixture.access,
            &settlement_layout(&fixture),
            &serialize(&fixture.unblinded_pset),
            &UnixMillis::new(fixture.quote.accept_before().value()),
            &mut thread_rng(),
        ),
        Err(ProviderBlindingError::Provider(
            crate::store::ProviderError::ReservationDeadlineElapsed { .. }
        ))
    ));

    let submission = fixture.submission();
    ProviderSettlementValidator::new(fixture.book(), &submission.chain, &fixture.output_recovery)
        .validate(
            fixture.access,
            &settlement_layout(&fixture),
            &submission.canonical_pset_bytes(),
        )
        .expect("baseline final settlement")
        .commit(fixture.book(), &VALIDATION_TIME)
        .expect("commit signing intent");
    assert!(matches!(
        provider_blind(&fixture, &fixture.unblinded_pset),
        Err(ProviderBlindingError::PointOfNoReturn(id)) if id == fixture.reservation.id()
    ));
}

#[test]
fn preexisting_blinding_artifacts_are_rejected_instead_of_merged() {
    let fixture = SettlementFixture::new();
    let mut pset = fixture.unblinded_pset.clone();
    let receive = fixture
        .quote
        .contribution()
        .outputs()
        .iter()
        .find(|output| output.role() == QuoteOutputRole::TakerReceive)
        .expect("taker receive");
    let index = fixture.baseline.layout.quote_output(receive.id());
    pset.outputs_mut()[index].asset_comm = fixture.baseline.pset.outputs()[index].asset_comm;

    assert!(provider_blind(&fixture, &pset).is_err());
}

#[test]
fn canonical_payload_bounds_apply_before_rng_or_secret_access() {
    let fixture = SettlementFixture::new();
    let mut rng = CountingRng::default();
    let result = ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
        fixture.access,
        &settlement_layout(&fixture),
        &[0xff],
        &VALIDATION_TIME,
        &mut rng,
    );
    assert!(matches!(
        result,
        Err(ProviderBlindingError::Settlement(
            SettlementValidationError::InvalidPset(_)
        ))
    ));
    assert_eq!(rng.calls, 0);
}

#[test]
fn stale_current_inventory_fails_closed_before_blinding() {
    let fixture = SettlementFixture::new();
    let mut rng = CountingRng::default();

    assert!(matches!(
        ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
            fixture.access,
            &settlement_layout(&fixture),
            &serialize(&fixture.unblinded_pset),
            &UnixMillis::new(10_100),
            &mut rng,
        ),
        Err(ProviderBlindingError::Inventory(
            InventoryCoordinatorError::SnapshotStale {
                observed_at,
                now,
                maximum_age_millis: 10_000,
            }
        )) if observed_at == UnixMillis::new(100) && now == UnixMillis::new(10_100)
    ));
    assert_eq!(rng.calls, 0);
}

#[test]
fn refreshed_inventory_missing_a_reserved_input_fails_closed() {
    let fixture = SettlementFixture::new();
    fixture.inventory_source.push(
        InventorySnapshot::new(
            fixture.identity,
            WalletScanAnchor::new(BlockHash::from_byte_array([0x88; 32]), 66),
            Vec::new(),
        )
        .expect("empty replacement inventory snapshot"),
    );
    fixture
        .engine
        .inventory()
        .refresh(&UnixMillis::new(103))
        .expect("publish complete replacement snapshot");
    let absent = fixture.quote.contribution().inputs()[0].outpoint();
    let mut rng = CountingRng::default();

    assert!(matches!(
        ProviderBlindingCoordinator::new(fixture.engine.inventory()).blind(
            fixture.access,
            &settlement_layout(&fixture),
            &serialize(&fixture.unblinded_pset),
            &UnixMillis::new(104),
            &mut rng,
        ),
        Err(ProviderBlindingError::ProviderInputAbsent(outpoint)) if outpoint == absent
    ));
    assert_eq!(rng.calls, 0);
}

#[test]
fn successful_precommit_retries_may_use_fresh_blinding_randomness() {
    let fixture = SettlementFixture::new();
    let first = provider_blind(&fixture, &fixture.unblinded_pset)
        .expect("first reversible provider-blinding attempt");
    let second = provider_blind(&fixture, &fixture.unblinded_pset)
        .expect("second reversible provider-blinding attempt");

    assert_ne!(first.bytes(), second.bytes());
    for attempt in [&first, &second] {
        let pset = deserialize::<PartiallySignedTransaction>(attempt.bytes())
            .expect("canonical provider-blinded retry");
        assert_eq!(pset.global.scalars.len(), 1);
        for output in fixture
            .quote
            .contribution()
            .outputs()
            .iter()
            .filter(|output| matches!(output.blinder(), QuoteBlinderRole::ProviderInput(_)))
        {
            assert!(!output_is_unblinded(
                &pset.outputs()[fixture.baseline.layout.quote_output(output.id())]
            ));
        }
    }
}

#[derive(Default)]
struct CountingRng {
    calls: usize,
}

impl elements::secp256k1_zkp::rand::RngCore for CountingRng {
    fn next_u32(&mut self) -> u32 {
        self.calls += 1;
        1
    }

    fn next_u64(&mut self) -> u64 {
        self.calls += 1;
        1
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.calls += 1;
        destination.fill(1);
    }

    fn try_fill_bytes(
        &mut self,
        destination: &mut [u8],
    ) -> Result<(), elements::secp256k1_zkp::rand::Error> {
        self.fill_bytes(destination);
        Ok(())
    }
}

impl elements::secp256k1_zkp::rand::CryptoRng for CountingRng {}
