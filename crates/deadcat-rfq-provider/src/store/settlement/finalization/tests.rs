use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};

use elements::encode::{deserialize, serialize};
use elements::hashes::Hash as _;
use elements::pset::PartiallySignedTransaction;
use elements::{BlockHash, OutPoint, SchnorrSighashType};
use tempfile::TempDir;
use thiserror::Error;

use super::{ProviderSigningCoordinator, SigningFinalizationError};
use crate::model::{RecoveryAction, SigningJob, UnixMillis};
use crate::store::{CommitOutcome, ProviderError, ReservationBook};
use crate::wallet::{ProviderInputSignature, ProviderSigner, SigningResponse, WalletBoundaryError};

use super::super::ProviderSettlementValidator;
use super::super::tests::{FixtureWallet, SettlementFixture, VALIDATION_TIME};

#[derive(Clone)]
enum SignerBehavior {
    Valid,
    WrongKey(Box<FixtureWallet>),
    WrongGenesis(BlockHash),
    WrongCommitment,
    Fail,
}

#[derive(Debug, Error)]
enum FixtureSignerError {
    #[error("injected signer failure")]
    Injected,
    #[error("invalid committed fixture PSET")]
    InvalidPset,
    #[error(transparent)]
    Wallet(#[from] WalletBoundaryError),
}

struct FixtureSigner {
    wallet: FixtureWallet,
    genesis_hash: BlockHash,
    behavior: SignerBehavior,
    calls: Arc<AtomicUsize>,
}

impl FixtureSigner {
    fn valid(fixture: &SettlementFixture) -> Self {
        Self::new(fixture, SignerBehavior::Valid)
    }

    fn new(fixture: &SettlementFixture, behavior: SignerBehavior) -> Self {
        Self {
            wallet: fixture.provider_inventory_wallet.clone(),
            genesis_hash: fixture.identity.genesis_hash(),
            behavior,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn signatures(
        &self,
        job: &SigningJob,
        wallet: &FixtureWallet,
        genesis_hash: BlockHash,
    ) -> Result<Vec<ProviderInputSignature>, FixtureSignerError> {
        let mut pset = deserialize::<PartiallySignedTransaction>(job.pre_sign_payload())
            .map_err(|_| FixtureSignerError::InvalidPset)?;
        job.targets()
            .iter()
            .map(|target| {
                let index = pset
                    .inputs()
                    .iter()
                    .position(|input| input_outpoint(input) == target.outpoint())
                    .ok_or(FixtureSignerError::InvalidPset)?;
                let signature = wallet.sign_input(&mut pset, index, genesis_hash);
                ProviderInputSignature::new(target.outpoint(), signature).map_err(Into::into)
            })
            .collect()
    }
}

impl ProviderSigner for FixtureSigner {
    type Error = FixtureSignerError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.behavior {
            SignerBehavior::Fail => Err(FixtureSignerError::Injected),
            SignerBehavior::Valid => {
                let signatures = self.signatures(job, &self.wallet, self.genesis_hash)?;
                SigningResponse::new(job, signatures).map_err(Into::into)
            }
            SignerBehavior::WrongKey(wallet) => {
                let signatures = self.signatures(job, wallet, self.genesis_hash)?;
                SigningResponse::new(job, signatures).map_err(Into::into)
            }
            SignerBehavior::WrongGenesis(genesis_hash) => {
                let signatures = self.signatures(job, &self.wallet, *genesis_hash)?;
                SigningResponse::new(job, signatures).map_err(Into::into)
            }
            SignerBehavior::WrongCommitment => {
                let signatures = self.signatures(job, &self.wallet, self.genesis_hash)?;
                let mut other = job.clone();
                other.commitment = crate::model::SigningCommitment::new([0x93; 32]);
                SigningResponse::new(&other, signatures).map_err(Into::into)
            }
        }
    }
}

fn committed_outcome(fixture: &SettlementFixture) -> CommitOutcome {
    settlement_outcome_at(fixture, VALIDATION_TIME)
}

fn settlement_outcome_at(fixture: &SettlementFixture, clock: UnixMillis) -> CommitOutcome {
    let submission = fixture.submission();
    let layout = submission
        .layout
        .settlement_layout()
        .expect("settlement layout");
    ProviderSettlementValidator::new(fixture.book(), &submission.chain, &fixture.output_recovery)
        .validate(fixture.access, &layout, &submission.canonical_pset_bytes())
        .expect("valid settlement")
        .commit(fixture.book(), &clock)
        .expect("durable signing commit")
}

fn committed_job(fixture: &SettlementFixture) -> SigningJob {
    committed_outcome(fixture)
        .signing_job()
        .expect("committed signing job")
        .clone()
}

fn input_outpoint(input: &elements::pset::Input) -> OutPoint {
    OutPoint::new(input.previous_txid, input.previous_output_index)
}

#[test]
fn real_signatures_finalize_only_provider_fields_and_persist_before_return() {
    let fixture = SettlementFixture::new();
    let outcome = committed_outcome(&fixture);
    let job = outcome
        .signing_job()
        .expect("committed signing job")
        .clone();
    let signer = FixtureSigner::valid(&fixture);
    let signed = ProviderSigningCoordinator::new(fixture.book(), &signer)
        .complete(outcome, &UnixMillis::new(103))
        .expect("sign and persist final PSET");

    assert!(signed.recorded());
    assert_eq!(signer.calls(), 1);
    assert_eq!(signed.artifact().reservation_id(), job.reservation_id());
    assert_eq!(signed.artifact().commitment(), job.commitment());

    let original =
        deserialize::<PartiallySignedTransaction>(job.pre_sign_payload()).expect("committed PSET");
    let finalized =
        deserialize::<PartiallySignedTransaction>(signed.artifact().bytes()).expect("signed PSET");
    assert_eq!(serialize(&finalized), signed.artifact().bytes());
    assert_eq!(original.global, finalized.global);
    assert_eq!(original.outputs(), finalized.outputs());
    assert_eq!(
        original.extract_tx().expect("original transaction").txid(),
        finalized.extract_tx().expect("final transaction").txid()
    );

    let target_outpoints = job
        .targets()
        .iter()
        .map(|target| target.outpoint())
        .collect::<Vec<_>>();
    let mut normalized = finalized.clone();
    for (index, (before, after)) in original.inputs().iter().zip(finalized.inputs()).enumerate() {
        if target_outpoints.contains(&input_outpoint(before)) {
            let signature = after.tap_key_sig.expect("provider signature");
            assert_eq!(signature.hash_ty, SchnorrSighashType::All);
            assert_eq!(
                after.final_script_witness.as_ref(),
                Some(&vec![signature.to_vec()])
            );
            normalized.inputs_mut()[index].tap_key_sig = None;
            normalized.inputs_mut()[index].final_script_witness = None;
        } else {
            assert_eq!(before, after, "non-provider input changed at {index}");
        }
    }
    assert_eq!(serialize(&normalized), job.pre_sign_payload());
    assert!(matches!(
        fixture.book().recovery_actions().expect("recovery state").as_slice(),
        [RecoveryAction::ReplaySignedExact(artifact)] if artifact == signed.artifact()
    ));
}

#[test]
fn real_signatures_finalize_every_input_in_a_multi_input_provider_job() {
    let fixture = SettlementFixture::with_multiple_provider_inputs();
    let outcome = committed_outcome(&fixture);
    let job = outcome
        .signing_job()
        .expect("committed multi-input signing job")
        .clone();
    assert_eq!(job.targets().len(), 2);

    let signer = FixtureSigner::valid(&fixture);
    let signed = ProviderSigningCoordinator::new(fixture.book(), &signer)
        .complete(outcome, &UnixMillis::new(103))
        .expect("sign and persist every provider input");
    assert!(signed.recorded());
    assert_eq!(signer.calls(), 1);

    let original =
        deserialize::<PartiallySignedTransaction>(job.pre_sign_payload()).expect("committed PSET");
    let finalized = deserialize::<PartiallySignedTransaction>(signed.artifact().bytes())
        .expect("multi-input signed PSET");
    let mut normalized = finalized.clone();
    let mut finalized_indexes = Vec::new();
    for target in job.targets() {
        let index = original
            .inputs()
            .iter()
            .position(|input| input_outpoint(input) == target.outpoint())
            .expect("durable target input");
        assert!(
            !finalized_indexes.contains(&index),
            "provider targets must resolve injectively"
        );
        finalized_indexes.push(index);
        let signature = finalized.inputs()[index]
            .tap_key_sig
            .expect("provider signature");
        assert_eq!(signature.hash_ty, SchnorrSighashType::All);
        assert_eq!(
            finalized.inputs()[index].final_script_witness.as_ref(),
            Some(&vec![signature.to_vec()])
        );
        normalized.inputs_mut()[index].tap_key_sig = None;
        normalized.inputs_mut()[index].final_script_witness = None;
    }
    assert_eq!(finalized_indexes.len(), 2);
    assert_eq!(serialize(&normalized), job.pre_sign_payload());
}

#[test]
fn invalid_signatures_and_signer_failures_leave_the_exact_job_recoverable() {
    for behavior in [
        SignerBehavior::WrongKey(Box::new(FixtureWallet::deterministic(81, 82))),
        SignerBehavior::WrongGenesis(BlockHash::from_byte_array([83; 32])),
        SignerBehavior::WrongCommitment,
        SignerBehavior::Fail,
    ] {
        let fixture = SettlementFixture::new();
        let job = committed_job(&fixture);
        let signer = FixtureSigner::new(&fixture, behavior.clone());
        let result = ProviderSigningCoordinator::new(fixture.book(), &signer)
            .finalize(&job, &UnixMillis::new(103));

        match behavior {
            SignerBehavior::WrongKey(_) | SignerBehavior::WrongGenesis(_) => assert!(matches!(
                result,
                Err(SigningFinalizationError::InvalidProviderSignature { .. })
            )),
            SignerBehavior::WrongCommitment => assert!(matches!(
                result,
                Err(SigningFinalizationError::ResponseCommitmentMismatch)
            )),
            SignerBehavior::Fail => {
                assert!(matches!(result, Err(SigningFinalizationError::Signer(_))))
            }
            SignerBehavior::Valid => unreachable!(),
        }
        assert_eq!(signer.calls(), 1);
        assert!(matches!(
            fixture.book().recovery_actions().expect("recovery state").as_slice(),
            [RecoveryAction::SignCommittedExact(actual)] if actual == &job
        ));
    }
}

#[test]
fn signed_and_stale_job_replays_do_not_invoke_the_signer() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let first_signer = FixtureSigner::valid(&fixture);
    let first = ProviderSigningCoordinator::new(fixture.book(), &first_signer)
        .finalize(&job, &UnixMillis::new(103))
        .expect("initial finalization");
    assert_eq!(first_signer.calls(), 1);

    let replay_signer = FixtureSigner::new(&fixture, SignerBehavior::Fail);
    let coordinator = ProviderSigningCoordinator::new(fixture.book(), &replay_signer);
    let completed_retry = coordinator
        .complete(
            settlement_outcome_at(&fixture, UnixMillis::new(104)),
            &UnixMillis::new(105),
        )
        .expect("exact signed validation replay");
    assert!(!completed_retry.recorded());
    assert_eq!(completed_retry.artifact(), first.artifact());
    assert_eq!(replay_signer.calls(), 0);

    let replay = coordinator
        .finalize(&job, &UnixMillis::new(106))
        .expect("stale job resolves to signed artifact");
    assert!(!replay.recorded());
    assert_eq!(replay.artifact(), first.artifact());
    assert_eq!(replay_signer.calls(), 0);

    let action = fixture
        .book()
        .recovery_actions()
        .expect("recovery state")
        .pop()
        .expect("signed replay action");
    let recovered = coordinator
        .recover(action, &UnixMillis::new(107))
        .expect("replay recovery");
    assert!(!recovered.recorded());
    assert_eq!(recovered.artifact(), first.artifact());
    assert_eq!(replay_signer.calls(), 0);
}

#[test]
fn foreign_and_tampered_jobs_fail_preflight_without_invoking_the_signer() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let signer = FixtureSigner::new(&fixture, SignerBehavior::Fail);

    let mut tampered = job.clone();
    tampered.pre_sign_payload.push(0);
    assert!(matches!(
        ProviderSigningCoordinator::new(fixture.book(), &signer)
            .finalize(&tampered, &UnixMillis::new(103)),
        Err(SigningFinalizationError::Provider(
            ProviderError::SigningJobBindingMismatch(_)
        ))
    ));
    assert_eq!(signer.calls(), 0);

    let other_directory = TempDir::new().expect("other book directory");
    let other_book = ReservationBook::open(
        other_directory.path().join("provider.redb"),
        fixture.identity,
    )
    .expect("other provider book");
    assert!(matches!(
        ProviderSigningCoordinator::new(&other_book, &signer).finalize(&job, &UnixMillis::new(103)),
        Err(SigningFinalizationError::Provider(
            ProviderError::ReservationNotFound(_)
        ))
    ));
    assert_eq!(signer.calls(), 0);
}

#[test]
fn committed_recovery_signs_and_then_becomes_an_exact_replay() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let action = fixture
        .book()
        .recovery_actions()
        .expect("committed recovery state")
        .pop()
        .expect("sign action");
    assert!(matches!(
        &action,
        RecoveryAction::SignCommittedExact(actual) if actual == &job
    ));

    let signer = FixtureSigner::valid(&fixture);
    let (directory, identity) = fixture.close_book();
    let database_path = directory.path().join("provider.redb");
    let book = ReservationBook::open(&database_path, identity).expect("reopen committed provider");
    let signed = ProviderSigningCoordinator::new(&book, &signer)
        .recover(action, &UnixMillis::new(103))
        .expect("recover committed signing job after restart");
    assert!(signed.recorded());
    assert_eq!(signer.calls(), 1);

    let replay = book
        .recovery_actions()
        .expect("signed recovery state")
        .pop()
        .expect("replay action");
    assert!(matches!(
        &replay,
        RecoveryAction::ReplaySignedExact(artifact) if artifact == signed.artifact()
    ));
    drop(book);
    let reopened =
        ReservationBook::open(database_path, identity).expect("reopen signed provider state");
    let replayed = ProviderSigningCoordinator::new(&reopened, &signer)
        .recover(replay, &UnixMillis::new(104))
        .expect("recover durable signed artifact after restart");
    assert!(!replayed.recorded());
    assert_eq!(replayed.artifact(), signed.artifact());
    assert_eq!(signer.calls(), 1);
}

#[test]
fn persistence_failpoints_return_no_candidate_and_leave_exact_recovery_work() {
    for failpoint in [
        super::super::super::mutation_failpoints::SIGNED_AFTER_RECORD,
        super::super::super::mutation_failpoints::SIGNED_AFTER_AUDIT,
    ] {
        let fixture = SettlementFixture::new();
        let job = committed_job(&fixture);
        let signer = FixtureSigner::valid(&fixture);
        let coordinator = ProviderSigningCoordinator::new(fixture.book(), &signer);
        let guard = super::super::super::mutation_failpoints::arm(failpoint, 0);
        let result = coordinator.finalize(&job, &UnixMillis::new(103));
        assert!(matches!(
            result,
            Err(SigningFinalizationError::Provider(
                ProviderError::InjectedMutationFailure(actual)
            )) if actual == failpoint
        ));
        drop(guard);
        assert_eq!(signer.calls(), 1);
        let action = fixture
            .book()
            .recovery_actions()
            .expect("rolled-back recovery state")
            .pop()
            .expect("sign action");
        assert!(matches!(
            &action,
            RecoveryAction::SignCommittedExact(actual) if actual == &job
        ));

        let signed = coordinator
            .recover(action, &UnixMillis::new(103))
            .expect("retry after rolled-back persistence");
        assert!(signed.recorded());
        assert_eq!(signer.calls(), 2);
    }
}

struct RacingSigner {
    inner: FixtureSigner,
    barrier: Barrier,
    produced: Mutex<Vec<Vec<u8>>>,
}

struct GatedSigner {
    inner: FixtureSigner,
    entered: mpsc::SyncSender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl ProviderSigner for GatedSigner {
    type Error = FixtureSignerError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        self.entered
            .send(())
            .map_err(|_| FixtureSignerError::Injected)?;
        self.release
            .lock()
            .map_err(|_| FixtureSignerError::Injected)?
            .recv()
            .map_err(|_| FixtureSignerError::Injected)?;
        self.inner.sign(job)
    }
}

impl ProviderSigner for RacingSigner {
    type Error = FixtureSignerError;

    fn sign(&self, job: &SigningJob) -> Result<SigningResponse, Self::Error> {
        self.barrier.wait();
        let response = self.inner.sign(job)?;
        self.produced
            .lock()
            .expect("produced signatures lock")
            .push(
                response
                    .signatures()
                    .iter()
                    .flat_map(|signature| signature.serialized().iter().copied())
                    .collect(),
            );
        Ok(response)
    }
}

#[test]
fn concurrent_distinct_valid_signatures_return_one_durable_winner() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let signer = RacingSigner {
        inner: FixtureSigner::valid(&fixture),
        barrier: Barrier::new(2),
        produced: Mutex::new(Vec::new()),
    };

    let (first, second) = std::thread::scope(|scope| {
        let first_job = job.clone();
        let second_job = job.clone();
        let book = fixture.book();
        let signer = &signer;
        let first = scope.spawn(move || {
            ProviderSigningCoordinator::new(book, signer)
                .finalize(&first_job, &UnixMillis::new(103))
        });
        let second = scope.spawn(move || {
            ProviderSigningCoordinator::new(book, signer)
                .finalize(&second_job, &UnixMillis::new(104))
        });
        (
            first.join().expect("first finalizer thread"),
            second.join().expect("second finalizer thread"),
        )
    });
    let first = first.expect("first finalization");
    let second = second.expect("second finalization");
    assert_eq!(first.artifact(), second.artifact());
    assert_ne!(first.recorded(), second.recorded());
    assert_eq!(signer.inner.calls(), 2);
    let produced = signer.produced.lock().expect("produced signatures lock");
    assert_eq!(produced.len(), 2);
    assert_ne!(produced[0], produced[1]);
    assert!(matches!(
        fixture.book().recovery_actions().expect("recovery state").as_slice(),
        [RecoveryAction::ReplaySignedExact(artifact)] if artifact == first.artifact()
    ));
}

#[test]
fn stale_concurrent_candidate_replays_the_newer_clock_winner() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let (entered_sender, entered_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let stale_signer = GatedSigner {
        inner: FixtureSigner::valid(&fixture),
        entered: entered_sender,
        release: Mutex::new(release_receiver),
    };
    let winner_signer = FixtureSigner::valid(&fixture);

    let (winner, stale) = std::thread::scope(|scope| {
        let stale_job = job.clone();
        let book = fixture.book();
        let signer = &stale_signer;
        let stale_worker = scope.spawn(move || {
            ProviderSigningCoordinator::new(book, signer)
                .finalize(&stale_job, &UnixMillis::new(103))
        });
        entered_receiver
            .recv()
            .expect("stale worker reached the signer after preflight");
        let winner = ProviderSigningCoordinator::new(fixture.book(), &winner_signer)
            .finalize(&job, &UnixMillis::new(104));
        release_sender
            .send(())
            .expect("release stale signing response");
        (winner, stale_worker.join().expect("stale finalizer thread"))
    });
    let winner = winner.expect("newer-clock finalization");
    let stale = stale.expect("stale candidate replays winner");
    assert!(winner.recorded());
    assert!(!stale.recorded());
    assert_eq!(stale.artifact(), winner.artifact());
    assert!(matches!(
        fixture.book().last_observed_time(),
        Ok(Some(observed)) if observed == UnixMillis::new(104)
    ));
    assert_eq!(winner_signer.calls(), 1);
    assert_eq!(stale_signer.inner.calls(), 1);
}

#[test]
fn concurrent_signer_error_replays_the_durable_winner() {
    let fixture = SettlementFixture::new();
    let job = committed_job(&fixture);
    let (entered_sender, entered_receiver) = mpsc::sync_channel(0);
    let (release_sender, release_receiver) = mpsc::sync_channel(0);
    let failing_signer = GatedSigner {
        inner: FixtureSigner::new(&fixture, SignerBehavior::Fail),
        entered: entered_sender,
        release: Mutex::new(release_receiver),
    };
    let winner_signer = FixtureSigner::valid(&fixture);

    let (winner, raced_failure) = std::thread::scope(|scope| {
        let failing_job = job.clone();
        let book = fixture.book();
        let signer = &failing_signer;
        let failing_worker = scope.spawn(move || {
            ProviderSigningCoordinator::new(book, signer)
                .finalize(&failing_job, &UnixMillis::new(103))
        });
        entered_receiver
            .recv()
            .expect("failing worker reached the signer after preflight");
        let winner = ProviderSigningCoordinator::new(fixture.book(), &winner_signer)
            .finalize(&job, &UnixMillis::new(104));
        release_sender
            .send(())
            .expect("release failing signing response");
        (
            winner,
            failing_worker.join().expect("failing finalizer thread"),
        )
    });
    let winner = winner.expect("concurrent worker durably finalized the job");
    let raced_failure = raced_failure.expect("signer error resolves to durable winner");
    assert!(winner.recorded());
    assert!(!raced_failure.recorded());
    assert_eq!(raced_failure.artifact(), winner.artifact());
    assert!(matches!(
        fixture.book().last_observed_time(),
        Ok(Some(observed)) if observed == UnixMillis::new(104)
    ));
    assert_eq!(winner_signer.calls(), 1);
    assert_eq!(failing_signer.inner.calls(), 1);
}
