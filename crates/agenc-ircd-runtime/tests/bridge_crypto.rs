//! Crypto bridge admission, completion, cancellation, and the channel-key
//! job (spec 21.3, line 4085; 21.7, lines 4242-4250).
#![forbid(unsafe_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::Duration;

use agenc_ircd_crypto::{CryptoError, CryptoWorkerConfig, CryptoWorkerError};
use agenc_ircd_runtime::RuntimeError;
use agenc_ircd_runtime::bridge::crypto::{
    CHANNEL_KEY_ARGON2_ITERATIONS, CHANNEL_KEY_ARGON2_MEMORY_KIB, CHANNEL_KEY_ARGON2_PARALLELISM,
    CHANNEL_KEY_HASH_BYTES, CHANNEL_KEY_SALT_BYTES, ChannelKeyConstructJob, ChannelKeyTarget,
    ChannelKeyVerifier, ChannelKeyVerifierRecord, ChannelKeyVerifyJob, CryptoBridge,
    CryptoJobOutput, MAX_CHANNEL_KEY_BYTES, MIN_CHANNEL_KEY_BYTES, RuntimeCryptoJob,
};

/// A stand-in derivation: the hash is the salt XOR the first secret byte
/// repeated, so matching and mismatching records are cheap to construct.
struct FakeVerifier {
    derivations: AtomicUsize,
    fail: bool,
}

impl ChannelKeyVerifier for FakeVerifier {
    fn derive(
        &self,
        secret: &[u8],
        salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], CryptoError> {
        self.derivations.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(CryptoError::LimitExceeded);
        }
        let first = secret.first().copied().unwrap_or(0);
        let mut hash = [0_u8; CHANNEL_KEY_HASH_BYTES];
        for (index, byte) in hash.iter_mut().enumerate() {
            *byte = salt
                .get(index % CHANNEL_KEY_SALT_BYTES)
                .copied()
                .unwrap_or(0)
                ^ first;
        }
        Ok(hash)
    }
}

/// A verifier that blocks until released, to fill the pool deterministically.
struct BlockingVerifier {
    started: SyncSender<()>,
    release: std::sync::Mutex<Receiver<()>>,
}

impl ChannelKeyVerifier for BlockingVerifier {
    fn derive(
        &self,
        _secret: &[u8],
        _salt: &[u8; CHANNEL_KEY_SALT_BYTES],
    ) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], CryptoError> {
        let _ = self.started.send(());
        if let Ok(release) = self.release.lock() {
            let _ = release.recv();
        }
        Ok([0; CHANNEL_KEY_HASH_BYTES])
    }
}

fn record(salt_byte: u8, secret_byte: u8) -> ChannelKeyVerifierRecord {
    let salt = [salt_byte; CHANNEL_KEY_SALT_BYTES];
    ChannelKeyVerifierRecord::new(salt, [salt_byte ^ secret_byte; CHANNEL_KEY_HASH_BYTES])
}

fn job(
    verifier: Arc<dyn ChannelKeyVerifier>,
    target: ChannelKeyTarget,
    secret: &[u8],
) -> Result<RuntimeCryptoJob, RuntimeError> {
    Ok(RuntimeCryptoJob::ChannelKeyVerify(
        ChannelKeyVerifyJob::new(verifier, target, secret.to_vec())?,
    ))
}

async fn verdict(
    bridge: &mut CryptoBridge,
    receiver: &mut tokio::sync::mpsc::Receiver<
        agenc_ircd_runtime::bridge::CryptoCompletionMessage<CryptoJobOutput>,
    >,
    job: RuntimeCryptoJob,
) -> Result<bool, Box<dyn std::error::Error>> {
    let job_id = bridge.try_submit(job).map_err(|refused| refused.reason())?;
    let message = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
        .await?
        .ok_or("completion channel closed")?;
    assert_eq!(message.job_id, job_id);
    match message.output? {
        CryptoJobOutput::ChannelKey(verdict) => Ok(verdict.matches()),
        _ => Err("unexpected output kind".into()),
    }
}

#[test]
fn the_argon2_parameters_and_key_bounds_are_the_spec_values() {
    assert_eq!(CHANNEL_KEY_ARGON2_MEMORY_KIB, 65_536);
    assert_eq!(CHANNEL_KEY_ARGON2_ITERATIONS, 3);
    assert_eq!(CHANNEL_KEY_ARGON2_PARALLELISM, 4);
    assert_eq!(CHANNEL_KEY_SALT_BYTES, 16);
    assert_eq!(MIN_CHANNEL_KEY_BYTES, 8);
    assert_eq!(MAX_CHANNEL_KEY_BYTES, 256);
    let verifier: Arc<dyn ChannelKeyVerifier> = Arc::new(FakeVerifier {
        derivations: AtomicUsize::new(0),
        fail: false,
    });
    let stored = ChannelKeyTarget::Stored(record(1, 2));
    assert_eq!(
        ChannelKeyVerifyJob::new(verifier.clone(), stored, vec![2; 7])
            .err()
            .map(|error| error.to_string()),
        Some(RuntimeError::InvalidValue.to_string())
    );
    assert!(ChannelKeyVerifyJob::new(verifier.clone(), stored, vec![2; 257]).is_err());
    assert!(ChannelKeyVerifyJob::new(verifier.clone(), stored, vec![2; 8]).is_ok());
    assert!(ChannelKeyVerifyJob::new(verifier.clone(), stored, vec![2; 256]).is_ok());
    assert!(ChannelKeyConstructJob::new(verifier.clone(), [3; 16], vec![2; 7]).is_err());
    assert!(ChannelKeyConstructJob::new(verifier.clone(), [3; 16], vec![2; 257]).is_err());
    assert!(ChannelKeyConstructJob::new(verifier.clone(), [3; 16], vec![2; 8]).is_ok());
    assert!(ChannelKeyConstructJob::new(verifier, [3; 16], vec![2; 256]).is_ok());
    let stored_record = record(9, 4);
    assert_eq!(stored_record.salt(), &[9; CHANNEL_KEY_SALT_BYTES]);
    assert_eq!(stored_record.hash(), &[9 ^ 4; CHANNEL_KEY_HASH_BYTES]);
}

#[tokio::test]
async fn channel_key_jobs_derive_once_and_dummy_targets_never_match()
-> Result<(), Box<dyn std::error::Error>> {
    let verifier = Arc::new(FakeVerifier {
        derivations: AtomicUsize::new(0),
        fail: false,
    });
    let shared: Arc<dyn ChannelKeyVerifier> = verifier.clone();
    let (mut bridge, mut receiver) = CryptoBridge::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let matching = job(
        shared.clone(),
        ChannelKeyTarget::Stored(record(1, 2)),
        &[2; 8],
    )?;
    assert!(verdict(&mut bridge, &mut receiver, matching).await?);
    let wrong = job(
        shared.clone(),
        ChannelKeyTarget::Stored(record(1, 2)),
        &[3; 8],
    )?;
    assert!(!verdict(&mut bridge, &mut receiver, wrong).await?);
    let dummy = job(
        shared.clone(),
        ChannelKeyTarget::Dummy(record(1, 2)),
        &[2; 8],
    )?;
    assert!(
        !verdict(&mut bridge, &mut receiver, dummy).await?,
        "a dummy target derives but never matches"
    );
    assert_eq!(verifier.derivations.load(Ordering::SeqCst), 3);
    let failing: Arc<dyn ChannelKeyVerifier> = Arc::new(FakeVerifier {
        derivations: AtomicUsize::new(0),
        fail: true,
    });
    let erroring = job(failing, ChannelKeyTarget::Stored(record(1, 2)), &[2; 8])?;
    assert!(!verdict(&mut bridge, &mut receiver, erroring).await?);
    assert_eq!(bridge.in_flight(), 0);
    bridge.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn channel_key_construction_derives_once_and_returns_the_supplied_salt()
-> Result<(), Box<dyn std::error::Error>> {
    let verifier = Arc::new(FakeVerifier {
        derivations: AtomicUsize::new(0),
        fail: false,
    });
    let shared: Arc<dyn ChannelKeyVerifier> = verifier.clone();
    let (mut bridge, mut receiver) = CryptoBridge::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let job = RuntimeCryptoJob::ChannelKeyConstruct(ChannelKeyConstructJob::new(
        shared,
        [9; CHANNEL_KEY_SALT_BYTES],
        vec![4; MIN_CHANNEL_KEY_BYTES],
    )?);
    let job_id = bridge.try_submit(job).map_err(|refused| refused.reason())?;
    let message = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
        .await?
        .ok_or("completion channel closed")?;
    assert_eq!(message.job_id, job_id);
    let CryptoJobOutput::ChannelKeyConstruct(constructed) = message.output? else {
        return Err("unexpected output kind".into());
    };
    let constructed = constructed?;
    assert_eq!(constructed.salt(), &[9; CHANNEL_KEY_SALT_BYTES]);
    assert_eq!(constructed.hash(), &[9 ^ 4; CHANNEL_KEY_HASH_BYTES]);
    assert_eq!(verifier.derivations.load(Ordering::SeqCst), 1);
    bridge.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn a_full_pool_refuses_with_server_busy_and_returns_the_job()
-> Result<(), Box<dyn std::error::Error>> {
    let (started_sender, started_receiver) = sync_channel(4);
    let (release_sender, release_receiver) = sync_channel(4);
    let blocking: Arc<dyn ChannelKeyVerifier> = Arc::new(BlockingVerifier {
        started: started_sender,
        release: std::sync::Mutex::new(release_receiver),
    });
    // One worker, one channel-class slot: the second job is refused before
    // it is enqueued, and the pool returns it unchanged.
    let (mut bridge, mut receiver) = CryptoBridge::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let target = ChannelKeyTarget::Stored(record(1, 1));
    let first = bridge
        .try_submit(job(blocking.clone(), target, &[1; 8])?)
        .map_err(|refused| refused.reason())?;
    started_receiver.recv_timeout(Duration::from_secs(30))?;
    let Err(refused) = bridge.try_submit(job(blocking.clone(), target, &[1; 8])?) else {
        return Err("second job was admitted".into());
    };
    assert_eq!(refused.reason(), CryptoWorkerError::QueueFull);
    assert!(refused.is_server_busy());
    assert!(refused.to_string().is_ascii());
    let returned = refused.into_job();
    assert!(matches!(returned, RuntimeCryptoJob::ChannelKeyVerify(_)));
    assert_eq!(bridge.in_flight(), 1);
    release_sender.send(())?;
    let message = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
        .await?
        .ok_or("completion channel closed")?;
    assert_eq!(message.job_id, first);
    assert!(message.output.is_ok());
    bridge.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn cancelling_one_waiter_fences_its_completion_and_preserves_other_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    let (started_sender, started_receiver) = sync_channel(4);
    let (release_sender, release_receiver) = sync_channel(4);
    let blocking: Arc<dyn ChannelKeyVerifier> = Arc::new(BlockingVerifier {
        started: started_sender,
        release: std::sync::Mutex::new(release_receiver),
    });
    let (mut bridge, mut receiver) = CryptoBridge::start(CryptoWorkerConfig::new(2, 1, 1)?)?;
    let target = ChannelKeyTarget::Stored(record(1, 1));
    let first = bridge
        .try_submit(job(blocking.clone(), target, &[1; 8])?)
        .map_err(|refused| refused.reason())?;
    started_receiver.recv_timeout(Duration::from_secs(30))?;
    let second = bridge
        .try_submit(job(blocking, target, &[1; 8])?)
        .map_err(|refused| refused.reason())?;
    assert_eq!(bridge.in_flight(), 2);
    assert!(bridge.cancel(second));
    assert!(!bridge.cancel(second));
    assert_eq!(bridge.in_flight(), 1);

    release_sender.send(())?;
    let message = tokio::time::timeout(Duration::from_secs(30), receiver.recv())
        .await?
        .ok_or("completion channel closed")?;
    assert_eq!(message.job_id, first);
    assert!(message.output.is_ok());
    assert!(
        tokio::time::timeout(Duration::from_millis(200), receiver.recv())
            .await
            .is_err(),
        "the cancelled waiter forwarded a completion"
    );
    assert!(started_receiver.try_recv().is_err());
    bridge.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn shutdown_aborts_waiters_and_joins_the_pool() -> Result<(), Box<dyn std::error::Error>> {
    let (started_sender, started_receiver) = sync_channel(4);
    let (release_sender, release_receiver) = sync_channel(4);
    let blocking: Arc<dyn ChannelKeyVerifier> = Arc::new(BlockingVerifier {
        started: started_sender,
        release: std::sync::Mutex::new(release_receiver),
    });
    let (mut bridge, receiver) = CryptoBridge::start(CryptoWorkerConfig::new(2, 1, 1)?)?;
    let target = ChannelKeyTarget::Stored(record(1, 1));
    bridge
        .try_submit(job(blocking.clone(), target, &[1; 8])?)
        .map_err(|refused| refused.reason())?;
    started_receiver.recv_timeout(Duration::from_secs(30))?;
    // Queued behind the running job; shutdown must cancel it before start.
    bridge
        .try_submit(job(blocking.clone(), target, &[1; 8])?)
        .map_err(|refused| refused.reason())?;
    assert_eq!(bridge.in_flight(), 2);
    drop(receiver);
    // Shutdown aborts the waiters first, which requests pre-start
    // cancellation of the queued job; the running job is then released so
    // the pool join can complete.
    let shutdown = tokio::spawn(bridge.shutdown());
    tokio::time::sleep(Duration::from_millis(200)).await;
    release_sender.send(())?;
    shutdown.await??;
    assert!(
        started_receiver.try_recv().is_err(),
        "the queued job never started"
    );
    Ok(())
}

#[test]
fn invalid_worker_configuration_is_reported_before_any_thread_starts() {
    let config = CryptoWorkerConfig::new(1, 1, 1);
    assert!(config.is_ok());
    let outside = CryptoWorkerConfig::new(0, 1, 1);
    assert_eq!(outside.err(), Some(CryptoWorkerError::InvalidConfiguration));
}
