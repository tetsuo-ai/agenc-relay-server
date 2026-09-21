#![forbid(unsafe_code)]

//! Secret-canary and supplemental OPAQUE timing-class checks for Stage 04.

use std::hint::black_box;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use agenc_relay_auth::{AuthError, OpaqueKe1, OpaqueProfile, OpaqueRegistrationRecord};
use agenc_relay_crypto::{
    BoundedCryptoPool, CryptoError, CryptoJob, CryptoPort, CryptoWorkerConfig, CryptoWorkerError,
    JobClass,
};
use agenc_relay_types::{NetworkId, OpaqueCredentialId};
use zeroize::Zeroizing;

const OPAQUE_VECTORS: &str =
    include_str!("../../../test-data/vectors/stage-four-opaque-v1.vectors");
const SECRET_CANARY: &str = "agenc-stage-four-secret-canary-7f193d11";
const TIMING_SCHEDULE: [bool; 48] = [
    true, false, false, true, false, true, true, false, true, false, true, false, false, true,
    false, true, true, false, true, false, false, true, false, true, false, true, true, false,
    false, true, true, false, false, true, false, true, true, false, false, true, true, false,
    true, false, false, true, false, true,
];

fn test_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}

fn opaque_record() -> Result<&'static str, io::Error> {
    OPAQUE_VECTORS
        .lines()
        .find(|line| line.starts_with("VEC-S04-007-OPAQUE|"))
        .ok_or_else(|| test_error("OPAQUE vector record is absent"))
}

fn field<'a>(record: &'a str, name: &str) -> Result<&'a str, io::Error> {
    record
        .split('|')
        .skip(3)
        .find_map(|item| {
            item.split_once('=')
                .filter(|(candidate, _)| *candidate == name)
                .map(|(_, value)| value)
        })
        .ok_or_else(|| test_error("OPAQUE vector field is absent"))
}

fn hex_nibble(byte: u8) -> Result<u8, io::Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(test_error("OPAQUE vector is not lowercase hexadecimal")),
    }
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, io::Error> {
    let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(test_error("OPAQUE vector hexadecimal length is odd"));
    }
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(encoded.len() / 2)
        .map_err(|_| test_error("OPAQUE vector allocation failed"))?;
    for [high, low] in pairs {
        decoded.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    Ok(decoded)
}

fn fixed<const SIZE: usize>(record: &str, name: &str) -> Result<[u8; SIZE], io::Error> {
    decode_hex(field(record, name)?)?
        .try_into()
        .map_err(|_| test_error("fixed OPAQUE vector has the wrong length"))
}

enum CanaryBehavior {
    Block {
        started: SyncSender<()>,
        release: Receiver<()>,
    },
    MarkExecuted(Arc<AtomicBool>),
    Panic,
}

struct CanaryJob {
    secret: Zeroizing<String>,
    behavior: CanaryBehavior,
}

impl CanaryJob {
    fn new(behavior: CanaryBehavior) -> Self {
        Self {
            secret: Zeroizing::new(SECRET_CANARY.to_owned()),
            behavior,
        }
    }
}

impl CryptoJob for CanaryJob {
    type Output = usize;

    fn class(&self) -> JobClass {
        JobClass::Opaque
    }

    fn execute(self) -> Self::Output {
        let secret_length = black_box(self.secret.len());
        match self.behavior {
            CanaryBehavior::Block { started, release } => {
                let _started = started.send(());
                let _released = release.recv();
                secret_length
            }
            CanaryBehavior::MarkExecuted(executed) => {
                executed.store(true, Ordering::Release);
                secret_length
            }
            CanaryBehavior::Panic => {
                assert!(black_box(false), "deliberate secret-canary worker failure");
                secret_length
            }
        }
    }
}

fn append_error_formats<T: core::fmt::Debug + core::fmt::Display>(
    output: &mut Vec<String>,
    errors: &[T],
) {
    for error in errors {
        output.push(format!("{error}"));
        output.push(format!("{error:?}"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn secret_canary_never_enters_error_or_worker_capture_text()
-> Result<(), Box<dyn core::error::Error>> {
    let auth_errors = [
        AuthError::InvalidEncoding,
        AuthError::ContextMismatch,
        AuthError::Consumed,
        AuthError::Expired,
        AuthError::WrongConnection,
        AuthError::WrongOrigin,
        AuthError::AuthenticationFailed,
        AuthError::InvitationRejected,
        AuthError::EntropyUnavailable,
        AuthError::AllocationFailed,
        AuthError::Overflow,
        AuthError::WorkerUnavailable,
        AuthError::WrongState,
    ];
    let crypto_errors = [
        CryptoError::EntropyUnavailable,
        CryptoError::InvalidEncoding,
        CryptoError::AuthenticationFailed,
        CryptoError::LimitExceeded,
        CryptoError::Overflow,
        CryptoError::AllocationFailed,
        CryptoError::KindMismatch,
    ];
    let worker_errors = [
        CryptoWorkerError::QueueFull,
        CryptoWorkerError::CancelledBeforeStart,
        CryptoWorkerError::WorkerPanicked,
        CryptoWorkerError::ShuttingDown,
        CryptoWorkerError::InvalidConfiguration,
        CryptoWorkerError::WorkerSpawnFailed,
    ];
    let mut captured = Vec::new();
    append_error_formats(&mut captured, &auth_errors);
    append_error_formats(&mut captured, &crypto_errors);
    append_error_formats(&mut captured, &worker_errors);

    let cancellation_pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 2, 1)?)?;
    let (started_sender, started_receiver) = sync_channel(1);
    let (release_sender, release_receiver) = sync_channel(1);
    let blocking = cancellation_pool
        .try_submit(CanaryJob::new(CanaryBehavior::Block {
            started: started_sender,
            release: release_receiver,
        }))
        .map_err(|error| error.reason())?;
    started_receiver.recv_timeout(Duration::from_secs(30))?;
    let executed = Arc::new(AtomicBool::new(false));
    let cancelled = cancellation_pool
        .try_submit(CanaryJob::new(CanaryBehavior::MarkExecuted(Arc::clone(
            &executed,
        ))))
        .map_err(|error| error.reason())?;
    cancelled.cancel_before_start();
    release_sender.send(())?;
    assert_eq!(blocking.completion().await?, SECRET_CANARY.len());
    let cancellation_error = cancelled
        .completion()
        .await
        .err()
        .ok_or_else(|| test_error("cancelled canary job unexpectedly executed"))?;
    assert_eq!(cancellation_error, CryptoWorkerError::CancelledBeforeStart);
    assert!(!executed.load(Ordering::Acquire));
    captured.push(format!("{cancellation_error}"));
    captured.push(format!("{cancellation_error:?}"));

    let panic_pool = BoundedCryptoPool::start(CryptoWorkerConfig::new(1, 1, 1)?)?;
    let panicking = panic_pool
        .try_submit(CanaryJob::new(CanaryBehavior::Panic))
        .map_err(|error| error.reason())?;
    let panic_error = panicking
        .completion()
        .await
        .err()
        .ok_or_else(|| test_error("panicking canary job unexpectedly completed"))?;
    assert_eq!(panic_error, CryptoWorkerError::WorkerPanicked);
    captured.push(format!("{panic_error}"));
    captured.push(format!("{panic_error:?}"));

    assert!(captured.iter().all(|text| !text.contains(SECRET_CANARY)));
    Ok(())
}

fn median(mut values: Vec<u128>) -> Result<u128, io::Error> {
    if values.is_empty() {
        return Err(test_error("timing sample set is empty"));
    }
    values.sort_unstable();
    values
        .get(values.len() / 2)
        .copied()
        .ok_or_else(|| test_error("timing median is absent"))
}

fn median_absolute_deviation(values: &[u128], center: u128) -> Result<u128, io::Error> {
    let deviations = values.iter().map(|value| value.abs_diff(center)).collect();
    median(deviations)
}

/// Supplemental smoke signal only: it checks that known and unknown logins
/// both perform the full OPAQUE server-start work within a wide tolerance.
/// Wall-clock samples inside a parallel test process are not constant-time
/// evidence; the source-bound review in the Stage 04 constant-time manifest
/// is the primary evidence and side-channel claims need dedicated tooling.
#[test]
fn shuffled_known_and_unknown_opaque_starts_share_one_timing_class()
-> Result<(), Box<dyn core::error::Error>> {
    let vector = opaque_record()?;
    let network = NetworkId::from_bytes(fixed(vector, "network")?);
    let known_credential = OpaqueCredentialId::from_bytes(fixed(vector, "credential_id")?);
    let unknown_credential = OpaqueCredentialId::from_bytes(fixed(vector, "fake_credential_id")?);
    let setup = fixed(vector, "setup")?;
    let fake_record = fixed(vector, "fake_record")?;
    let profile = OpaqueProfile::from_serialized(network, setup, fake_record)?;
    let known_record = OpaqueRegistrationRecord::from_bytes(fixed(vector, "registration_record")?)?;
    let ke1 = OpaqueKe1::from_bytes(fixed(vector, "ke1")?)?;

    for known in [true, false, false, true] {
        let (credential, record) = if known {
            (&known_credential, Some(&known_record))
        } else {
            (&unknown_credential, None)
        };
        let _warmup = profile.authentication_start(network, credential, record, &ke1)?;
    }

    let mut known_samples = Vec::new();
    let mut unknown_samples = Vec::new();
    for known in TIMING_SCHEDULE {
        let (credential, record) = if known {
            (&known_credential, Some(&known_record))
        } else {
            (&unknown_credential, None)
        };
        let started = Instant::now();
        let _result = profile.authentication_start(network, credential, record, &ke1)?;
        let elapsed = started.elapsed().as_nanos();
        if known {
            known_samples.push(elapsed);
        } else {
            unknown_samples.push(elapsed);
        }
    }
    assert_eq!(known_samples.len(), unknown_samples.len());
    let known_median = median(known_samples.clone())?;
    let unknown_median = median(unknown_samples.clone())?;
    let mut pooled = known_samples;
    pooled.extend(unknown_samples);
    let pooled_median = median(pooled.clone())?;
    let pooled_mad = median_absolute_deviation(&pooled, pooled_median)?;
    let noise_allowance = pooled_mad
        .checked_mul(12)
        .ok_or_else(|| test_error("timing deviation allowance overflow"))?;
    let tolerance = pooled_median.max(noise_allowance);
    assert!(
        known_median.abs_diff(unknown_median) <= tolerance,
        "known/unknown OPAQUE medians left the reviewed timing class"
    );
    Ok(())
}
