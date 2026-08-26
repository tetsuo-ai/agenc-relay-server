#![forbid(unsafe_code)]

//! Boundary tests for deterministic test-only capabilities.

use std::error::Error;

use agenc_ircd_testkit::{
    CapabilityError, DeterministicMonotonicClock, DeterministicWallClock, FaultStore,
    FaultStoreError, MAX_FAULT_STORE_BYTES, MAX_FAULT_STORE_RECORDS, MAX_SCRIPTED_ENTROPY_BYTES,
    MAX_TRANSCRIPT_STEP_BYTES, MAX_TRANSCRIPT_STEPS, ReferenceModel, ReferenceTransitionError,
    ScriptedEntropy, StoreOperation, TranscriptActor, TranscriptDriver, TranscriptError,
    TranscriptStep,
};
use agenc_ircd_types::{
    ClockError, EntropyError, EntropySource, MonotonicClock, NetworkId, WallClock,
};

#[test]
fn clock_overflow_is_atomic() -> Result<(), CapabilityError> {
    let mut clock = DeterministicMonotonicClock::at(u64::MAX - 1);
    assert_eq!(clock.advance(1)?, u64::MAX);
    assert_eq!(clock.advance(1), Err(CapabilityError::ClockOverflow));
    assert_eq!(clock.now(), u64::MAX);
    Ok(())
}

#[test]
fn wall_clock_is_distinct_and_overflow_is_atomic() -> Result<(), CapabilityError> {
    let mut clock = DeterministicWallClock::at(u64::MAX - 1);
    assert_eq!(clock.advance(1)?, u64::MAX);
    assert_eq!(clock.advance(1), Err(CapabilityError::ClockOverflow));
    assert_eq!(clock.now(), u64::MAX);
    Ok(())
}

#[test]
fn deterministic_capabilities_implement_production_ports() -> Result<(), Box<dyn Error>> {
    let monotonic = DeterministicMonotonicClock::at(17);
    assert_eq!(MonotonicClock::now(&monotonic).get(), 17);

    let wall = DeterministicWallClock::at(23);
    assert_eq!(WallClock::utc_now(&wall)?.get(), 23);
    assert_eq!(
        WallClock::utc_now(&DeterministicWallClock::unavailable_at(23)),
        Err(ClockError::Unavailable)
    );

    let mut entropy = ScriptedEntropy::new(vec![7; 32])?;
    assert_eq!(NetworkId::generate(&mut entropy)?.as_bytes(), &[7; 32]);
    assert_eq!(
        EntropySource::fill_exact(&mut entropy, &mut [0; 1]),
        Err(EntropyError::Unavailable)
    );
    Ok(())
}

#[test]
fn entropy_exhaustion_consumes_nothing() -> Result<(), CapabilityError> {
    let mut entropy = ScriptedEntropy::new(vec![1, 2, 3])?;
    let mut oversized = [0_u8; 4];
    assert_eq!(
        entropy.fill_exact(&mut oversized),
        Err(CapabilityError::EntropyExhausted)
    );
    assert_eq!(entropy.remaining(), 3);

    let mut exact = [0_u8; 3];
    entropy.fill_exact(&mut exact)?;
    assert_eq!(exact, [1, 2, 3]);
    assert_eq!(entropy.remaining(), 0);
    Ok(())
}

#[test]
fn capability_errors_are_bounded_and_descriptive() {
    assert_eq!(
        CapabilityError::ClockOverflow.to_string(),
        "deterministic clock overflow"
    );
    assert_eq!(
        CapabilityError::EntropyExhausted.to_string(),
        "scripted entropy exhausted"
    );
    assert_eq!(
        CapabilityError::EntropyScriptTooLarge.to_string(),
        "scripted entropy exceeds its byte ceiling"
    );
    assert_eq!(
        ScriptedEntropy::new(vec![0_u8; MAX_SCRIPTED_ENTROPY_BYTES + 1]),
        Err(CapabilityError::EntropyScriptTooLarge)
    );
    let oversized_capacity = Vec::with_capacity(MAX_SCRIPTED_ENTROPY_BYTES + 1);
    assert_eq!(
        ScriptedEntropy::new(oversized_capacity),
        Err(CapabilityError::EntropyScriptTooLarge)
    );
}

#[test]
fn rejected_reference_transition_preserves_state() {
    let mut model = ReferenceModel::new(5_u64);
    let rejected = model.apply(3_u64, |_state, _input| Err::<(u64, u64), _>("rejected"));
    assert_eq!(
        rejected,
        Err(ReferenceTransitionError::Rejected("rejected"))
    );
    assert_eq!(*model.state(), 5);
    assert_eq!(model.revision(), 0);

    let accepted = model.apply(3_u64, |state, input| {
        Ok::<_, &str>((state + input, state * input))
    });
    assert_eq!(accepted, Ok(15));
    assert_eq!(*model.state(), 8);
    assert_eq!(model.revision(), 1);
}

#[test]
fn exhausted_reference_revision_rejects_before_transition() {
    let mut model = ReferenceModel::at_revision(5_u64, u64::MAX);
    let result = model.apply(3_u64, |state, input| {
        Ok::<_, ()>((state + input, state * input))
    });
    assert_eq!(result, Err(ReferenceTransitionError::RevisionExhausted));
    assert_eq!(*model.state(), 5);
    assert_eq!(model.revision(), u64::MAX);
}

#[test]
fn fault_store_failures_are_counted_and_side_effect_free() -> Result<(), FaultStoreError> {
    let mut store = FaultStore::new(1, 16)?;
    store.fail_next(StoreOperation::Write, 1);
    assert_eq!(
        store.insert("key", "value", 5),
        Err(FaultStoreError::Injected(StoreOperation::Write))
    );
    assert!(store.is_empty());

    assert_eq!(store.insert("key", "value", 5)?, None);
    assert_eq!(
        store.insert("other", "value", 5),
        Err(FaultStoreError::CapacityExhausted)
    );
    assert_eq!(store.get(&"key")?, Some(&"value"));
    Ok(())
}

#[test]
fn fault_store_validates_capacity_and_each_operation() -> Result<(), FaultStoreError> {
    assert!(matches!(
        FaultStore::<u8, u8>::new(0, 1),
        Err(FaultStoreError::InvalidCapacity)
    ));
    assert!(matches!(
        FaultStore::<u8, u8>::new(MAX_FAULT_STORE_RECORDS + 1, 1),
        Err(FaultStoreError::InvalidCapacity)
    ));
    assert!(matches!(
        FaultStore::<u8, u8>::new(1, MAX_FAULT_STORE_BYTES + 1),
        Err(FaultStoreError::InvalidCapacity)
    ));
    assert_eq!(
        FaultStoreError::InvalidCapacity.to_string(),
        "invalid fault-store capacity"
    );
    assert_eq!(
        FaultStoreError::Injected(StoreOperation::Read).to_string(),
        "injected Read fault"
    );
    assert_eq!(
        FaultStoreError::CapacityExhausted.to_string(),
        "fault-store capacity exhausted"
    );
    assert_eq!(
        FaultStoreError::ByteCapacityExhausted.to_string(),
        "fault-store byte capacity exhausted"
    );

    let mut store = FaultStore::new(2, 3)?;
    assert_eq!(store.insert(1, 10, 2)?, None);
    assert_eq!(store.insert(1, 11, 3)?, Some(10));
    assert_eq!(store.len(), 1);
    assert_eq!(store.stored_bytes(), 3);
    assert_eq!(
        store.insert(2, 20, 1),
        Err(FaultStoreError::ByteCapacityExhausted)
    );

    store.fail_next(StoreOperation::Read, 2);
    assert_eq!(
        store.get(&1),
        Err(FaultStoreError::Injected(StoreOperation::Read))
    );
    assert_eq!(
        store.get(&1),
        Err(FaultStoreError::Injected(StoreOperation::Read))
    );
    assert_eq!(store.get(&1)?, Some(&11));

    store.fail_next(StoreOperation::Delete, 1);
    store.fail_next(StoreOperation::Delete, 0);
    assert_eq!(store.remove(&1)?, Some(11));
    assert!(store.is_empty());
    assert_eq!(store.stored_bytes(), 0);
    Ok(())
}

#[test]
fn transcript_mismatch_does_not_consume_expectation() -> Result<(), TranscriptError> {
    let mut driver = TranscriptDriver::new();
    driver.push_expected(TranscriptStep::new(
        TranscriptActor::Client,
        b"CAP LS 302\r\n".to_vec(),
    )?)?;

    assert_eq!(
        driver.observe(TranscriptActor::Server, b"CAP LS 302\r\n"),
        Err(TranscriptError::Mismatch { index: 0 })
    );
    assert_eq!(
        driver.observe(TranscriptActor::Client, b"CAP LS\r\n"),
        Err(TranscriptError::Mismatch { index: 0 })
    );
    driver.observe(TranscriptActor::Client, b"CAP LS 302\r\n")?;
    driver.finish()
}

#[test]
fn transcript_limits_and_terminal_states_are_explicit() -> Result<(), TranscriptError> {
    assert_eq!(
        TranscriptStep::new(
            TranscriptActor::Administrator,
            vec![0_u8; MAX_TRANSCRIPT_STEP_BYTES + 1]
        ),
        Err(TranscriptError::StepTooLarge)
    );
    let oversized_capacity = Vec::with_capacity(MAX_TRANSCRIPT_STEP_BYTES + 1);
    assert_eq!(
        TranscriptStep::new(TranscriptActor::Administrator, oversized_capacity),
        Err(TranscriptError::StepCapacityTooLarge)
    );

    let mut empty = TranscriptDriver::new();
    assert_eq!(
        empty.observe(TranscriptActor::Coordinator, b"unexpected"),
        Err(TranscriptError::UnexpectedStep)
    );
    assert_eq!(
        empty.observe(
            TranscriptActor::Edge,
            &vec![0_u8; MAX_TRANSCRIPT_STEP_BYTES + 1]
        ),
        Err(TranscriptError::StepTooLarge)
    );

    let mut incomplete = TranscriptDriver::new();
    incomplete.push_expected(TranscriptStep::new(TranscriptActor::Server, Vec::new())?)?;
    assert_eq!(
        incomplete.finish(),
        Err(TranscriptError::Incomplete { remaining: 1 })
    );

    let mut full = TranscriptDriver::new();
    for _ in 0..MAX_TRANSCRIPT_STEPS {
        full.push_expected(TranscriptStep::new(TranscriptActor::Server, Vec::new())?)?;
    }
    assert_eq!(
        full.push_expected(TranscriptStep::new(TranscriptActor::Server, Vec::new())?),
        Err(TranscriptError::TooManySteps)
    );

    let mut drained = TranscriptDriver::new();
    for _ in 0..MAX_TRANSCRIPT_STEPS {
        drained.push_expected(TranscriptStep::new(TranscriptActor::Server, Vec::new())?)?;
        drained.observe(TranscriptActor::Server, &[])?;
    }
    assert_eq!(
        drained.push_expected(TranscriptStep::new(TranscriptActor::Server, Vec::new())?),
        Err(TranscriptError::TooManySteps)
    );
    assert_eq!(
        drained.observe(TranscriptActor::Server, &[]),
        Err(TranscriptError::TooManySteps)
    );
    Ok(())
}

#[test]
fn transcript_errors_are_bounded_and_descriptive() {
    assert_eq!(
        TranscriptError::TooManySteps.to_string(),
        "transcript step ceiling reached"
    );
    assert_eq!(
        TranscriptError::StepTooLarge.to_string(),
        "transcript step exceeds its byte ceiling"
    );
    assert_eq!(
        TranscriptError::StepCapacityTooLarge.to_string(),
        "transcript step backing capacity exceeds its byte ceiling"
    );
    assert_eq!(
        TranscriptError::AllocationFailed.to_string(),
        "transcript queue allocation failed"
    );
    assert_eq!(
        TranscriptError::UnexpectedStep.to_string(),
        "unexpected transcript step"
    );
    assert_eq!(
        TranscriptError::Mismatch { index: 7 }.to_string(),
        "transcript mismatch at step 7"
    );
    assert_eq!(
        TranscriptError::Incomplete { remaining: 2 }.to_string(),
        "transcript has 2 unconsumed steps"
    );
}
