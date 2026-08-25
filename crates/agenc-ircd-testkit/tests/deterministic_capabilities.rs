#![forbid(unsafe_code)]

//! Boundary tests for deterministic test-only capabilities.

use agenc_ircd_testkit::{
    CapabilityError, DeterministicClock, FaultStore, FaultStoreError, MAX_FAULT_STORE_RECORDS,
    MAX_SCRIPTED_ENTROPY_BYTES, MAX_TRANSCRIPT_STEP_BYTES, MAX_TRANSCRIPT_STEPS, ReferenceModel,
    ReferenceTransitionError, ScriptedEntropy, StoreOperation, TranscriptActor, TranscriptDriver,
    TranscriptError, TranscriptStep,
};

#[test]
fn clock_overflow_is_atomic() -> Result<(), CapabilityError> {
    let mut clock = DeterministicClock::at(u64::MAX - 1);
    assert_eq!(clock.advance(1)?, u64::MAX);
    assert_eq!(clock.advance(1), Err(CapabilityError::ClockOverflow));
    assert_eq!(clock.now(), u64::MAX);
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
    let mut store = FaultStore::new(1)?;
    store.fail_next(StoreOperation::Write, 1);
    assert_eq!(
        store.insert("key", "value"),
        Err(FaultStoreError::Injected(StoreOperation::Write))
    );
    assert!(store.is_empty());

    assert_eq!(store.insert("key", "value")?, None);
    assert_eq!(
        store.insert("other", "value"),
        Err(FaultStoreError::CapacityExhausted)
    );
    assert_eq!(store.get(&"key")?, Some(&"value"));
    Ok(())
}

#[test]
fn fault_store_validates_capacity_and_each_operation() -> Result<(), FaultStoreError> {
    assert!(matches!(
        FaultStore::<u8, u8>::new(0),
        Err(FaultStoreError::InvalidCapacity)
    ));
    assert!(matches!(
        FaultStore::<u8, u8>::new(MAX_FAULT_STORE_RECORDS + 1),
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

    let mut store = FaultStore::new(2)?;
    assert_eq!(store.insert(1, 10)?, None);
    assert_eq!(store.insert(1, 11)?, Some(10));
    assert_eq!(store.len(), 1);

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
