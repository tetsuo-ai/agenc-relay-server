//! RUN-04: the default idle-client admission model (spec 19.2, 28.7).
//!
//! The composed client path is assembled here from the same functions the
//! listener and connection supervisor use, so the model measures what a real
//! connection charges rather than a restated constant.

#![forbid(unsafe_code)]

use super::{
    BackingReservationPort, CLIENT_CONNECTION_BASE_BYTES, MemoryBudget, MemoryBudgetPort as _,
    TLS_SETUP_INCREMENT_BYTES, startup_arithmetic,
};
use crate::RuntimeError;
use crate::admission::overload::{
    CONNECTION_STOP_PERCENT, EVICTION_PERCENT, GUEST_STOP_PERCENT, OverloadClass, OverloadState,
};
use crate::connection::sink::ConnectionGeneration;
use crate::connection::{ConnectionLimits, WriterQueue};
use crate::listener::connection_charges;
use crate::purpose::ListenerPurpose;
use crate::state_core::client_input::ClientInputs;
use crate::state_core::session::MAX_TRACKED_CONNECTIONS;
use crate::sync::Arc;

/// Appendix C.2 default `server.memory_budget_bytes`.
const DEFAULT_BUDGET_BYTES: u64 = 4_294_967_296;
/// Appendix C.2 default `server.crypto_worker_threads`.
const DEFAULT_CRYPTO_WORKERS: u64 = 4;
/// Appendix C.6 default `parsed_arena_bytes`.
const DEFAULT_PARSED_ARENA_BYTES: u64 = 32_768;
/// Appendix C.6 default `client_connections`.
const DEFAULT_CLIENT_CONNECTIONS: u64 = 50_000;
/// The eager output backing every admitted client charged before RUN-04:
/// `allocation_charge(4,104 * 40)`.
const EAGER_QUEUE_BACKING_BYTES: u64 = 167_936;
/// The eager input backing every opened client port charged before RUN-04:
/// `allocation_charge(128 * 56 + 4,096)`.
const EAGER_INPUT_BACKING_BYTES: u64 = 16_384;

fn default_pool() -> Result<u64, RuntimeError> {
    Ok(startup_arithmetic(
        DEFAULT_BUDGET_BYTES,
        DEFAULT_CRYPTO_WORKERS,
        &[ListenerPurpose::ClientTls, ListenerPurpose::AdminLocal],
        DEFAULT_PARSED_ARENA_BYTES,
    )?
    .protocol_pool_bytes())
}

/// Composes one admitted TLS client the way the listener, supervisor, and
/// StateCore do, and returns what it holds once its handshake allocations
/// are destroyed.
fn composed_idle_charge(
    budget: &Arc<MemoryBudget>,
    inputs: &ClientInputs,
) -> Result<u64, RuntimeError> {
    let charges = connection_charges(ListenerPurpose::ClientTls, true)?;
    let mut permits = budget.try_acquire_batch(charges)?;
    // The supervisor splits the base charge for StateCore's connection state.
    let state_permit = permits
        .split_exact(CLIENT_CONNECTION_BASE_BYTES)
        .ok_or(RuntimeError::InvalidValue)?;
    // The TLS setup increment returns when the handshake allocations are gone.
    let setup = permits
        .split_exact(TLS_SETUP_INCREMENT_BYTES)
        .ok_or(RuntimeError::InvalidValue)?;
    drop(setup);
    let generation = ConnectionGeneration::new(1);
    let queue = WriterQueue::new(generation, ConnectionLimits::DEFAULT.queue)?;
    let owner = inputs.open(generation)?;
    let charged = budget.charged();
    drop((owner, queue, state_permit, permits));
    Ok(charged)
}

#[test]
fn an_idle_client_connection_charges_only_its_base() -> Result<(), RuntimeError> {
    let budget = Arc::new(MemoryBudget::new(default_pool()?));
    let inputs_owner = ClientInputs::new(
        MAX_TRACKED_CONNECTIONS,
        BackingReservationPort::new(Arc::clone(&budget)),
    )?;
    let fixed = budget.charged();
    let composed = composed_idle_charge(&budget, &inputs_owner)?;
    assert_eq!(
        composed - fixed,
        CLIENT_CONNECTION_BASE_BYTES,
        "queue and input backing are acquired on demand, never at admission"
    );
    assert_eq!(budget.charged(), fixed, "the closed connection returned it");
    drop(inputs_owner);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn the_default_pool_admits_fifty_thousand_idle_clients() -> Result<(), RuntimeError> {
    let pool = default_pool()?;
    assert_eq!(pool, 3_338_666_016);
    let budget = Arc::new(MemoryBudget::new(pool));
    // The one count-scaled fixed owner the client path installs at startup.
    let inputs = ClientInputs::new(
        MAX_TRACKED_CONNECTIONS,
        BackingReservationPort::new(Arc::clone(&budget)),
    )?;
    let fixed = budget.charged();
    let population = DEFAULT_CLIENT_CONNECTIONS
        .checked_mul(CLIENT_CONNECTION_BASE_BYTES)
        .and_then(|clients| clients.checked_add(fixed))
        .ok_or(RuntimeError::Overflow)?;
    assert!(
        population <= pool,
        "50,000 idle clients and the fixed owners need {population} of {pool} bytes"
    );
    // The eager backing this issue removed did not fit, with or without the
    // fixed owners: it is the concrete impossibility RUN-04 names.
    let eager = DEFAULT_CLIENT_CONNECTIONS
        .checked_mul(
            CLIENT_CONNECTION_BASE_BYTES + EAGER_QUEUE_BACKING_BYTES + EAGER_INPUT_BACKING_BYTES,
        )
        .ok_or(RuntimeError::Overflow)?;
    assert!(eager > pool * 3, "the eager model needed {eager} bytes");
    drop(inputs);
    Ok(())
}

/// The 4-GiB default admits every idle client's memory charge, but the
/// Section 19.3 overload percentages are taken against the same live pool
/// `P`, so a full default population sits above all three thresholds. The
/// numbers below are the exact conflict recorded for a normative decision;
/// they must be updated with whatever resolves it.
#[test]
fn a_full_default_population_crosses_every_overload_threshold() -> Result<(), RuntimeError> {
    let pool = default_pool()?;
    let population = DEFAULT_CLIENT_CONNECTIONS * CLIENT_CONNECTION_BASE_BYTES;
    assert_eq!(population, 3_276_800_000);
    assert_eq!(population * 100 / pool, 98);
    let mut overload = OverloadState::new();
    assert_eq!(overload.classify(population, pool), OverloadClass::Evict);
    let admitted = |percent: u64| percent * pool / 100 / CLIENT_CONNECTION_BASE_BYTES;
    assert_eq!(admitted(GUEST_STOP_PERCENT), 40_755);
    assert_eq!(admitted(CONNECTION_STOP_PERCENT), 45_849);
    assert_eq!(admitted(EVICTION_PERCENT), 48_396);
    Ok(())
}
