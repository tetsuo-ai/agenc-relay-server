//! Audit export uses authenticated commands and a committed observed receipt.
#![forbid(unsafe_code)]
#![cfg(test)]

use super::*;
use crate::admin::{
    ADMIN_OUTPUT_CAPACITY, AdminAdmissionSnapshot, AdminOutput, AdminOwner, AdminOwnerClocks,
    AdminOwnerHealth, AdminOwnerRuntime,
};
use crate::budget::{MemoryBudget, MemoryCharge};
use crate::cancel::CancellationToken;
use crate::connection::ConnectionGeneration;
use crate::observe::health::{Liveness, ReadinessGate};
use crate::state_core::{AdminCoreFailure, AdminCoreInbox, admin_core_channel};
use agenc_relay_admin::{
    AdminChallenge, Challenge, MAX_AUDIT_EXPORT_BYTES, PeerIdentity, TransportBinding,
    TransportKind, encode_base64url, render_admin_tag,
};
use agenc_relay_testkit::{DeterministicMonotonicClock, DeterministicWallClock, ScriptedEntropy};
use tokio::sync::mpsc;

fn owner(fixture: &Fixture, core: &StateCoreFixture) -> TestResult<(AdminOwner, AdminCoreInbox)> {
    let (port, inbox) = admin_core_channel();
    let scope = fixture.scope();
    let export_backing = MemoryCharge::allocation(MAX_AUDIT_EXPORT_BYTES)?
        .bytes()
        .checked_mul(2)
        .ok_or("export budget overflow")?;
    Ok((
        AdminOwner::new(
            AdminSessionBinding {
                network_id: scope.network_id(),
                server_id: scope.server_id(),
            },
            fixture.operators()?,
            AdminAdmissionSnapshot::new(vec![1_000], Vec::new(), Vec::new()),
            fixture.authority(core)?,
            port,
            AdminOwnerRuntime {
                health: AdminOwnerHealth {
                    readiness: Arc::new(ReadinessGate::new()),
                    liveness: Arc::new(Liveness::new()),
                },
                config: None,
                reload: None,
                backup: None,
                process: None,
                fatal: None,
                observer: None,
                budget: Arc::new(MemoryBudget::new(export_backing)),
                entropy: Box::new(ScriptedEntropy::new(vec![7; 64])?),
                clocks: AdminOwnerClocks {
                    monotonic: Box::new(DeterministicMonotonicClock::at(0)),
                    wall: Box::new(DeterministicWallClock::at(60)),
                },
            },
        ),
        inbox,
    ))
}

mod maintenance_export;
