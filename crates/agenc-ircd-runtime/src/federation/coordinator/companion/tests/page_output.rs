//! The actual SendPage adapter retains backing while the link writer is stalled.
#![forbid(unsafe_code)]

use super::*;
use crate::bridge::crypto::ChannelKeyVerifierRecord;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::sync::SnapshotPageOutput;
use crate::federation::coordinator::{CoordinatorConfig, LiveLink};
use crate::federation::link::{LinkHandle, LinkQueue, link_queue};
use crate::test_support::{StateCoreFixture, TestResult};
use std::sync::Arc;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const LINK: LinkId = LinkId::new(11);

fn sender(
    fixture: &StateCoreFixture,
) -> TestResult<(FederationCoordinator, LinkHandle, LinkQueue)> {
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: fixture.identity.network_id,
            server_id: fixture.identity.server_id,
            server_name: "coordinator.example".into(),
            recovery_epoch: fixture.identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        vec![crate::federation::PeerIdentity::new(
            PEER,
            "edge.example",
            agenc_ircd_types::FederationRole::Edge,
            fixture.identity.recovery_epoch,
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([9; 32]).public_key(),
            [8; 32],
        )],
        Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    let (handle, queue) = link_queue(1 << 20);
    let state = coordinator.peers.get_mut(&PEER).ok_or("configured peer")?;
    state.live = Some(LiveLink {
        link: LINK,
        handle: handle.clone(),
        incarnation: ServerIncarnation::from_bytes([51; 16]),
    });
    Ok((coordinator, handle, queue))
}

fn output(budget: &Arc<MemoryBudget>) -> TestResult<(SnapshotPageOutput, u64)> {
    let lines = (0..3)
        .map(|sequence| {
            FederationLineText::from_rendered(format!(
                ":coordinator.example FPONG :page-{sequence}\r\n"
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = lines
        .iter()
        .try_fold(0_u64, |sum, line| {
            sum.checked_add(u64::try_from(line.len()).ok()?)
        })
        .ok_or("encoded bytes overflow")?;
    let memory = BackingReservationPort::new(Arc::clone(budget)).reserve(16_384)?;
    Ok((SnapshotPageOutput::for_fixture(lines, memory), bytes))
}

#[test]
fn a_stalled_page_writer_keeps_the_actual_output_charge_until_its_queue_drops() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![44; 65_536])?;
    let (mut coordinator, handle, queue) = sender(&fixture)?;
    let budget = Arc::new(MemoryBudget::new(65_536));
    let (output, bytes) = output(&budget)?;
    let charged = budget.charged();
    send_page(&mut coordinator, fixture.context_mut()?, LINK, PEER, output);
    assert_eq!(handle.queued_bytes(), bytes);
    assert_eq!(
        budget.charged(),
        charged,
        "accepted page strings outlived their process memory charge"
    );
    drop(queue);
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn a_replaced_page_link_never_receives_output_or_retains_its_backing() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![44; 65_536])?;
    let (mut coordinator, handle, _queue) = sender(&fixture)?;
    let budget = Arc::new(MemoryBudget::new(65_536));
    let (output, _) = output(&budget)?;
    send_page(
        &mut coordinator,
        fixture.context_mut()?,
        LinkId::new(12),
        PEER,
        output,
    );
    assert_eq!(handle.queued_bytes(), 0);
    assert_eq!(budget.charged(), 0);
    Ok(())
}
