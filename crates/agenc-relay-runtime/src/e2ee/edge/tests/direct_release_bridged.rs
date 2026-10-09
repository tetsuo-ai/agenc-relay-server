#![forbid(unsafe_code)]

//! The real coordinator's lines reach the real edge (companion 12.5,
//! ENC-23): a direct route leaves the edge's projection when hosting ends,
//! a reinstalled edge is sent no direct route it does not host, and an
//! honest cut passes the edge's entitlement check even when a base
//! resynchronization closes the counted session in the middle of it.

use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::tests::direct_release::{
    Bridged, DIRECT, hosted_cut_over_the_bridge, hosting_ends_over_the_bridge,
    reinstalled_cut_over_the_bridge,
};
use crate::e2ee::edge::{LocalOrigin, Phase};
use crate::federation::link::{ParsedLine, parse_line};
use crate::sync::Arc;

fn frames(bridged: &Bridged) -> TestResult<Vec<CompanionFrame>> {
    bridged
        .lines
        .iter()
        .map(|text| {
            let parsed = parse_line(text.trim_end_matches("\r\n"), "coordinator.example")
                .map_err(|error| format!("{error:?}"))?;
            match parsed {
                ParsedLine::Companion(frame) => Ok(frame),
                ParsedLine::Base(_) => Err("expected a companion frame".into()),
            }
        })
        .collect()
}

/// A local connection authenticated as `held` with an attached device.
fn attached(held: [u8; 24]) -> LocalOrigin {
    LocalOrigin {
        origin_id: [21; 16],
        declared: Some(1),
        acked: Some(1),
        predates_device: None,
        next_sequence: 0,
        sequenced: Some(1),
        state_id: [0; 32],
        declaration: None,
        user_id: None,
        account: Some(held),
        device: Some(([9; 16], 1)),
        device_principal: Some((None, Some(held))),
    }
}

/// Commits every batch the edge staged and releases its receipts.
async fn settle(fixture: &mut WitnessFixture) -> TestResult {
    for _ in 0..8 {
        if fixture.core.context_mut()?.pending_len() == 0 {
            break;
        }
        fixture.core.commit_staged_batch().await?;
        let _outputs = fixture
            .companion
            .batch_applied(fixture.core.context_mut()?, &mut fixture.base);
    }
    Ok(())
}

/// An edge whose link just came up and awaits its cut.
async fn resuming() -> TestResult<WitnessFixture> {
    let mut fixture = WitnessFixture::new().await?;
    fixture.companion = edge();
    fixture
        .companion
        .install_snapshot_backing(BackingReservationPort::new(Arc::new(MemoryBudget::new(
            1 << 20,
        ))));
    assert!(
        fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    assert_eq!(fixture.companion.phase, Phase::Resuming);
    Ok(fixture)
}

#[tokio::test]
async fn hosting_ends_and_the_route_leaves_the_edge_projection() -> TestResult {
    let bridged = hosting_ends_over_the_bridge()?;
    let mut fixture = WitnessFixture::new().await?;
    // The coordinator's stream for this edge starts at its first position.
    fixture.companion.delivery = crate::e2ee::edge::sync::DeliveryState::default();
    fixture
        .companion
        .route_changed(&bridged.route)
        .map_err(|refusal| refusal.code.to_string())?;
    assert!(fixture.companion.conversations.contains_key(&DIRECT));
    // The state core holds link input while a batch is in flight, so the
    // router sees one frame at a time with its batch settled in between.
    for frame in frames(&bridged)? {
        assert!(
            fixture
                .companion
                .handle_frames(fixture.core.context_mut()?, &mut fixture.base, vec![frame])
                .is_empty()
        );
        settle(&mut fixture).await?;
    }
    settle(&mut fixture).await?;
    assert_eq!(fixture.companion.phase, Phase::Active, "the link stays up");
    assert!(!fixture.companion.conversations.contains_key(&DIRECT));
    assert!(!fixture.companion.route_objects.contains_key(&DIRECT));
    assert!(
        fixture
            .companion
            .routes
            .routes()
            .all(|route| route.conversation_id.0 != DIRECT)
    );
    // Both copies of the plan were applied and acknowledged in order.
    assert_eq!(fixture.companion.delivery.next_sequence(), 2);
    Ok(())
}

#[tokio::test]
async fn a_reinstalled_edge_receives_no_direct_route_it_does_not_host() -> TestResult {
    let bridged = reinstalled_cut_over_the_bridge()?;
    assert!(
        bridged
            .lines
            .iter()
            .all(|line| !line.contains(" ESTATE ENTRY ")),
        "the cut names no direct route"
    );
    let mut fixture = Box::pin(resuming()).await?;
    assert!(
        fixture
            .companion
            .handle_frames(
                fixture.core.context_mut()?,
                &mut fixture.base,
                frames(&bridged)?
            )
            .is_empty()
    );
    // The hosting-free edge accepts the cut and records READY.
    assert_eq!(fixture.companion.phase, Phase::Transferring);
    assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_honest_cut_is_accepted_across_a_resync_that_closes_the_counted_session() -> TestResult {
    let bridged = hosted_cut_over_the_bridge()?;
    let mut all = frames(&bridged)?;
    assert!(
        all.iter()
            .any(|frame| matches!(frame, CompanionFrame::StateEntry { .. })),
        "the honest cut names the hosted direct route"
    );
    let rest = all.split_off(1);
    let mut fixture = Box::pin(resuming()).await?;
    let generation = ConnectionGeneration::new(1);
    fixture
        .companion
        .origins
        .insert(generation, attached(bridged.hosted));
    // BEGIN opens the transfer while the session is counted.
    assert!(
        fixture
            .companion
            .handle_frames(fixture.core.context_mut()?, &mut fixture.base, all)
            .is_empty()
    );
    // The paired base resynchronization closes it before the entry arrives.
    fixture.companion.connection_closed(generation);
    assert!(
        fixture
            .companion
            .handle_frames(fixture.core.context_mut()?, &mut fixture.base, rest)
            .is_empty()
    );
    assert_eq!(fixture.companion.phase, Phase::Transferring);
    assert_ne!(fixture.core.context_mut()?.pending_len(), 0);
    let snapshot = fixture
        .companion
        .snapshot
        .as_ref()
        .ok_or("the generation")?;
    assert!(snapshot.pending.route_objects.contains_key(&DIRECT));
    // The same cut at an edge that never hosted the pair is refused.
    let mut stranger = Box::pin(resuming()).await?;
    assert!(
        stranger
            .companion
            .handle_frames(
                stranger.core.context_mut()?,
                &mut stranger.base,
                frames(&bridged)?
            )
            .is_empty()
    );
    assert_eq!(stranger.companion.phase, Phase::Down);
    Ok(())
}
