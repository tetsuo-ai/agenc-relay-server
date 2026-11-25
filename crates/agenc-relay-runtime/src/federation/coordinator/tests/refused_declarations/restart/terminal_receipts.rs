//! Projected origin closures require the exact request position and durable completion.
#![forbid(unsafe_code)]

use super::*;
use crate::federation::coordinator::origin::{self as owner, TerminalOrigin, TerminalReceipt};
use crate::state_core::fanout::FanoutRequest;
use agenc_relay_domain::federation::OperationKey;

async fn declared() -> TestResult<(Box<Restartable>, OriginKey)> {
    let mut relay = Box::new(Restartable::new()?);
    let origin = Origin::new(94);
    relay.link(1)?;
    relay.settle().await?;
    relay.declare(&origin, false, None)?;
    relay.settle().await?;
    assert!(acknowledges(
        &relay.frames().await?,
        &origin,
        origin.generation
    ));
    let key = relay.key(&origin);
    Ok((relay, key))
}

fn stage_terminal(
    relay: &mut Restartable,
    proposed: TerminalOrigin,
    revision_offset: u64,
) -> TestResult<TerminalReceipt> {
    let context = relay.core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let write = proposed
        .row(&relay.coordinator, revision)
        .map_err(|_| "encode terminal origin")?;
    let receipt = proposed.receipt(context, revision + revision_offset);
    context
        .stage_durable_with_account_service(
            plan,
            FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            vec![write],
        )
        .map_err(|_| "stage exact terminal origin")?;
    Ok(receipt)
}

#[tokio::test]
async fn a_quota_closure_shortens_a_committed_deletion_only_at_its_exact_pending_sequence()
-> TestResult {
    let (mut relay, key) = declared().await?;
    let original = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("no declared origin")?;
    let request = OperationKey {
        origin: key,
        generation: original.generation,
        sequence: original.next_sequence,
    };
    let future = OperationKey {
        sequence: request.sequence + 1,
        ..request
    };
    let stale = OperationKey {
        generation: request.generation + 1,
        ..request
    };
    let missing = OperationKey {
        origin: relay.key(&Origin::new(97)),
        ..request
    };
    for invalid in [future, stale, missing] {
        assert!(TerminalOrigin::at_capacity(&relay.coordinator, &invalid).is_err());
    }
    let declared_cut = request.sequence + 3;
    owner::delete(
        &mut relay.coordinator,
        relay.core.context_mut()?,
        relay.edge.link,
        relay.edge.server_id,
        key,
        request.generation,
        declared_cut,
    )
    .map_err(|_| "issue ordinary FORIGIN DEL")?;
    relay.settle().await?;
    let deleted = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("missing current deletion")?;
    assert_eq!(deleted.deleted_after, Some(declared_cut));
    let terminal = TerminalOrigin::at_capacity(&relay.coordinator, &request)
        .map_err(|_| "admit the preceding queued request")?;
    let receipt = stage_terminal(&mut relay, terminal, 0)?;
    relay.core.commit_staged_batch().await?;
    assert!(receipt.published(&mut relay.coordinator, relay.core.context_mut()?));
    let published = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("missing final origin")?;
    assert_eq!(published.deleted_after, Some(request.sequence));
    assert_eq!(
        relay.coordinator.refused_declarations.get(&key),
        Some(&request.generation)
    );
    assert!(TerminalOrigin::at_capacity(&relay.coordinator, &request).is_err());
    relay.restart().await?;
    let reloaded = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("missing stored terminal origin")?;
    assert_eq!(reloaded.status, OriginStatus::Deleted);
    assert_eq!(reloaded.deleted_after, Some(request.sequence));
    relay.coordinator.origins.fence(&key)?;
    assert!(TerminalOrigin::at_capacity(&relay.coordinator, &request).is_err());
    Ok(())
}

#[derive(Clone, Copy)]
enum ReceiptFault {
    Early,
    OtherStorageHead,
    OtherRevision,
    ChangedDeclaration,
    AlreadyFenced,
}

async fn verify_receipt(fault: ReceiptFault) -> TestResult {
    let (mut relay, key) = declared().await?;
    let original = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("declared origin")?;
    let terminal = TerminalOrigin::at_capacity(
        &relay.coordinator,
        &OperationKey {
            origin: key,
            generation: original.generation,
            sequence: original.next_sequence,
        },
    )
    .map_err(|_| "expected valid deletion projection")?;
    let revision_offset = u64::from(matches!(fault, ReceiptFault::OtherRevision));
    let mut receipt = stage_terminal(&mut relay, terminal, revision_offset)?;
    if !matches!(fault, ReceiptFault::Early) {
        relay.core.commit_staged_batch().await?;
    }
    match fault {
        ReceiptFault::OtherStorageHead => {
            receipt.staged_after = relay.core.context_mut()?.head().storage_commit_sequence;
        }
        ReceiptFault::ChangedDeclaration => relay.coordinator.origins.restore_origin(
            key,
            agenc_relay_domain::federation::OriginEntry {
                generation: original.generation + 1,
                ..original
            },
        ),
        ReceiptFault::AlreadyFenced => relay.coordinator.origins.fence(&key)?,
        ReceiptFault::Early | ReceiptFault::OtherRevision => {}
    }
    let violations = relay.coordinator.counters().violations;
    let accepted = receipt.published(&mut relay.coordinator, relay.core.context_mut()?);
    let current = relay
        .coordinator
        .origins
        .origin(&key)
        .ok_or("missing origin")?;
    if matches!(fault, ReceiptFault::AlreadyFenced) {
        assert!(accepted);
        assert_eq!(current.status, OriginStatus::Fenced);
    } else {
        assert!(!accepted);
        assert_eq!(relay.coordinator.counters().violations, violations + 1);
        assert!(
            !relay
                .coordinator
                .link_is_live(relay.edge.link, relay.edge.server_id)
        );
        assert!(!relay.coordinator.refused_declarations.contains_key(&key));
        assert_eq!(current.status, OriginStatus::Live);
    }
    Ok(())
}

#[tokio::test]
async fn terminal_publication_checks_the_exact_storage_head_and_origin_and_preserves_a_permanent_fence()
-> TestResult {
    for fault in [
        ReceiptFault::Early,
        ReceiptFault::OtherStorageHead,
        ReceiptFault::OtherRevision,
        ReceiptFault::ChangedDeclaration,
        ReceiptFault::AlreadyFenced,
    ] {
        verify_receipt(fault).await?;
    }
    Ok(())
}
