//! The closed cleanup admission and staged account authority at shutdown.
#![forbid(unsafe_code)]

use super::*;
use crate::account_service::AccountTransactionCleanup;
use crate::state_core::inbox::{SignalEvent, StateCoreMessage};
use crate::state_core::{StageAccepted, StageRefused};
use crate::test_support::FrameSink;

fn quiescing_fixture() -> crate::test_support::TestResult<CoordinatorFixture> {
    let mut fixture = CoordinatorFixture::new(vec![13; 4_096])?;
    let _exit = fixture
        .core
        .state_mut()?
        .step_message(StateCoreMessage::Signal(SignalEvent::Terminate));
    assert!(fixture.core.context_mut()?.is_quiescing());
    Ok(fixture)
}

#[test]
fn cleanup_admission_cannot_write_credentials_or_unrelated_state() -> crate::test_support::TestResult
{
    let mut fixture = quiescing_fixture()?;
    let generation = ConnectionGeneration::new(1);
    let sink = FrameSink::new(generation, true);
    let context = fixture.core.context_mut()?;
    let now = context.now();
    context.sessions_mut().open(
        generation,
        crate::purpose::ListenerPurpose::ClientOnion,
        crate::state_core::inbox::SourceAddressKey::onion_listener(),
        Arc::clone(&sink) as Arc<dyn crate::connection::ClientSink>,
        now,
    )?;
    let before = context.head();
    for table in [
        TableId::Account,
        TableId::OpaqueRecord,
        TableId::LoginIndex,
        TableId::AuthTransaction,
    ] {
        let cleanup = AccountTransactionCleanup {
            writes: vec![AccountServiceDurableWrite::Put {
                table,
                key: StoredKey::new(vec![1; 16])?,
                plaintext: zeroize::Zeroizing::new(Vec::new()),
            }],
        };
        assert!(matches!(
            context.stage_account_transaction_cleanup(cleanup),
            Err(StageRefused::Domain(
                agenc_ircd_domain::DomainError::InvariantViolation
            ))
        ));
    }
    for table in [
        TableId::Account,
        TableId::OpaqueRecord,
        TableId::Session,
        TableId::FederationPeer,
    ] {
        let key = if matches!(table, TableId::Account | TableId::OpaqueRecord) {
            crate::state_core::durable::KeyDeriver::account_key(account(1))?
        } else {
            StoredKey::new(vec![1; 16])?
        };
        let cleanup = AccountTransactionCleanup {
            writes: vec![AccountServiceDurableWrite::Delete { table, key }],
        };
        assert!(context.stage_account_transaction_cleanup(cleanup).is_err());
    }
    assert_eq!(context.pending_len(), 0);
    assert_eq!(context.head().state_generation, before.state_generation);
    assert_eq!(
        context.head().account_service_response_count,
        before.account_service_response_count
    );
    assert!(sink.lines().is_empty());
    Ok(())
}

#[test]
fn cleanup_admission_keeps_its_count_and_pending_batch_limits() -> crate::test_support::TestResult {
    let mut fixture = quiescing_fixture()?;
    let context = fixture.core.context_mut()?;
    assert!(
        context
            .stage_account_transaction_cleanup(AccountTransactionCleanup { writes: Vec::new() })
            .is_err()
    );
    let excessive = (0..=super::super::MAX_TRANSACTION_CLEANUPS_PER_BATCH.saturating_mul(3))
        .map(|_| {
            AccountServiceDurableWrite::delete(
                TableId::AuthTransaction,
                StoredKey::new(vec![1; 16])?,
            )
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;
    assert!(
        context
            .stage_account_transaction_cleanup(AccountTransactionCleanup { writes: excessive })
            .is_err()
    );
    assert_eq!(context.pending_len(), 0);
    let writes =
        TransactionCleanup::authentication(TransactionId::from_bytes([1; 16])).durable_writes()?;
    assert!(matches!(
        context.stage_account_transaction_cleanup(AccountTransactionCleanup { writes }),
        Ok(StageAccepted::Staged { .. })
    ));
    let writes =
        TransactionCleanup::authentication(TransactionId::from_bytes([2; 16])).durable_writes()?;
    assert!(matches!(
        context.stage_account_transaction_cleanup(AccountTransactionCleanup { writes }),
        Err(StageRefused::Busy)
    ));
    assert_eq!(context.pending_len(), 1);
    Ok(())
}

#[test]
fn shutdown_cancellation_waits_for_each_staged_authority_owner() -> crate::test_support::TestResult
{
    let mut fixture = quiescing_fixture()?;
    let (accounts, context) = fixture.parts()?;
    let generation = ConnectionGeneration::new(1);
    accounts.connection_opened(context, generation)?;
    accounts.pending_authority = Some(PendingAuthority::Logout {
        generation,
        carrier_generation: 1,
    });
    assert!(!accounts.cancel_for_shutdown(context));
    assert!(accounts.connections.contains_key(&generation));
    accounts.pending_authority = None;
    accounts
        .grant_consumptions
        .insert(generation, TransactionId::from_bytes([1; 16]));
    assert!(!accounts.cancel_for_shutdown(context));
    assert!(accounts.connections.contains_key(&generation));
    accounts.grant_consumptions.clear();
    accounts.pending_account_deletions.insert(
        generation,
        AccountDeletionBarrier {
            account_id: account(1),
            tombstone_id: (100, account(1)),
            authentications: Vec::new(),
            grants: Vec::new(),
            completions: Vec::new(),
        },
    );
    assert!(!accounts.cancel_for_shutdown(context));
    assert!(accounts.connections.contains_key(&generation));
    assert_eq!(accounts.pending_account_deletions.len(), 1);
    accounts.pending_account_deletions.clear();
    assert!(accounts.cancel_for_shutdown(context));
    assert!(!accounts.connections.contains_key(&generation));
    Ok(())
}
