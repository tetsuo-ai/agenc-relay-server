#![forbid(unsafe_code)]

use super::*;

#[test]
fn mailbox_scan_charges_each_copy_through_the_existing_account_byte_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let ceiling = usize::try_from(MAX_MAILBOX_BYTES_PER_ACCOUNT)?;
    let mut admission = FetchAdmission::default();
    assert!(admission.charge(ceiling / 2).is_ok());
    assert!(admission.charge(ceiling / 2).is_ok());
    assert_eq!(admission.scanned_bytes, MAX_MAILBOX_BYTES_PER_ACCOUNT);
    assert!(admission.charge(1).is_err());
    assert_eq!(admission.scanned_bytes, MAX_MAILBOX_BYTES_PER_ACCOUNT);
    assert!(admission.charge(usize::MAX).is_err());
    assert_eq!(admission.scanned_bytes, MAX_MAILBOX_BYTES_PER_ACCOUNT);
    Ok(())
}
#[test]
fn a_mailbox_scan_refuses_an_over_budget_copy_before_decoding() {
    let mut coordinator = CompanionCoordinator::new(
        [1; 32],
        agenc_ircd_types::ServerId::from_bytes([2; 16]),
        "coordinator.example".into(),
    );
    let item = Item {
        object_id: [3; 32],
        conversation_id: [4; 32],
        inserted_at: 1,
        expires_at: 1_000,
        grant: None,
    };
    coordinator.state.objects.insert(item.object_id, vec![0; 8]);
    let target = Target {
        account_digest: [5; 32],
        device_id: [6; 16],
    };
    let mut admission = FetchAdmission {
        scanned_bytes: MAX_MAILBOX_BYTES_PER_ACCOUNT - 8,
    };
    let first = admission.admitted(&coordinator, target, MailboxKind::Binding, &item);
    assert_eq!(
        first.map_err(|failure| failure.code),
        Err(E2eeReplyCode::InvalidFragment)
    );
    assert_eq!(admission.scanned_bytes, MAX_MAILBOX_BYTES_PER_ACCOUNT);
    let repeat = admission.admitted(&coordinator, target, MailboxKind::Binding, &item);
    assert_eq!(
        repeat.map_err(|failure| failure.code),
        Err(E2eeReplyCode::RateLimited)
    );
    assert_eq!(admission.scanned_bytes, MAX_MAILBOX_BYTES_PER_ACCOUNT);
}
