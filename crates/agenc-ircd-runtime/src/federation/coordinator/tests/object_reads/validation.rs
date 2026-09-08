//! Decoded storage rows still bind the exact requested hash and conversation.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget};
use crate::e2ee::coordinator::object_read::{Request, Resolved};
use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use std::sync::Arc;

#[test]
fn a_resolved_object_cannot_be_reused_for_another_request() -> TestResult {
    let fixture = crate::e2ee::coordinator::tests::fresh_fetch_fixture()?;
    let budget = Arc::new(MemoryBudget::new(1 << 20));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    let request = Request {
        conversation_id: fixture.conversation,
        object_id: fixture.object_id,
    };
    let row = ObjectRow::new(fixture.bytes.clone())?;
    let record = PersistentRecordValue::new(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    let resolved = Resolved::admit(request, vec![(row.key()?, record)], &backing)
        .map_err(|e| format!("resolve: {e:?}"))?;
    assert_eq!(
        resolved
            .lookup(request)
            .map_err(|e| format!("lookup: {e:?}"))?,
        Some(fixture.bytes.as_slice())
    );
    assert!(
        resolved
            .lookup(Request {
                conversation_id: [99; 32],
                ..request
            })
            .is_err()
    );
    assert!(
        resolved
            .lookup(Request {
                object_id: [99; 32],
                ..request
            })
            .is_err()
    );
    let retained = resolved.backing();
    drop(resolved);
    assert!(budget.charged() > 0);
    drop(retained);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn wrong_hash_key_kind_and_body_are_rejected_after_storage_decode() -> TestResult {
    let fixture = crate::e2ee::coordinator::tests::fresh_fetch_fixture()?;
    let budget = Arc::new(MemoryBudget::new(1 << 20));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    for fault in 0..4 {
        let mut request = Request {
            conversation_id: fixture.conversation,
            object_id: fixture.object_id,
        };
        let row = ObjectRow::new(fixture.bytes.clone())?;
        let mut key = row.key()?;
        let mut body = row.encode()?;
        let mut kind = OBJECT_RECORD_KIND;
        match fault {
            0 => request.object_id = [99; 32],
            1 => key = agenc_ircd_storage::e2ee_records::object_key(&[99; 32])?,
            2 => kind += 1,
            3 => body.clear(),
            _ => return Err("fault".into()),
        }
        let record =
            PersistentRecordValue::new(TableId::E2eeObject, kind, 1, 0, None, Vec::new(), body);
        if fault >= 2 {
            // The storage value codec rejects invalid kinds and bodies before the reader.
            assert!(record.is_err());
        } else {
            assert!(Resolved::admit(request, vec![(key, record?)], &backing).is_err());
        }
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}
