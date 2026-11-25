//! A sealed admission cannot replace the signed old-group proof or the exact package sequence.
#![forbid(unsafe_code)]

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::e2ee_records::binding_admission::BindingAdmissionRow;
use agenc_relay_storage::{PersistentRecordValue, TableId};

fn rewrite(
    h: &mut Harness,
    key: &agenc_relay_storage::StoredKey,
    edit: impl FnOnce(&[u8]) -> TestResult<Vec<u8>>,
) -> TestResult {
    for write in &mut h.writes {
        if let Write::Put {
            table: TableId::E2eeState,
            key: stored,
            plaintext,
        } = write
            && stored == key
        {
            let old = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
            let body = edit(old.body())?;
            let new = PersistentRecordValue::new(
                TableId::E2eeState,
                old.record_kind(),
                old.revision(),
                old.generation(),
                old.expires_at(),
                old.references().to_vec(),
                body,
            )?;
            *plaintext = zeroize::Zeroizing::new(new.encode()?);
            return Ok(());
        }
    }
    Err("missing durable state row".into())
}

fn change(
    h: &mut Harness,
    key: &agenc_relay_storage::StoredKey,
    edit: fn(&mut BindingAdmissionRow),
) -> TestResult {
    rewrite(h, key, |body| {
        let mut row = BindingAdmissionRow::decode(body)?;
        edit(&mut row);
        Ok(row.encode()?)
    })
}

#[test]
fn restart_requires_every_binding_admission_and_its_exact_terminal_and_packages() -> TestResult {
    let (mut h, original, peer) = direct()?;
    let id = original.conversation;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    let (next, target) = advance(&original, nonce)?;
    approve(&mut h, id, 2, target)?;
    install(&mut h, grant, &next, target)?;
    let admitted = h
        .coordinator
        .state
        .conversations
        .get(&id)
        .and_then(|state| state.binding_admissions.get(&1))
        .ok_or("admission")?;
    let key = admitted.key()?;
    let mut missing = h.reloaded()?;
    missing
        .writes
        .retain(|row| !matches!(row, Write::Put { key: stored, .. } if *stored == key));
    assert!(missing.reloaded().is_err());
    let mut orphan = h.reloaded()?;
    let route = agenc_relay_storage::e2ee_records::RouteRow::key(&id)?;
    orphan
        .writes
        .retain(|row| !matches!(row, Write::Put { key: stored, .. } if *stored == route));
    assert!(orphan.reloaded().is_err());
    // Keep the complete real route and all its recovery gates intact. A
    // separate, internally keyed admission must not gain authority by itself.
    let mut unbound = h.reloaded()?;
    let mut extra = admitted.clone();
    extra.conversation_id[0] ^= 1;
    unbound.writes.push(
        crate::e2ee::coordinator::request::state_row(
            TableId::E2eeState,
            agenc_relay_storage::e2ee_records::binding_admission::KIND,
            extra.key()?,
            extra.encode()?,
        )
        .map_err(|_| "binding admission row")?,
    );
    assert!(unbound.reloaded().is_err());
    type Edit = fn(&mut BindingAdmissionRow);
    let edits: [Edit; 6] = [
        |r| r.conversation_id[0] ^= 1,
        |r| r.generation += 1,
        |r| r.route_sequence -= 1,
        |r| r.previous_binding_object[0] ^= 1,
        |r| r.binding_object[0] ^= 1,
        |r| r.terminal_record_object[0] ^= 1,
    ];
    for edit in edits {
        let mut bad = h.reloaded()?;
        change(&mut bad, &key, edit)?;
        assert!(bad.reloaded().is_err());
    }
    Ok(())
}

#[test]
fn a_mixed_predecessor_route_or_disagreeing_signed_log_projection_refuses_restart() -> TestResult {
    use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
    use agenc_relay_storage::e2ee_records::RouteRow;
    let (mut h, original, peer) = direct()?;
    let id = original.conversation;
    let previous = package(&original.bytes)?.binding.tbs.route_binding;
    let (grant, nonce) = ok_reservation(reserve_direct(&mut h, &peer)?)?;
    let (next, target) = advance(&original, nonce)?;
    approve(&mut h, id, 2, target)?;
    install(&mut h, grant, &next, target)?;
    let key = RouteRow::key(&id)?;
    let edit = |h: &mut Harness,
                patch: &dyn Fn(&mut ArcFederationRouteState) -> TestResult|
     -> TestResult {
        rewrite(h, &key, |body| {
            let mut row = RouteRow::decode(body)?;
            let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
            let obj = ArcWireObject::decode_kind(
                &row.route_state,
                Some(ArcWireObjectKind::FederationState),
                &mut budget,
            )?;
            let mut view = ArcFederationRouteState::decode_exact(obj.body(), &mut budget)?;
            patch(&mut view)?;
            row.route_state = wire(ArcWireObjectKind::FederationState, &view)?;
            Ok(row.encode()?)
        })
    };
    let mut mixed = h.reloaded()?;
    edit(&mut mixed, &|view| {
        view.route_binding = previous;
        Ok(())
    })?;
    assert!(mixed.reloaded().is_err());
    type Edit = fn(&mut ArcFederationRouteState) -> TestResult;
    let edits: [Edit; 14] = [
        |v| {
            v.profile_version += 1;
            Ok(())
        },
        |v| {
            v.network_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.conversation_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.binding_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.semantic_route_lock_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.conversation_kind = ArcConversationKind::Channel;
            Ok(())
        },
        |v| {
            v.channel_instance_id = Opaque::from_slice(&[71; 16])?;
            Ok(())
        },
        |v| {
            v.canonical_channel_name_hash[0] ^= 1;
            Ok(())
        },
        |v| {
            v.direct_account_a = v.direct_account_b.clone();
            Ok(())
        },
        |v| {
            v.direct_account_b = v.direct_account_a.clone();
            Ok(())
        },
        |v| {
            v.accepted_state_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.sequencer_record_head_id[0] ^= 1;
            Ok(())
        },
        |v| {
            v.sequencer_record_head_sequence += 1;
            Ok(())
        },
        |v| {
            v.state = ArcRouteStateKind::EncryptedTombstone;
            Ok(())
        },
    ];
    for patch in edits {
        let mut bad = h.reloaded()?;
        edit(&mut bad, &patch)?;
        assert!(bad.reloaded().is_err());
    }
    let mut wrong_epoch = h.reloaded()?;
    edit(&mut wrong_epoch, &|view| {
        view.finalized_epoch += 1;
        Ok(())
    })?;
    assert!(wrong_epoch.reloaded().is_err());
    Ok(())
}
