//! Directory operations: identities, rosters, capabilities, binding locks,
//! device attachment, and the KeyPackage stock (companion Sections 8, 11.6,
//! 13.1).

use agenc_ircd_crypto::{SemanticHashDomain, SignatureDomain};
use agenc_ircd_domain::e2ee::directory::{CapabilityHead, ClaimOutcome, ClaimParameters, Package};
use agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS;
use agenc_ircd_domain::e2ee::projection::{EmptyKind, StoreKind};
use agenc_ircd_e2ee::identity::{
    ValidationTime, verify_capabilities, verify_key_package_credential, verify_root_identity,
    verify_roster,
};
use agenc_ircd_e2ee::limits::{
    MAX_CAPABILITY_OBJECT, MAX_DEVICE_ATTACH_OBJECT, MAX_IDENTITY_OBJECT, MAX_KEY_PACKAGE_OBJECT,
    MAX_ROSTER_OBJECT,
};
use agenc_ircd_e2ee::mls_outer::{
    MlsOuterMessage, parse_mls_message, verify_key_package_signatures,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::attach::{
    IrcDeviceAttach, IrcDeviceAttachChallenge, IrcDeviceAttachTbs,
};
use agenc_ircd_e2ee::objects::identity::{
    IrcAccountRootChain, IrcDeviceCapabilities, IrcDeviceRoster, IrcRootIdentity,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{
    ATTACH_ROW_KIND, AttachChallenge, AttachRow, DIRECTORY_ROW_KIND, DirectoryRow,
    PACKAGE_ROW_KIND, PackageRow, PackageState,
};

use super::super::CompanionCoordinator;
use super::super::request::{Outcome, ResponseObject, ResultBody, state_row};
use super::{Exec, Fail, account, cursor};

fn digest(exec: &Exec<'_>, account: &[u8; 24]) -> Result<[u8; 32], Fail> {
    agenc_ircd_e2ee::ids::account_id_digest(&exec.coordinator.network_id, account)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}

fn decode<T: TlsDecode>(bytes: &[u8], limit: usize) -> Result<T, Fail> {
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    T::decode_exact(bytes, &mut budget).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))
}

fn single(exec: &mut Exec<'_>, bytes: Option<Vec<u8>>, empty: EmptyKind) -> Result<Outcome, Fail> {
    let Some(bytes) = bytes else {
        return Ok(Outcome::scalar(ResultBody::Empty(empty)));
    };
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some(exec.random()?);
    outcome.responses.push(ResponseObject {
        bytes,
        delivery_token: None,
        target_device_id: None,
    });
    Ok(outcome)
}

pub(super) fn directory_write(
    key: agenc_ircd_storage::StoredKey,
    row: &DirectoryRow,
) -> Result<crate::state_core::durable::AccountServiceDurableWrite, Fail> {
    state_row(
        TableId::E2eeState,
        DIRECTORY_ROW_KIND,
        key,
        row.encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )
    .map_err(Fail::from)
}

/// `fetch_identity`.
pub fn fetch_identity(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let target = exec.params().read(account)?;
    exec.account_id()?;
    let digest = digest(exec, &target)?;
    let bytes = exec
        .coordinator
        .state
        .directory
        .account(&digest)
        .and_then(|entry| entry.root.as_ref())
        .and_then(|root| root.chain.last())
        .and_then(|id| exec.coordinator.state.objects.get(id).cloned());
    single(exec, bytes, EmptyKind::Identity)
}

/// `fetch_root_chain`: one `root_identity_chain` object holding the
/// contiguous page from the requested generation.
pub fn fetch_root_chain(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (target, first, _cursor) = exec
        .params()
        .read(|reader| Ok((account(reader)?, reader.u64()?, cursor(reader)?)))?;
    exec.account_id()?;
    let digest = digest(exec, &target)?;
    let Some(root) = exec
        .coordinator
        .state
        .directory
        .account(&digest)
        .and_then(|entry| entry.root.as_ref())
    else {
        return Ok(Outcome::scalar(ResultBody::Empty(EmptyKind::RootChain)));
    };
    let start = usize::try_from(first).map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let mut roots = Vec::new();
    for id in root.chain.iter().skip(start).take(MAX_BATCH_OBJECTS) {
        let bytes = exec
            .coordinator
            .state
            .objects
            .get(id)
            .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
        let object = IrcWireObject::peek(bytes)
            .ok()
            .and_then(|(kind, _)| (kind == IrcWireObjectKind::RootIdentity).then_some(bytes))
            .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
        let mut budget = DecodeBudget::new(MAX_IDENTITY_OBJECT, 1 << 12);
        let wire =
            IrcWireObject::decode_kind(object, Some(IrcWireObjectKind::RootIdentity), &mut budget)
                .map_err(|_| Fail::from(E2eeReplyCode::ObjectNotFound))?;
        roots.push(decode::<IrcRootIdentity>(wire.body(), MAX_IDENTITY_OBJECT)?);
    }
    if roots.is_empty() {
        return Ok(Outcome::scalar(ResultBody::Empty(EmptyKind::RootChain)));
    }
    let chain = IrcAccountRootChain {
        account_id: Opaque::from_slice(&target)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        roots: TlsVec::new(roots).map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?,
    };
    let body = chain
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let bytes = IrcWireObject::new(IrcWireObjectKind::RootIdentityChain, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::ObjectTooLarge))?;
    single(exec, Some(bytes), EmptyKind::RootChain)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler validates the root chain, derives the new head, and stages the object, head row, and directory event as one atomic set
/// `publish_identity`: the next root of the requester's own account.
pub fn publish_identity(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    exec.params().none()?;
    let account_id = exec.account_id()?;
    let account_digest = exec.account_digest()?;
    let (object, bytes) = exec.payload()?;
    let root: IrcRootIdentity = decode(object.body(), MAX_IDENTITY_OBJECT)?;
    if root.tbs.account_id.as_slice() != account_id {
        return Err(E2eeReplyCode::AccountRequired.into());
    }
    let predecessor = exec
        .coordinator
        .state
        .principals
        .get(&account_digest)
        .map(|(root, _)| root);
    let verified = verify_root_identity(&exec.coordinator.network_id, &root, predecessor)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let mut directory = exec.coordinator.state.directory.clone();
    directory
        .publish_root(
            account_digest,
            verified.generation,
            verified.fingerprint,
            object_id,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::OperationConflict))?;
    let chain = directory
        .account(&account_digest)
        .and_then(|entry| entry.root.as_ref())
        .map(|root| root.chain.clone())
        .unwrap_or_default();
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Identity, object_id));
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(directory_write(
        DirectoryRow::identity_key(&account_digest)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        &DirectoryRow::Identity {
            root_generation: verified.generation,
            root_fingerprint: verified.fingerprint,
            object_id,
            chain_object_ids: chain,
        },
    )?);
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
        let roster = companion
            .principals
            .remove(&account_digest)
            .map(|(_, roster)| roster);
        if let Some(roster) = roster {
            companion
                .principals
                .insert(account_digest, (verified, roster));
        } else {
            companion.pending_roots.insert(account_digest, verified);
        }
    }));
    Ok(outcome)
}

/// `fetch_roster`.
pub fn fetch_roster(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let target = exec.params().read(account)?;
    exec.account_id()?;
    let digest = digest(exec, &target)?;
    let bytes = exec
        .coordinator
        .state
        .directory
        .account(&digest)
        .and_then(|entry| entry.roster.as_ref())
        .and_then(|roster| {
            exec.coordinator
                .state
                .objects
                .get(&roster.object_id)
                .cloned()
        });
    single(exec, bytes, EmptyKind::Roster)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler validates the roster against its root, burns removed devices, and stages the rows and events as one atomic set
/// `publish_roster`.
pub fn publish_roster(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    exec.params().none()?;
    let account_id = exec.account_id()?;
    let account_digest = exec.account_digest()?;
    let (object, bytes) = exec.payload()?;
    let roster: IrcDeviceRoster = decode(object.body(), MAX_ROSTER_OBJECT)?;
    if roster.tbs.account_id.as_slice() != account_id {
        return Err(E2eeReplyCode::AccountRequired.into());
    }
    let (root, previous) = match (
        exec.coordinator.state.principals.get(&account_digest),
        exec.coordinator.state.pending_roots.get(&account_digest),
    ) {
        (Some((root, roster)), _) => (root, Some(roster)),
        (None, Some(root)) => (root, None),
        (None, None) => return Err(E2eeReplyCode::BindingAuthInvalid.into()),
    };
    let verified = verify_roster(root, &roster, previous)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let devices: std::collections::BTreeSet<[u8; 16]> = verified.devices.keys().copied().collect();
    let mut directory = exec.coordinator.state.directory.clone();
    let burned = directory
        .publish_roster(
            account_digest,
            verified.generation,
            verified.roster_id,
            root.fingerprint,
            devices.clone(),
            object_id,
        )
        .map_err(|_| Fail::from(E2eeReplyCode::OperationConflict))?;
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Roster, object_id));
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(directory_write(
        DirectoryRow::roster_key(&account_digest)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        &DirectoryRow::Roster {
            roster_generation: verified.generation,
            roster_id: verified.roster_id,
            root_fingerprint: root.fingerprint,
            object_id,
            active_devices: devices.into_iter().collect(),
        },
    )?);
    for reference in &burned {
        let key = PackageRow::package_key(reference)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        outcome.writes.push(
            crate::state_core::durable::AccountServiceDurableWrite::delete(TableId::E2eeState, key)
                .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        );
    }
    let root = *root;
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
        companion
            .roster_snapshots
            .insert(verified.roster_id, object_id);
        companion.pending_roots.remove(&account_digest);
        companion
            .principals
            .insert(account_digest, (root, verified));
    }));
    Ok(outcome)
}

/// `fetch_capabilities`: every active device once, in Device ID order.
pub fn fetch_capabilities(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (target, cursor) = exec
        .params()
        .read(|reader| Ok((account(reader)?, cursor(reader)?)))?;
    exec.account_id()?;
    let digest = digest(exec, &target)?;
    let pages = exec.coordinator.state.directory.capability_page(&digest);
    let start = cursor.map_or(0, |cursor| {
        pages
            .iter()
            .position(|(_, id)| *id == cursor)
            .map_or(pages.len(), |index| index + 1)
    });
    let window: Vec<[u8; 32]> = pages
        .iter()
        .skip(start)
        .take(MAX_BATCH_OBJECTS + 1)
        .map(|(_, id)| *id)
        .collect();
    let next = window
        .get(MAX_BATCH_OBJECTS)
        .and_then(|_| window.get(MAX_BATCH_OBJECTS - 1).copied());
    let objects: Vec<Vec<u8>> = window
        .iter()
        .take(MAX_BATCH_OBJECTS)
        .filter_map(|id| exec.coordinator.state.objects.get(id).cloned())
        .collect();
    if objects.is_empty() {
        return Ok(Outcome::scalar(ResultBody::Empty(EmptyKind::Capabilities)));
    }
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some(exec.random()?);
    outcome.next_cursor = next;
    outcome.responses = objects
        .into_iter()
        .map(|bytes| ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        })
        .collect();
    Ok(outcome)
}

/// `publish_capabilities`.
pub fn publish_capabilities(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let device_id = exec.params().read(|reader| reader.fixed::<16>())?;
    let account_digest = exec.account_digest()?;
    let (attached, _) = exec.attached_device()?;
    if attached != device_id {
        return Err(E2eeReplyCode::DeviceRequired.into());
    }
    let (object, bytes) = exec.payload()?;
    let capabilities: IrcDeviceCapabilities = decode(object.body(), MAX_CAPABILITY_OBJECT)?;
    let (_, roster) = exec
        .coordinator
        .state
        .principals
        .get(&account_digest)
        .ok_or_else(|| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let previous = exec
        .coordinator
        .state
        .capabilities
        .get(&(account_digest, device_id));
    let verified = verify_capabilities(roster, &capabilities, previous)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    if capabilities.tbs.device_id != device_id {
        return Err(E2eeReplyCode::DeviceRequired.into());
    }
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let head = CapabilityHead {
        generation: verified.generation,
        capability_id: CompanionCoordinator::id_of(
            SemanticHashDomain::CapabilityId,
            &capabilities.tbs,
        )?,
        roster_id: roster.roster_id,
        object_id,
    };
    let mut directory = exec.coordinator.state.directory.clone();
    directory
        .publish_capability(account_digest, device_id, head)
        .map_err(|_| Fail::from(E2eeReplyCode::OperationConflict))?;
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Capabilities, object_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(directory_write(
        DirectoryRow::capability_key(&account_digest, &device_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        &DirectoryRow::Capability {
            generation: head.generation,
            capability_id: head.capability_id,
            roster_id: head.roster_id,
            object_id,
        },
    )?);
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
        companion
            .capabilities
            .insert((account_digest, device_id), verified);
    }));
    Ok(outcome)
}

/// `fetch_binding_locks`: the contiguous chain of one root from the
/// requested sequence.
pub fn fetch_binding_locks(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (target, fingerprint, first, _cursor) = exec.params().read(|reader| {
        Ok((
            account(reader)?,
            reader.fixed::<32>()?,
            reader.u64()?,
            cursor(reader)?,
        ))
    })?;
    exec.account_id()?;
    let digest = digest(exec, &target)?;
    let objects: Vec<Vec<u8>> = exec
        .coordinator
        .state
        .binding_locks
        .get(&(digest, fingerprint))
        .map(|locks| {
            locks
                .range(first..)
                .take(MAX_BATCH_OBJECTS)
                .filter_map(|(_, entry)| {
                    exec.coordinator
                        .state
                        .objects
                        .get(&entry.object_id)
                        .cloned()
                })
                .collect()
        })
        .unwrap_or_default();
    if objects.is_empty() {
        return Ok(Outcome::scalar(ResultBody::Empty(EmptyKind::BindingLock)));
    }
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some(exec.random()?);
    outcome.responses = objects
        .into_iter()
        .map(|bytes| ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        })
        .collect();
    Ok(outcome)
}

/// `whoami`.
pub fn whoami(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    exec.params().none()?;
    let account = exec.account_id()?;
    let generation = exec.origin.device.map_or(0, |(_, generation)| generation);
    Ok(Outcome::scalar(ResultBody::Account(account, generation)))
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler checks the device, issues the challenge, and stages the attach row and challenge state as one atomic set
/// `attach_begin`.
pub fn attach_begin(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let device_id = exec.params().read(|reader| reader.fixed::<16>())?;
    let account_id = exec.account_id()?;
    let account_digest = exec.account_digest()?;
    let mut directory = exec.coordinator.state.directory.clone();
    let challenge = directory
        .attach_begin(
            account_digest,
            device_id,
            exec.origin.connection_id,
            exec.now,
        )
        .map_err(|_| Fail::with(E2eeReplyCode::DeviceRequired, &device_id))?;
    let server_challenge: [u8; 32] = exec.random()?;
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let tbs = IrcDeviceAttachTbs {
        profile_version: 1,
        network_id: exec.coordinator.network_id,
        account_id: Opaque::from_slice(&account_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        device_id,
        connection_nonce: exec.origin.connection_nonce,
        server_challenge,
        session_generation: challenge.reserved_generation,
        issued_at: exec.now,
        expires_at: challenge.expires_at,
    };
    let object = IrcDeviceAttachChallenge {
        sequencer_signature: signer
            .sign(SignatureDomain::DeviceAttachChallenge, &tbs)
            .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?,
        tbs,
    };
    let body = object
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let bytes = IrcWireObject::new(IrcWireObjectKind::DeviceAttachChallenge, body)
        .and_then(|object| object.encode())
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(&bytes).as_bytes();
    let mut outcome = Outcome::scalar(ResultBody::AttachChallenge(device_id, object_id));
    outcome.snapshot_token = Some(exec.random()?);
    outcome.responses.push(ResponseObject {
        bytes: bytes.clone(),
        delivery_token: None,
        target_device_id: None,
    });
    outcome
        .writes
        .push(CompanionCoordinator::object_write(&bytes)?);
    let session_generation = directory.session_generation(&account_digest, &device_id);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        ATTACH_ROW_KIND,
        AttachRow::key(&account_digest, &device_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        AttachRow {
            session_generation,
            challenge: Some(AttachChallenge {
                connection_id: challenge.connection_id,
                connection_nonce: exec.origin.connection_nonce,
                server_challenge,
                reserved_generation: challenge.reserved_generation,
                expires_at: challenge.expires_at,
                object_id,
            }),
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
        companion
            .challenges
            .insert((account_digest, device_id), server_challenge);
    }));
    Ok(outcome)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler verifies the challenge answer, compares and swaps the session generation, and stages the attach row and mailbox effects as one atomic set
/// `attach_finish`.
pub fn attach_finish(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let device_id = exec.params().read(|reader| reader.fixed::<16>())?;
    let account_id = exec.account_id()?;
    let account_digest = exec.account_digest()?;
    let (object, bytes) = exec.payload()?;
    let attach: IrcDeviceAttach = decode(object.body(), MAX_DEVICE_ATTACH_OBJECT)?;
    let tbs = &attach.challenge.tbs;
    let expected_challenge = exec
        .coordinator
        .state
        .challenges
        .get(&(account_digest, device_id))
        .copied()
        .ok_or_else(|| Fail::with(E2eeReplyCode::DeviceRequired, &device_id))?;
    let agrees = tbs.account_id.as_slice() == account_id
        && tbs.device_id == device_id
        && tbs.connection_nonce == exec.origin.connection_nonce
        && tbs.server_challenge == expected_challenge
        && tbs.network_id == exec.coordinator.network_id
        && tbs.expires_at > exec.now;
    if !agrees {
        return Err(Fail::with(E2eeReplyCode::DeviceRequired, &device_id));
    }
    let signer = exec
        .coordinator
        .signer()
        .ok_or_else(|| Fail::from(E2eeReplyCode::Syncing))?;
    let expected_signature = signer
        .sign(SignatureDomain::DeviceAttachChallenge, tbs)
        .map_err(|_| Fail::from(E2eeReplyCode::Syncing))?;
    if expected_signature != attach.challenge.sequencer_signature {
        return Err(Fail::with(E2eeReplyCode::DeviceRequired, &device_id));
    }
    let (_, roster) = exec
        .coordinator
        .state
        .principals
        .get(&account_digest)
        .ok_or_else(|| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let certificate = roster
        .device(&device_id)
        .ok_or_else(|| Fail::with(E2eeReplyCode::DeviceRequired, &device_id))?;
    let encoded = tbs
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    certificate
        .key
        .verify(
            SignatureDomain::DeviceAttachPossession,
            &encoded,
            &attach.device_signature,
        )
        .map_err(|_| Fail::with(E2eeReplyCode::DeviceRequired, &device_id))?;
    let mut directory = exec.coordinator.state.directory.clone();
    let generation = directory
        .attach_finish(
            account_digest,
            device_id,
            exec.origin.connection_id,
            tbs.session_generation,
            exec.now,
        )
        .map_err(|_| Fail::with(E2eeReplyCode::DeviceRequired, &device_id))?;
    let mut outcome = Outcome::scalar(ResultBody::Attached(device_id, generation));
    outcome.security_mutation = true;
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        ATTACH_ROW_KIND,
        AttachRow::key(&account_digest, &device_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        AttachRow {
            session_generation: generation,
            challenge: None,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    // The attachment reaches the origin only through the EORIGIN UPDATE
    // that follows the base generation transition (companion 12.5).
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
        companion.challenges.remove(&(account_digest, device_id));
    }));
    Ok(outcome)
}

fn claimed(
    exec: &mut Exec<'_>,
    device_id: [u8; 16],
    outcome: &ClaimOutcome,
) -> Result<Outcome, Fail> {
    match outcome {
        ClaimOutcome::Claimed {
            key_package_ref,
            object_id,
        } => {
            let bytes = exec
                .coordinator
                .state
                .objects
                .get(object_id)
                .cloned()
                .ok_or_else(|| Fail::from(E2eeReplyCode::ObjectNotFound))?;
            let mut result = Outcome::scalar(ResultBody::Claimed(
                device_id,
                key_package_ref.clone(),
                *object_id,
            ));
            result.snapshot_token = Some(exec.random()?);
            result.responses.push(ResponseObject {
                bytes,
                delivery_token: None,
                target_device_id: None,
            });
            Ok(result)
        }
        ClaimOutcome::Unavailable => Ok(Outcome::scalar(ResultBody::Empty(EmptyKind::Package))),
    }
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler applies the idempotent claim, burns the package, and stages the claim and package rows as one atomic set
/// `claim_package`.
pub fn claim_package(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (target, device_id, suite, operation_id) = exec.params().read(|reader| {
        Ok((
            account(reader)?,
            reader.fixed::<16>()?,
            reader.u16()?,
            reader.fixed::<16>()?,
        ))
    })?;
    let claimant = exec.account_digest()?;
    exec.attached_device()?;
    // A repeated operation replays the recorded claim; its rows are already
    // durable, so only a fresh claim stages writes.
    let fresh = exec
        .coordinator
        .state
        .directory
        .claim_status(&claimant, &operation_id)
        .is_none();
    let parameters = ClaimParameters {
        target_account_digest: digest(exec, &target)?,
        target_device_id: device_id,
        suite,
    };
    let mut directory = exec.coordinator.state.directory.clone();
    let claim = directory
        .claim_package(claimant, operation_id, parameters, exec.now)
        .map_err(|error| match error {
            agenc_ircd_domain::e2ee::directory::DirectoryError::OperationConflict => {
                Fail::with(E2eeReplyCode::OperationConflict, &operation_id)
            }
            agenc_ircd_domain::e2ee::directory::DirectoryError::DeviceInactive => {
                Fail::with(E2eeReplyCode::KeyUnavailable, &device_id)
            }
            _ => Fail::with(E2eeReplyCode::KeyUnavailable, &device_id),
        })?;
    let mut outcome = claimed(exec, device_id, &claim)?;
    if let ClaimOutcome::Claimed {
        key_package_ref,
        object_id,
    } = &claim
        && fresh
    {
        let key = PackageRow::claim_key(&claimant, &operation_id)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        outcome.writes.push(state_row(
            TableId::E2eeState,
            PACKAGE_ROW_KIND,
            key,
            PackageRow::Claim {
                target_account_digest: parameters.target_account_digest,
                target_device_id: device_id,
                suite,
                outcome: agenc_ircd_storage::e2ee_records::ClaimOutcome::Claimed,
                key_package_ref: key_package_ref.clone(),
                object_id: Some(*object_id),
                retain_until: exec.now.saturating_add(
                    agenc_ircd_domain::e2ee::limits::KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS,
                ),
            }
            .encode()
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        )?);
        let package_key = PackageRow::package_key(key_package_ref)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
        outcome.writes.push(
            crate::state_core::durable::AccountServiceDurableWrite::delete(
                TableId::E2eeState,
                package_key,
            )
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        );
    }
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
    }));
    Ok(outcome)
}

/// `claim_status`.
pub fn claim_status(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let operation_id = exec.params().read(|reader| reader.fixed::<16>())?;
    let claimant = exec.account_digest()?;
    let claim = exec
        .coordinator
        .state
        .directory
        .claim_status(&claimant, &operation_id)
        .cloned()
        .unwrap_or(ClaimOutcome::Unavailable);
    let device = exec.origin.device.map_or([0; 16], |(device, _)| device);
    claimed(exec, device, &claim)
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one handler validates the public KeyPackage against its capability chain and stages the object and package row as one atomic set
/// `publish_package`.
pub fn publish_package(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let (device_id, suite, expires_at) = exec
        .params()
        .read(|reader| Ok((reader.fixed::<16>()?, reader.u16()?, reader.u64()?)))?;
    let account_digest = exec.account_digest()?;
    let (attached, _) = exec.attached_device()?;
    if attached != device_id {
        return Err(E2eeReplyCode::DeviceRequired.into());
    }
    let (object, bytes) = exec.payload()?;
    let mut budget = DecodeBudget::new(MAX_KEY_PACKAGE_OBJECT, 1 << 14);
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(object.body(), &mut budget)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?
    else {
        return Err(E2eeReplyCode::InvalidFragment.into());
    };
    verify_key_package_signatures(&package)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    if package.has_last_resort_extension() || package.cipher_suite != suite {
        return Err(E2eeReplyCode::BindingAuthInvalid.into());
    }
    let (_, roster) = exec
        .coordinator
        .state
        .principals
        .get(&account_digest)
        .ok_or_else(|| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    let credential = verify_key_package_credential(&exec.coordinator.network_id, roster, &package)
        .map_err(|_| Fail::from(E2eeReplyCode::BindingAuthInvalid))?;
    if credential.certificate.device_id != device_id
        || !credential
            .certificate
            .interval
            .covers(ValidationTime(exec.now))
    {
        return Err(E2eeReplyCode::BindingAuthInvalid.into());
    }
    let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
    let reference = package.key_package_ref.to_vec();
    let row = Package {
        account_digest,
        device_id,
        suite,
        expires_at,
        object_id,
    };
    let mut directory = exec.coordinator.state.directory.clone();
    directory
        .publish_package(reference.clone(), row, exec.now)
        .map_err(|error| match error {
            agenc_ircd_domain::e2ee::directory::DirectoryError::DuplicatePackage => {
                Fail::from(E2eeReplyCode::OperationConflict)
            }
            _ => Fail::from(E2eeReplyCode::BindingAuthInvalid),
        })?;
    let mut outcome = Outcome::scalar(ResultBody::Stored(StoreKind::Package, object_id));
    outcome
        .writes
        .push(CompanionCoordinator::object_write(bytes)?);
    outcome.writes.push(state_row(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        PackageRow::package_key(&reference)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
        PackageRow::Package {
            account_digest,
            device_id,
            suite,
            expires_at,
            object_id,
            state: PackageState::Published,
            claimed_by: None,
        }
        .encode()
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    )?);
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
    }));
    Ok(outcome)
}

/// `revoke_package`.
pub fn revoke_package(exec: &mut Exec<'_>) -> Result<Outcome, Fail> {
    let reference = exec.params().read(|reader| reader.opaque(1, 255))?;
    let (device_id, _) = exec.attached_device()?;
    let mut directory = exec.coordinator.state.directory.clone();
    directory
        .revoke_package(&device_id, &reference)
        .map_err(|error| match error {
            agenc_ircd_domain::e2ee::directory::DirectoryError::NotOwner => {
                Fail::from(E2eeReplyCode::DeviceRequired)
            }
            _ => Fail::from(E2eeReplyCode::KeyUnavailable),
        })?;
    let mut outcome = Outcome::scalar(ResultBody::Revoked(reference.clone()));
    let key = PackageRow::package_key(&reference)
        .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?;
    outcome.writes.push(
        crate::state_core::durable::AccountServiceDurableWrite::delete(TableId::E2eeState, key)
            .map_err(|_| Fail::from(E2eeReplyCode::InvalidFragment))?,
    );
    outcome.effects.push(Box::new(move |companion| {
        companion.directory = directory;
    }));
    Ok(outcome)
}
