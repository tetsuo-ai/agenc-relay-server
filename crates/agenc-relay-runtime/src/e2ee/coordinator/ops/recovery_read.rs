//! Public-object reads cannot use another route as a recovery-gate bypass.

#![forbid(unsafe_code)]

use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::ids::conversation_id;
use agenc_relay_e2ee::limits::PROFILE_VERSION;
use agenc_relay_e2ee::mls_outer::{MlsOuterMessage, parse_mls_message};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind as Kind};
use agenc_relay_e2ee::objects::aad::{ArcApplicationAad, ArcCommitAad};
use agenc_relay_e2ee::objects::reinit::ArcStagedReInit;
use agenc_relay_e2ee::objects::sequencing::ArcDeliveredWelcome;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

use super::{Exec, recovery};

type EncryptedLineages = ([u8; 32], Option<[u8; 32]>);

pub(super) fn permitted(exec: &Exec<'_>, requested: &[u8; 32], bytes: &[u8]) -> bool {
    encrypted_lineages(exec, bytes).is_ok_and(|lineages| match lineages {
        None => true,
        Some((conversation, predecessor)) => {
            conversation == *requested
                && recovery::permitted(&exec.coordinator.state, &conversation)
                && predecessor.is_none_or(|id| recovery::permitted(&exec.coordinator.state, &id))
        }
    })
}

fn encrypted_lineages(
    exec: &Exec<'_>,
    bytes: &[u8],
) -> Result<Option<EncryptedLineages>, E2eeError> {
    let (kind, _) = ArcWireObject::peek(bytes)?;
    if kind.is_server_only() {
        return Err(E2eeError::WrongKind);
    }
    if !matches!(
        kind,
        Kind::ApplicationMls | Kind::CommitMls | Kind::WelcomeMls | Kind::StagedReinit
    ) {
        return Ok(None);
    }
    let mut budget = DecodeBudget::new(kind.maximum_object_bytes(), 1 << 20);
    let object = ArcWireObject::decode_kind(bytes, Some(kind), &mut budget)?;
    let ids = match kind {
        Kind::ApplicationMls | Kind::CommitMls => {
            (private_conversation(exec, &object, &mut budget)?, None)
        }
        Kind::WelcomeMls => {
            let welcome = ArcDeliveredWelcome::decode_exact(object.body(), &mut budget)?;
            if welcome.profile_version != PROFILE_VERSION
                || welcome.network_id != exec.coordinator.network_id
            {
                return Err(E2eeError::ProfileMismatch);
            }
            (welcome.conversation_id, None)
        }
        Kind::StagedReinit => {
            let staged = ArcStagedReInit::decode_exact(object.body(), &mut budget)?;
            if staged.receipt.tbs.profile_version != PROFILE_VERSION
                || staged.receipt.tbs.network_id != exec.coordinator.network_id
            {
                return Err(E2eeError::ProfileMismatch);
            }
            (
                staged.new_conversation_id,
                Some(staged.receipt.tbs.old_conversation_id),
            )
        }
        _ => return Err(E2eeError::WrongKind),
    };
    Ok(Some(ids))
}

fn private_conversation(
    exec: &Exec<'_>,
    object: &ArcWireObject,
    budget: &mut DecodeBudget,
) -> Result<[u8; 32], E2eeError> {
    let MlsOuterMessage::Private(header) = parse_mls_message(object.body(), budget)? else {
        return Err(E2eeError::WrongKind);
    };
    let (profile, network, conversation) = if object.kind() == Kind::ApplicationMls {
        let aad = ArcApplicationAad::decode_exact(&header.authenticated_data, budget)?;
        (aad.profile_version, aad.network_id, aad.conversation_id)
    } else {
        let aad = ArcCommitAad::decode_exact(&header.authenticated_data, budget)?;
        (aad.profile_version, aad.network_id, aad.conversation_id)
    };
    if profile != PROFILE_VERSION
        || network != exec.coordinator.network_id
        || conversation_id(&network, &header.group_id)? != conversation
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(conversation)
}
