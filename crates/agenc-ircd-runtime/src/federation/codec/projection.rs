//! Projection arm objects for standing entries (spec 20.8, B.4).

use agenc_ircd_domain::federation::ProjectionRecord;
use agenc_ircd_federation_wire::{CodecError, SchemaObject, projection_schema_name};
use agenc_ircd_types::FederationProjectionKind;

use super::{
    account_projection_object, account_projection_of, channel_detail_object, channel_detail_of,
    invite_projection_object, invite_projection_of, membership_object, membership_of,
    session_projection_object, session_projection_of,
};

/// Returns the registered projection kind of one standing record.
pub(crate) const fn projection_kind(record: &ProjectionRecord) -> FederationProjectionKind {
    match record {
        ProjectionRecord::Session(_) => FederationProjectionKind::Session,
        ProjectionRecord::ChannelDetail(_) => FederationProjectionKind::ChannelDetail,
        ProjectionRecord::Membership(_) => FederationProjectionKind::Membership,
        ProjectionRecord::Invite(_) => FederationProjectionKind::Invite,
        ProjectionRecord::Account(_) => FederationProjectionKind::Account,
    }
}

/// Encodes one standing record as its projection arm.
pub(crate) fn projection_arm_object(record: &ProjectionRecord) -> Result<SchemaObject, CodecError> {
    match record {
        ProjectionRecord::Session(record) => session_projection_object(record),
        ProjectionRecord::ChannelDetail(record) => channel_detail_object(record),
        ProjectionRecord::Membership(record) => membership_object(record),
        ProjectionRecord::Invite(record) => invite_projection_object(record),
        ProjectionRecord::Account(record) => account_projection_object(record),
    }
}

/// Decodes one projection arm of the given kind.
pub(crate) fn projection_record_of(
    kind: FederationProjectionKind,
    arm: &SchemaObject,
) -> Result<ProjectionRecord, CodecError> {
    if arm.schema().name != projection_schema_name(kind) {
        return Err(CodecError::SchemaMismatch);
    }
    Ok(match kind {
        FederationProjectionKind::Session => ProjectionRecord::Session(session_projection_of(arm)?),
        FederationProjectionKind::ChannelDetail => {
            ProjectionRecord::ChannelDetail(channel_detail_of(arm)?)
        }
        FederationProjectionKind::Membership => ProjectionRecord::Membership(membership_of(arm)?),
        FederationProjectionKind::Invite => ProjectionRecord::Invite(invite_projection_of(arm)?),
        FederationProjectionKind::Account => ProjectionRecord::Account(account_projection_of(arm)?),
    })
}
