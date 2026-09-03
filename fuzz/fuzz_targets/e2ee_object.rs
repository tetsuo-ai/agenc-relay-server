#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::objects::{TypedBody, decode_body};
use agenc_ircd_e2ee::{DecodeBudget, IrcWireObject, ObjectId, TlsDecode as _, TlsEncode as _};
use libfuzzer_sys::fuzz_target;

const BUDGET_BYTES: usize = 8 * 1024 * 1024;
const BUDGET_VALUES: usize = 1_000_000;

// An accepted envelope re-encodes to the accepted bytes and keeps one
// identity; an accepted typed body re-encodes to the exact envelope body.
fuzz_target!(|data: &[u8]| {
    let mut budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    if IrcWireObject::peek(data).is_err() {
        return;
    }
    let Ok(object) = IrcWireObject::decode_exact(data, &mut budget) else {
        return;
    };
    let reencoded = object.encode().expect("accepted envelope must re-encode");
    assert_eq!(reencoded, data, "accepted envelope did not re-encode canonically");
    assert_eq!(ObjectId::compute(data), object.object_id().expect("object id"));
    let mut body_budget = DecodeBudget::new(BUDGET_BYTES, BUDGET_VALUES);
    let Ok(body) = decode_body(&object, &mut body_budget) else {
        return;
    };
    assert_eq!(body.kind(), object.kind());
    let typed = match &body {
        TypedBody::CommitApproval(value) => Some(value.encode()),
        TypedBody::CommitAck(value) => Some(value.encode()),
        TypedBody::FinalizationRequest(value) => Some(value.encode()),
        TypedBody::FinalizationCertificate(value) => Some(value.encode()),
        TypedBody::AbortRequest(value) => Some(value.encode()),
        TypedBody::AbortCertificate(value) => Some(value.encode()),
        TypedBody::WelcomeMls(value) => Some(value.encode()),
        TypedBody::RootIdentity(value) => Some(value.encode()),
        TypedBody::RootIdentityChain(value) => Some(value.encode()),
        TypedBody::DeviceRoster(value) => Some(value.encode()),
        TypedBody::DeviceCapabilities(value) => Some(value.encode()),
        TypedBody::ConversationBinding(value) => Some(value.encode()),
        TypedBody::CloseAuthorization(value) => Some(value.encode()),
        TypedBody::Reservation(value) => Some(value.encode()),
        TypedBody::ReinitAttempt(value) => Some(value.encode()),
        TypedBody::StagedReinit(value) => Some(value.encode()),
        TypedBody::ReinitAck(value) => Some(value.encode()),
        TypedBody::ReinitActivationRequest(value) => Some(value.encode()),
        TypedBody::ReinitActivationCertificate(value) => Some(value.encode()),
        TypedBody::ReinitAbortRequest(value) => Some(value.encode()),
        TypedBody::ReinitAbortCertificate(value) => Some(value.encode()),
        TypedBody::SequencerRecord(value) => Some(value.encode()),
        TypedBody::DeviceAttachChallenge(value) => Some(value.encode()),
        TypedBody::DeviceAttach(value) => Some(value.encode()),
        TypedBody::RootBindingLock(value) => Some(value.encode()),
        TypedBody::FederationState(value) => Some(value.encode()),
        TypedBody::FederationOrigin(value) => Some(value.encode()),
        TypedBody::FederationRequest(value) => Some(value.encode()),
        TypedBody::FederationResult(value) => Some(value.encode()),
        TypedBody::FederationEvent(value) => Some(value.encode()),
        TypedBody::ApplicationMls(_) | TypedBody::CommitMls(_) | TypedBody::KeyPackageMls(_) => {
            None
        }
    };
    if let Some(encoded) = typed {
        let encoded = encoded.expect("accepted body must re-encode");
        assert_eq!(encoded, object.body(), "accepted body did not re-encode canonically");
    }
});
