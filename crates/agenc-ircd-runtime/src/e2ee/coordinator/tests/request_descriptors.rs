//! The descriptor registry rule of one result kind bounds the response count,
//! the wire kinds, and whether mailbox delivery tokens may appear.
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::tls::TlsEncode;

use super::{DescriptorRule, ResponseObject, check_descriptors};

/// The companion discriminant of `ApplicationMls`.
const MLS: &[u8] = &[1];

fn response(kind: IrcWireObjectKind, tokened: bool) -> ResponseObject {
    let bytes = IrcWireObject::new(kind, vec![9; 8])
        .and_then(|object| object.encode())
        .unwrap_or_default();
    ResponseObject {
        bytes,
        delivery_token: tokened.then_some([3; 32]),
        target_device_id: tokened.then_some([4; 16]),
    }
}

#[test]
fn each_descriptor_rule_bounds_count_kind_and_delivery_tokens() {
    let mls = || response(IrcWireObjectKind::ApplicationMls, false);
    let event = || response(IrcWireObjectKind::FederationEvent, false);
    let mailbox = || response(IrcWireObjectKind::ApplicationMls, true);

    assert!(check_descriptors(&DescriptorRule::None, &[]).is_ok());
    assert!(check_descriptors(&DescriptorRule::None, &[mls()]).is_err());

    let exactly = DescriptorRule::ExactlyOne(1);
    assert!(check_descriptors(&exactly, &[mls()]).is_ok());
    assert!(check_descriptors(&exactly, &[event()]).is_err());
    assert!(check_descriptors(&exactly, &[mls(), mls()]).is_err());
    assert!(
        check_descriptors(&exactly, &[mailbox()]).is_err(),
        "delivery tokens belong to mailbox pages only"
    );

    let page = DescriptorRule::Page(MLS);
    assert!(check_descriptors(&page, &[]).is_err());
    assert!(check_descriptors(&page, &[event()]).is_err());
    assert!(check_descriptors(&page, &[mls()]).is_ok());
    let over: Vec<ResponseObject> = (0..=agenc_ircd_domain::e2ee::limits::MAX_BATCH_OBJECTS)
        .map(|_| mls())
        .collect();
    assert!(check_descriptors(&page, &over).is_err());

    assert!(check_descriptors(&DescriptorRule::MailboxPage, &[mls()]).is_err());
    assert!(check_descriptors(&DescriptorRule::MailboxPage, &[mailbox()]).is_ok());

    let garbage = ResponseObject {
        bytes: vec![0xff; 3],
        delivery_token: None,
        target_device_id: None,
    };
    assert!(check_descriptors(&page, &[garbage]).is_err());
}
