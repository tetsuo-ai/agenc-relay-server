//! The optional edge buffer is admitted against an existing authenticated link and charged once.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::StateCoreFixture;

#[test]
fn optional_input_charges_only_the_exact_start_and_releases_on_retirement()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = StateCoreFixture::new(vec![23; 1_048_576])?;
    let context = fixture.context_mut()?;
    let mut edge = EdgeCarrier::new()?;
    let guarded = InitialRootCarrier::GuardedCreation;
    let start = ("CLAIMSTART", Some("4726"), false);
    assert!(!edge.admit_buffer(context, guarded, None, start));
    assert!(edge.pin_initial_root(LinkId::new(40)));
    assert!(!edge.pin_initial_root(LinkId::new(41)));
    for invalid in [
        ("DATA", Some("a"), false),
        ("CLAIMSTART", Some("4725"), false),
        ("CLAIMSTART", Some("4726"), true),
    ] {
        assert!(!edge.admit_buffer(context, guarded, None, invalid));
    }
    assert!(!edge.admit_buffer(
        context,
        InitialRootCarrier::Claim,
        None,
        ("CLAIM", Some("4726"), false)
    ));
    assert!(edge.root_buffer.is_none());
    assert!(edge.admit_buffer(context, guarded, None, start));
    assert!(edge.admit_buffer(context, guarded, None, ("DATA", Some("a"), false)));
    assert!(
        edge.root_buffer
            .as_ref()
            .is_some_and(|slot| slot._backing.bytes()
                == u64::try_from(agenc_relay_client_wire::ACCOUNT_REQUEST_CHARACTERS)
                    .unwrap_or_default())
    );
    edge.release_initial_buffer(guarded.into(), false);
    assert!(edge.root_buffer.is_some());
    edge.release_initial_buffer(guarded.into(), true);
    assert!(edge.root_buffer.is_none());
    assert!(edge.transfer(guarded.into()).is_none());
    Ok(())
}
