//! A companion origin declaration mirrors the base connection exactly: the
//! generation, connection identity and nonce the base origin carries.

#![forbid(unsafe_code)]

use super::*;

#[test]
fn an_origin_declaration_must_mirror_the_base_generation_connection_and_nonce() -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (honest, _) = origin_object(0, [0; 32], None, None)?;
    let mut later_generation = honest.clone();
    later_generation.origin_generation = 1;
    let mut other_connection = honest.clone();
    other_connection.connection_id = [9; 16];
    let mut other_nonce = honest.clone();
    other_nonce.connection_nonce = [9; 32];
    for (name, origin) in [
        ("a later generation", later_generation),
        ("another connection", other_connection),
        ("another nonce", other_nonce),
    ] {
        let generation = origin.origin_generation;
        let bytes = wire(ArcWireObjectKind::FederationOrigin, &origin)?;
        assert_eq!(
            sync.declare(false, generation, &bytes).err(),
            Some(CompanionFault::Protocol),
            "{name}"
        );
        assert!(
            sync.harness.coordinator.state.origins.is_empty(),
            "{name} leaves no origin"
        );
    }
    let bytes = wire(ArcWireObjectKind::FederationOrigin, &honest)?;
    assert_eq!(frames(&sync.declare(false, 0, &bytes)?)?.len(), 1);
    assert_eq!(sync.harness.coordinator.state.origins.len(), 1);
    Ok(())
}
