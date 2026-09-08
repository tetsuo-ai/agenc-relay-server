//! Every scope field and the retained ACK-time watermark remain authoritative.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{DeliveryScope, DeliveryScopeFields};

#[test]
fn each_historical_scope_field_is_required_for_range_and_owner_admission() -> TestResult {
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 0, 1)?;
    let scope = f.current.scope();
    let original = DeliveryScopeFields {
        network_id: scope.network_id(),
        coordinator_server_id: scope.coordinator_server_id(),
        coordinator_incarnation: scope.coordinator_incarnation(),
        coordinator_recovery_epoch: scope.coordinator_recovery_epoch(),
        target_server_id: scope.target_server_id(),
        target_incarnation: scope.target_incarnation(),
        covered_base_client_resync_epoch: scope.covered_base_client_resync_epoch(),
    };
    for fields in [
        DeliveryScopeFields {
            network_id: [81; 32],
            ..original
        },
        DeliveryScopeFields {
            coordinator_server_id: [82; 16],
            ..original
        },
        DeliveryScopeFields {
            coordinator_incarnation: [83; 16],
            ..original
        },
        DeliveryScopeFields {
            coordinator_recovery_epoch: [84; 16],
            ..original
        },
        DeliveryScopeFields {
            target_server_id: [85; 16],
            ..original
        },
        DeliveryScopeFields {
            target_incarnation: [86; 16],
            ..original
        },
        DeliveryScopeFields {
            covered_base_client_resync_epoch: 87,
            ..original
        },
    ] {
        let changed = DeliveryScope::new(fields)?;
        assert_ne!(changed, *scope);
        let range = AckRange::new(AckRangeFields {
            scope: changed,
            ..*f.range(0, 0)?.fields()
        })?;
        assert!(f.inventory()?.admit_range(range).is_err());
        let replay = ReplayOwner::new(ReplayOwnerFields {
            scope: changed,
            ..*f.replay.fields()
        })?;
        assert!(Inventory::new(f.current.clone(), replay).is_err());
    }
    Ok(())
}

#[test]
fn a_known_ack_time_cannot_exceed_or_replace_a_missing_owner_watermark() -> TestResult {
    let f = Fixture::new(0, LastAcknowledged::BeforeFirst, 0, 1)?;
    for time in [None, Some(199)] {
        let replay = ReplayOwner::new(ReplayOwnerFields {
            trusted_unix_seconds: time,
            ..*f.replay.fields()
        })?;
        let mut scan = Inventory::new(f.current.clone(), replay)?;
        scan.admit_range(f.range(0, 0)?)?;
        assert!(
            scan.observe(f.row(0, Acknowledgement::Unacknowledged)?)
                .is_err()
        );
        assert!(scan.finish().is_err());
    }
    Ok(())
}
