#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_storage::history_records::{
    HistoryControlRecord, HistoryCoordinatorResultRecord, HistoryEdgeRequestRecord,
    HistoryMessageRecord,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(record) = HistoryMessageRecord::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = HistoryControlRecord::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = HistoryCoordinatorResultRecord::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
    if let Ok(record) = HistoryEdgeRequestRecord::decode(data) {
        assert_eq!(record.encode().ok().as_deref(), Some(data));
    }
});
