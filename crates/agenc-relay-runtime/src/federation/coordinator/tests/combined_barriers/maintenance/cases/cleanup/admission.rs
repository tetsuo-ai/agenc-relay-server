//! No prefix deletion can be staged from malformed or misordered sealed metadata.
#![forbid(unsafe_code)]

use super::*;

#[tokio::test]
async fn reversed_or_truncated_empty_cleanup_pages_fail_before_staging_any_delete() -> TestResult {
    for reversed in [false, true] {
        let mut fixture = Box::pin(logically_expired()).await?;
        retry(&mut fixture)?;
        let owner = fixture.core.next_storage_read().await?;
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, owner);
        let mut page = fixture.core.next_storage_read().await?;
        let rows = page.result.as_mut().map_err(|e| format!("page: {e:?}"))?;
        assert_eq!(rows.records.len(), 2);
        if reversed {
            rows.records.reverse();
        } else {
            rows.records.clear();
            rows.truncated = true;
        }
        fixture
            .coordinator
            .storage_read_completed(fixture.core.context_mut()?, page);
        assert!(!fixture.coordinator.loaded());
        assert!(fixture.coordinator.pending.is_none());
        assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
        assert_eq!(physical_rows(&mut fixture, false).await?, 2);
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
    }
    Ok(())
}
