//! A newly encrypted projection revokes a previously authorized transient page.
#![forbid(unsafe_code)]

use super::*;

fn install_encrypted_projection(edge: &mut EdgeFederation) -> TestResult {
    let entries = edge
        .replica
        .entries()
        .map(|mut record| {
            if let ProjectionRecord::ChannelDetail(channel) = &mut record {
                channel.content_policy = ContentPolicy::E2eeBound;
                channel.history = HistoryPolicy::Off;
                channel.e2ee_route_binding = Some([23; 32]);
                channel.channel_revision = Revision::new(21)?;
            }
            Ok(record)
        })
        .collect::<TestResult<Vec<_>>>()?;
    edge.replica.install(2, entries)?;
    Ok(())
}

#[tokio::test]
async fn encrypted_projection_revokes_saved_history_before_preparation_and_delivery() -> TestResult
{
    for before_prepare in [true, false] {
        let (mut fixture, mut edge, sink, page) = fixture()?;
        let unrelated = seed_session(fixture.context_mut()?, 2, "other-reader", None)?;
        let unrelated_sink =
            bind_live_session(fixture.context_mut()?, 2, unrelated, capabilities()?, true)?;
        let record = edge.history.records.get(&ID).ok_or("record")?.clone();
        if before_prepare {
            install_encrypted_projection(&mut edge)?;
        }
        let mut prepared = prepare_page(
            &edge,
            fixture.context_mut()?,
            ConnectionGeneration::new(1),
            record,
            FederationHash32::from_bytes([14; 32]),
            &page,
        )
        .map_err(|error| format!("prepare: {error:?}"))?;
        if !before_prepare {
            prepared.record.phase = HistoryEdgePhase::Rendered;
            install_encrypted_projection(&mut edge)?;
        }
        assert!(sink.lines().is_empty());
        assert!(edge.pending.contains_key(&ID));
        committed(&mut edge, fixture.context_mut()?, prepared);
        assert_eq!(edge.phase, Phase::Active);
        assert!(!edge.pending.contains_key(&ID));
        let lines = sink.lines();
        assert_eq!(lines.len(), 1);
        assert!(lines.first().ok_or("failure")?.contains("QUERY_EXPIRED"));
        assert!(!lines.iter().any(|line| line.contains("history must wait")));
        assert!(unrelated_sink.lines().is_empty());
        assert!(
            fixture
                .context_mut()?
                .sessions()
                .sink_for_generation(ConnectionGeneration::new(2))
                .is_some()
        );
    }
    Ok(())
}
