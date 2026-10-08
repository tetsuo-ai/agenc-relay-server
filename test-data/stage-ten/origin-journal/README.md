# Edge origin rows written before the origin journal rule

These files are the restore evidence of plan item G-08 for the server topic
`sdk/b-origin-journal` (decision D-41, SDK program, outside master #35),
recorded in [the origin journal record](../../../docs/stage-10-origin-journal.md).
Governing evidence: G-08 and decision D-06 (storage generation 5); the
rules they exercise are Architecture Sections 20.5 and 20.7. They support
no conformance claim by themselves.

Each `.rows` file holds the `federation_origin` rows that an edge's journal
made durable for one state, one row per line, `<table id> <key hex> <value
hex>`, the value being the plaintext persistent record before sealing, in
key order. The tests in
`crates/agenc-relay-runtime/src/federation/edge/tests/origin_deletion/stored_rows.rs`
seal them into a storage fixture of this tree and restore an edge from them
through the storage reads a restart uses.

| File | Written by | State |
| --- | --- | --- |
| `deleted-unsent-update.rows` | `4313f328a7953d9e0b85c8694edf1bd771149838` (`main` before the topic) | One connection's origin: generation zero acknowledged after three requests, its session bound, which queues the update to generation one, and the connection ended while that update waited for its journal write, so no link carried it. Its rows: generation zero's, as the connection's admission wrote it, and generation one's, the update deleted at sequence zero with its deletion pending. |
| `live-pending-update.rows` | `4313f328a7953d9e0b85c8694edf1bd771149838` | The same origin with the update's row written and the connection still open, as an edge that stops without deleting it leaves it: generation zero's row and generation one's, the update live at sequence zero. |

Release candidate 3 (`70c832c487e5590b892336f538d97769d867513e`) writes the
same rows for these states: its edge `journal.rs` differs from the one at
`4313f328` only by two struct-field initialisers (`update_sent` of a
restored origin and `message_echoes` of a restored request), neither of
which the origin row's content or key reads.

## How the files were written

`git archive 4313f328a7953d9e0b85c8694edf1bd771149838` was extracted into a
scratch directory (not a checkout), where one test-only module was added as
`crates/agenc-relay-runtime/src/federation/edge/tests/origin_deletion_g08.rs`
and declared at the end of `tests/origin_deletion.rs` with
`#[path = "origin_deletion_g08.rs"] mod g08_origin_journal;`; no other file
changed. The module ran with that tree's own lockfile and toolchain:

```sh
G08_OUT=<directory> cargo nextest run -p agenc-relay-runtime --lib \
  --all-features --locked --run-ignored only \
  -E 'test(write_g08_origin_journal_fixtures)'
```

The output is deterministic: separate runs wrote byte-identical files. The
module:

```rust
//! Test-only generator of the G-08 restore fixtures of the origin journal
//! topic: writes the durable origin rows this edge's journal holds for each
//! state, one row per line, `<table> <key hex> <value hex>`, in key order.
//! `G08_OUT` names the output directory.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;

/// Every row the journal made durable so far, keyed by table and key.
type Store = BTreeMap<(u16, Vec<u8>), Vec<u8>>;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Commits the edge's staged batches through the fixture's storage, as
/// `commit_edge_batches` does, recording every row each batch writes.
async fn commit_recording(
    edge: &mut EdgeFederation,
    fixture: &mut StateCoreFixture,
    store: &mut Store,
) -> TestResult {
    for _ in 0..16 {
        if edge.commit.is_none() {
            return Ok(());
        }
        for write in fixture.context_mut()?.staged_rows_for_test()? {
            match write {
                Write::Put {
                    table,
                    key,
                    plaintext,
                } => {
                    store.insert((table as u16, key.as_bytes().to_vec()), plaintext.to_vec());
                }
                Write::Delete { table, key } => {
                    store.remove(&(table as u16, key.as_bytes().to_vec()));
                }
            }
        }
        fixture.commit_staged_batch().await?;
        let _completions = edge.batch_applied(fixture.context_mut()?);
    }
    Err("edge checkpoint continuation did not settle".into())
}

fn dump(store: &Store, name: &str) -> TestResult {
    let dir = std::env::var("G08_OUT")?;
    let mut text = String::new();
    for ((table, key), value) in store {
        if *table == agenc_relay_storage::TableId::FederationOrigin as u16 {
            let _ = writeln!(text, "{table} {} {}", hex(key), hex(value));
        }
    }
    std::fs::write(format!("{dir}/{name}.rows"), text)?;
    Ok(())
}

/// The `bound` fixture of the origin deletion tests, recording every row:
/// an active edge whose connection's generation-zero declaration was
/// acknowledged after `EXECUTED` requests ran under it, and whose session
/// is now bound, queueing the update.
async fn bound_recording(
    fixture: &mut StateCoreFixture,
    connection: ConnectionGeneration,
    store: &mut Store,
) -> TestResult<(EdgeFederation, LinkQueue)> {
    let mut edge = resync_edge();
    let queue = resync_snapshot_link(&mut edge);
    edge.phase = Phase::Active;
    edge.connection_opened(fixture.context_mut()?, connection);
    commit_recording(&mut edge, fixture, store).await?;
    let origin = edge.origins.get(&connection).ok_or("origin")?;
    let acknowledgement = FederationFrame::OriginAck {
        edge_server_id: EDGE,
        server_incarnation: EDGE_INCARNATION,
        origin_id: origin.origin_id,
        generation: 0,
        object_id: Some(agenc_relay_federation_wire::FederationHash32::from_bytes(
            origin.object_id,
        )),
    };
    edge.handle_frame(fixture.context_mut()?, acknowledgement)
        .map_err(|violation| format!("the acknowledgement was refused: {violation:?}"))?;
    let origin = edge.origins.get_mut(&connection).ok_or("origin")?;
    origin.sequence = EXECUTED;
    origin.session = Some((
        SessionId::from_bytes([41; 16]),
        UserId::from_bytes([42; 16]),
    ));
    edge.session_bound(fixture.context_mut()?, connection);
    Ok((edge, queue))
}

#[tokio::test]
#[ignore = "writes the G-08 fixtures of sdk/b-origin-journal to G08_OUT"]
async fn write_g08_origin_journal_fixtures() -> TestResult {
    // The connection ends while the update its registration queued waits
    // for its journal write, so no link carried it.
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut store = Store::new();
    let connection = ConnectionGeneration::new(1);
    let (mut edge, _queue) = bound_recording(&mut fixture, connection, &mut store).await?;
    edge.connection_closed(fixture.context_mut()?, connection, "");
    commit_recording(&mut edge, &mut fixture, &mut store).await?;
    dump(&store, "deleted-unsent-update")?;
    // The edge stops with the update's row written and the connection
    // still open.
    let mut fixture = StateCoreFixture::new(entropy_script())?;
    let mut store = Store::new();
    let (mut edge, _queue) = bound_recording(&mut fixture, connection, &mut store).await?;
    commit_recording(&mut edge, &mut fixture, &mut store).await?;
    dump(&store, "live-pending-update")?;
    Ok(())
}
```
