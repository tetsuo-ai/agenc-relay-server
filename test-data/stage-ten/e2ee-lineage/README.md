# Directory stores written before the lineage rules

These files are the restore evidence of plan item G-08 for the server topic
`sdk/b-e2ee-lineage` (SDK program items B-15 and B-16, outside master #35),
recorded in [the E2EE lineage record](../../../docs/stage-10-e2ee-lineage.md).
Governing evidence: G-08 and decision D-06 (storage generation 5); the
rules they exercise are companion Sections 8.2, 8.4, 8.5, 11.6 and 14.
They support no conformance claim by themselves.

Each `.rows` file holds the durable rows that a coordinator stored for one
state, as its test harness's logical store held them: one row per line,
`<table id> <key hex> <value hex>`, the value being the plaintext persistent
record before sealing. The tests in
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/earlier_lineage.rs`
seal them into a storage fixture of this tree and restore them through the
storage reads a restart uses, and reload them into the coordinator harness
for the requests that follow.

| File | State |
| --- | --- |
| `renewed-roster.rows` | The account's root and roster published, device 7 attached and its generation-zero capability statement published, then the account's next roster under the same root, so the device's head names the replaced roster |
| `renewed-roster-expired.rows` | The same store after object expiry past every retention window, which collected the replaced roster |
| `root-pending.rows` | The account's root, roster and device 7's statement, then a continued root of generation one, its first roster not yet published |
| `rotated-continued.rows` | That rotation completed as the writing coordinator required it: the new root's roster at generation one naming the first roster, and device 7's statement continuing its counter under it |

All four were written by `eb2b0256623ba73f3886e84baa4ac594b9793369`, the
server's `main` this topic starts from.

## How the files were written

`git archive eb2b0256623ba73f3886e84baa4ac594b9793369` was extracted into a
scratch directory (not a checkout), where one test-only module was added as
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/g08_lineage.rs`
and declared with `mod g08_lineage;` at the end of `tests/sequence.rs`; no
other file changed. The module ran with that tree's own lockfile and
toolchain:

```sh
G08_OUT=<directory> cargo nextest run -p agenc-relay-runtime --lib \
  --all-features --locked --run-ignored only -E 'test(write_g08_lineage_fixtures)'
```

The output is deterministic: two runs wrote byte-identical files. The
module:

```rust
//! Test-only generator of the G-08 restore fixtures of the e2ee lineage
//! topic: writes the durable rows this coordinator holds for each state, one
//! row per line, `<table> <key hex> <value hex>`, in the harness's store
//! order. `G08_OUT` names the output directory.

use super::*;
use crate::e2ee::coordinator::tests::{DEVICE_ID, ROOT_SEED, support};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::objects::identity::{ArcDeviceCapabilities, ArcDeviceRoster, ArcRootIdentity};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn dump(harness: &Harness, name: &str) -> TestResult {
    let dir = std::env::var("G08_OUT")?;
    let mut text = String::new();
    for write in &harness.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            return Err("a delete in the logical store".into());
        };
        let _ = writeln!(
            text,
            "{} {} {}",
            *table as u16,
            hex(key.as_bytes()),
            hex(plaintext)
        );
    }
    std::fs::write(format!("{dir}/{name}.rows"), text)?;
    Ok(())
}

/// Publishes `value` as the payload of `op`.
fn publish(
    harness: &mut Harness,
    op: Op,
    params: &[u8],
    kind: ArcWireObjectKind,
    value: &impl TlsEncode,
) -> TestResult {
    let bytes = wire(kind, value)?;
    ok(harness.run(op, params, Some(&bytes))?)?;
    Ok(())
}

/// The account's root and roster published, device 7 attached and its
/// generation-zero capability statement published.
fn provisioned() -> TestResult<(Harness, ArcDeviceCapabilities)> {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let first = support::capabilities(
        DEVICE,
        &harness.principal.roster,
        0,
        [0; 32],
        (100, 200),
        vec![1, 3],
    )?;
    publish(
        &mut harness,
        Op::PublishCapabilities,
        &DEVICE_ID,
        ArcWireObjectKind::DeviceCapabilities,
        &first,
    )?;
    Ok((harness, first))
}

/// A roster of `generation` under `root` (signed by the key of `seed`)
/// naming `previous`, keeping device 7 certified for `target`.
fn roster_under(
    seed: u8,
    root: &ArcRootIdentity,
    generation: u64,
    previous: [u8; 32],
    target: u64,
) -> TestResult<ArcDeviceRoster> {
    let secret = support::key(seed);
    let device = support::DeviceSpec {
        target_roster_generation: target,
        ..support::DeviceSpec::new(DEVICE)
    };
    Ok(support::roster(
        &secret,
        root,
        generation,
        previous,
        (100, 100 + 6 * 24 * 3600),
        vec![support::certificate(&secret, root, &device)?],
        Vec::new(),
    )?)
}

#[test]
#[ignore = "writes the G-08 fixtures of sdk/b-e2ee-lineage to G08_OUT"]
fn write_g08_lineage_fixtures() -> TestResult {
    // The account renews its roster under the same root after device 7
    // published its statement naming the first roster.
    let (mut harness, _) = provisioned()?;
    let first_roster = harness.principal.roster.clone();
    let renewed = roster_under(
        ROOT_SEED,
        &harness.principal.root,
        1,
        support::roster_id(&first_roster)?,
        0,
    )?;
    publish(
        &mut harness,
        Op::PublishRoster,
        &[],
        ArcWireObjectKind::DeviceRoster,
        &renewed,
    )?;
    dump(&harness, "renewed-roster")?;
    // The same store after object expiry past every retention window.
    super::retention::expire(&mut harness, super::retention::PAST_EVERY_WINDOW)?;
    dump(&harness, "renewed-roster-expired")?;
    // The account publishes a continued root and not yet its roster.
    let (mut harness, first) = provisioned()?;
    let continued = support::root(
        &support::key(ROOT_SEED + 1),
        &harness.account,
        1,
        (0, 2_000_000),
        Some((&harness.principal.root_secret, &harness.principal.root)),
    )?;
    publish(
        &mut harness,
        Op::PublishIdentity,
        &[],
        ArcWireObjectKind::RootIdentity,
        &continued,
    )?;
    dump(&harness, "root-pending")?;
    // The rotation completes with the counters this coordinator admits: the
    // new root's roster at generation one naming the first roster, and the
    // device's statement continuing its counter under it.
    let first_roster = harness.principal.roster.clone();
    let rotated = roster_under(
        ROOT_SEED + 1,
        &continued,
        1,
        support::roster_id(&first_roster)?,
        1,
    )?;
    publish(
        &mut harness,
        Op::PublishRoster,
        &[],
        ArcWireObjectKind::DeviceRoster,
        &rotated,
    )?;
    let next = support::capabilities(
        DEVICE,
        &rotated,
        1,
        semantic_id_of(SemanticHashDomain::CapabilityId, &first.tbs)?,
        (100, 200),
        vec![1, 3],
    )?;
    publish(
        &mut harness,
        Op::PublishCapabilities,
        &DEVICE_ID,
        ArcWireObjectKind::DeviceCapabilities,
        &next,
    )?;
    dump(&harness, "rotated-continued")?;
    Ok(())
}
```
