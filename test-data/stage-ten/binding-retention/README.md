# Encrypted stores written before the binding-retention rules

These files are the restore evidence of plan item G-08 for the server topic
`sdk/b-binding-retention` (decision D-39, SDK program, outside master #35),
recorded in [the binding retention record](../../../docs/stage-10-binding-retention.md).
Governing evidence: G-08 and decision D-06 (storage generation 5); the
rules they exercise are companion Sections 11.5, 11.7, 13.7.3, 13.8 and 15.
They support no conformance claim by themselves.

Each `.rows` file holds the durable rows that a coordinator stored for one
state, as its test harness's logical store held them: one row per line,
`<table id> <key hex> <value hex>`, the value being the plaintext persistent
record before sealing. The tests in
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/earlier_stores.rs`
seal them into a storage fixture of this tree and restore them through the
storage reads a restart uses, and reload them into the coordinator harness
for the requests that follow; they also remove a route's binding package
rows from a store to restore a store that lacks them.

| File | Written by | State |
| --- | --- | --- |
| `bound-channel.rows` | `70c832c487e5590b892336f538d97769d867513e` (release candidate 3) | `#room` bound, its two policies and the attached device's leaf proof published, and its bootstrap activation finalized |
| `council-roster-replaced.rows` | `70c832c487e5590b892336f538d97769d867513e` | `#room` bound by an account with two council devices, which then publishes a roster without the second one |
| `installed-successor.rows` | `c262ce1606417f356f8d183cee9d98b15a192a7d` (`main` after the merge of the P-04 topic) | `#room` bound, its ReInit Commit finalized, its attempt admitted and activated, and the successor installed by the activation |

## How the files were written

`git archive <commit>` of each commit was extracted into a scratch directory
(not a checkout), where one test-only module was added and declared; no
other file of either commit changed (`diff -rq` against a fresh export). The
module ran with that tree's own lockfile and toolchain:

```sh
G08_OUT=<directory> cargo nextest run -p agenc-relay-runtime --lib \
  --all-features --locked --run-ignored only -E 'test(<name>)'
```

The output is deterministic: separate runs wrote byte-identical files.

For `70c832c`, the module is
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/g08_retention.rs`,
declared with `mod g08_retention;` in `tests/sequence.rs`, run with
`test(write_g08_retention_fixtures)`. For `c262ce1`, it is
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/reinit/successor/g08_retention.rs`,
declared with `mod g08_retention;` in `tests/sequence/reinit/successor.rs`,
run with `test(write_g08_retention_successor_fixtures)`. Both modules start
with the same lines:

```rust
//! Test-only generator of the G-08 restore fixtures of the
//! binding-retention topic: writes the durable rows this coordinator holds
//! for each state, one row per line, `<table> <key hex> <value hex>`, in
//! the harness's store order. `G08_OUT` names the output directory.

use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
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
```

The `70c832c` module continues:

```rust
/// The bootstrap activation of a bound conversation (epoch zero).
fn activate_bootstrap(harness: &mut Harness, conversation: [u8; 32]) -> TestResult {
    use super::recovery_pending::close_authorization::{finalization_bytes, open_finalization};
    let opened = open_finalization(harness, conversation, 0)?;
    let (bytes, _) = finalization_bytes(harness, &opened, None, &[DEVICE])?;
    ok(harness.run(Op::SubmitFinalization, &conversation, Some(&bytes))?)?;
    Ok(())
}

#[test]
#[ignore = "writes the G-08 fixtures of sdk/b-binding-retention to G08_OUT"]
fn write_g08_retention_fixtures() -> TestResult {
    // A bound #room after its bootstrap activation.
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    activate_bootstrap(&mut harness, conversation)?;
    dump(&harness, "bound-channel")?;
    // A bound #room whose account then publishes a roster without its
    // second council device.
    let mut harness = Harness::with_devices(&[DEVICE, DEVICE + 1])?;
    harness.bind_channel()?;
    super::super::retire_council_device(&mut harness, [DEVICE + 1; 16])?;
    dump(&harness, "council-roster-replaced")?;
    Ok(())
}
```

The `c262ce1` module continues:

```rust
#[test]
#[ignore = "writes the G-08 fixtures of sdk/b-binding-retention to G08_OUT"]
fn write_g08_retention_successor_fixtures() -> TestResult {
    // A ReInit whose activation installed the successor of the bound #room.
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    dump(&fixture.harness, "installed-successor")?;
    Ok(())
}
```
