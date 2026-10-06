//! Bounded physical deletion of expired unowned objects (companion 15, 16).
//!
//! The ENC-08 ownership accounts are the only input: an object is a
//! candidate exactly when no accepted owner names it, the batch that retired
//! its last owner recorded a trusted second, and the retention its class
//! implies has elapsed by the trusted clock the maintenance pass was
//! admitted with. No client-supplied time reaches this decision; an undated
//! or reconstructed account without a trusted acceptance second is never
//! collected, it is only retained until a later dated batch touches it.
//!
//! One pass reads a bounded page of accounts from a persisted continuation,
//! charges its work buffer, and stages the object deletions, the
//! `owner/v1/` retirements and the advanced `object-expiry/v1` progress row
//! in the same batch, so a restart resumes at the page of the last
//! committed deletion without skipping an undeleted account or charging one
//! twice. A page that deletes nothing changes no accounting and stages no
//! batch; only the live continuation moves, so an idle store writes nothing
//! and a restart simply re-reads those pages. Every candidate is
//! revalidated against the exact account and the resident body before the
//! receipt publishes anything, so a reference accepted since the capture
//! keeps its body.

#![forbid(unsafe_code)]

use super::{CompanionCoordinator, CompanionFault, CompanionState, owners};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::limits::{
    ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS, SEQUENCER_RECORD_RETENTION_SECONDS,
    WELCOME_RETENTION_SECONDS,
};
use agenc_relay_e2ee::object::ArcWireObjectKind;
use agenc_relay_storage::e2ee_records::{
    EXPIRY_PROGRESS_ROW_KIND, ObjectExpiryProgressRow, ObjectOwnerRow, RetentionClass,
    UNDATED_SECOND, object_key,
};
use agenc_relay_storage::{PersistentRecordValue, TableId};

/// Ownership accounts one pass may examine.
pub(crate) const MAX_EXPIRY_ACCOUNTS: usize = 64;
/// Object bytes one pass may delete; a candidate that would cross it stops
/// the pass before the cursor names it, so the next pass sees it again.
pub(crate) const MAX_EXPIRY_BYTES: u64 = 4 * 1024 * 1024;

/// The durable continuation of the collector, mirrored from the
/// `object-expiry/v1` row and advanced only by a committed batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Progress {
    /// The last account a committed pass examined; the next pass resumes
    /// strictly after it.
    pub(crate) cursor: Option<[u8; 32]>,
    /// Sweeps that reached the last account and wrapped, as of the last
    /// committed deletion.
    pub(crate) passes: u64,
    /// Objects deleted since the store was created.
    pub(crate) deleted_objects: u64,
    /// Object bytes deleted since the store was created.
    pub(crate) deleted_bytes: u64,
}

impl Progress {
    /// The progress this row records.
    pub(crate) const fn from_row(row: ObjectExpiryProgressRow) -> Self {
        Self {
            cursor: row.cursor,
            passes: row.passes,
            deleted_objects: row.deleted_objects,
            deleted_bytes: row.deleted_bytes,
        }
    }

    const fn row(self) -> ObjectExpiryProgressRow {
        ObjectExpiryProgressRow {
            cursor: self.cursor,
            passes: self.passes,
            deleted_objects: self.deleted_objects,
            deleted_bytes: self.deleted_bytes,
        }
    }

    /// The progress the batch of `scan` leaves behind. A pass that examined
    /// fewer accounts than its page and was not stopped by the byte budget
    /// reached the end of the accounts and wraps.
    fn advanced(self, scan: &Scan) -> Self {
        let wrapped = !scan.halted && scan.scanned < MAX_EXPIRY_ACCOUNTS;
        let deleted = u64::try_from(scan.changes.len()).unwrap_or(u64::MAX);
        Self {
            cursor: if wrapped { None } else { scan.cursor },
            passes: self.passes.saturating_add(u64::from(wrapped)),
            deleted_objects: self.deleted_objects.saturating_add(deleted),
            deleted_bytes: self.deleted_bytes.saturating_add(scan.bytes),
        }
    }
}

/// The retention an unowned object of `class` serves after the trusted
/// second its last owner retired (companion 15 and 16). A security proof
/// takes the longest published window: the accounts prove only that no row
/// names it, which is weaker evidence than the final close
/// `SECURITY_PROOF_RETENTION` measures from.
const fn retention_seconds(class: RetentionClass) -> u64 {
    match class {
        RetentionClass::SecurityProof | RetentionClass::Ordinary => {
            SEQUENCER_RECORD_RETENTION_SECONDS
        }
        RetentionClass::Mailbox => WELCOME_RETENTION_SECONDS,
        RetentionClass::Replay => ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS,
    }
}

/// One object this pass deletes, with the exact account it was chosen from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Change {
    id: [u8; 32],
    kind: u8,
    size: u64,
    retention: RetentionClass,
    accepted_at: u64,
    retired_at: u64,
}

impl Change {
    /// The candidate `account` makes, or `None` when any owner still names
    /// the object, the retirement or acceptance is undated, or the trusted
    /// retention has not elapsed at `now`.
    fn expired(id: &[u8; 32], account: &owners::Account, now: u64) -> Option<Self> {
        account.owners.is_empty().then_some(())?;
        let dated = |at: u64| (at != 0 && at != UNDATED_SECOND).then_some(at);
        let accepted_at = dated(account.accepted_at)?;
        let retired_at = account.retired_at.and_then(dated)?;
        let due = retired_at.checked_add(retention_seconds(account.retention))?;
        (now >= due).then_some(Self {
            id: *id,
            kind: account.kind,
            size: account.size,
            retention: account.retention,
            accepted_at,
            retired_at,
        })
    }

    /// Whether the account still describes exactly the object this pass
    /// chose and still has no accepted owner. A reference accepted since the
    /// capture reinstates an owner and clears the retirement, so the body
    /// stays and this pass refuses its own receipt.
    fn matches(&self, state: &CompanionState) -> bool {
        let Some(account) = state.owners.account(&self.id) else {
            return false;
        };
        let same = (
            account.owners.is_empty(),
            account.retired_at,
            account.kind,
            account.size,
            account.retention,
            account.accepted_at,
        ) == (
            true,
            Some(self.retired_at),
            self.kind,
            self.size,
            self.retention,
            self.accepted_at,
        );
        same && state
            .objects
            .get(&self.id)
            .is_none_or(|bytes| self.identifies(bytes))
    }

    /// Whether a resident body is byte-for-byte the object named: its
    /// content identifier and its complete accounted length.
    fn identifies(&self, bytes: &[u8]) -> bool {
        u64::try_from(bytes.len()) == Ok(self.size)
            && *ObjectId::compute(bytes).as_bytes() == self.id
    }
}

/// The bounded page one pass examined.
struct Scan {
    changes: Vec<Change>,
    bytes: u64,
    cursor: Option<[u8; 32]>,
    scanned: usize,
    halted: bool,
}

impl Scan {
    fn new(cursor: Option<[u8; 32]>) -> Self {
        Self {
            changes: Vec::with_capacity(MAX_EXPIRY_ACCOUNTS),
            bytes: 0,
            cursor,
            scanned: 0,
            halted: false,
        }
    }

    /// Admits one account. A false result stops the pass before the cursor
    /// names `id`, so the byte budget never hides an undeleted account.
    fn admit(&mut self, id: &[u8; 32], account: &owners::Account, now: u64) -> bool {
        if let Some(change) = Change::expired(id, account, now) {
            let Some(bytes) = self
                .bytes
                .checked_add(change.size)
                .filter(|total| *total <= MAX_EXPIRY_BYTES)
            else {
                self.halted = true;
                return false;
            };
            self.bytes = bytes;
            self.changes.push(change);
        }
        self.scanned = self.scanned.saturating_add(1);
        self.cursor = Some(*id);
        true
    }
}

/// One captured pass, owned until its exact storage receipt.
pub(crate) struct Prepared {
    changes: Vec<Change>,
    next: Progress,
    _backing: MemoryPermit,
}

impl Prepared {
    /// Chooses the next bounded page from the persisted continuation. The
    /// work buffer is charged before any account is read.
    pub(crate) fn capture(
        executor: &CompanionCoordinator,
        progress: Progress,
        now: u64,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let reserved = backing
            .reserve(MAX_EXPIRY_ACCOUNTS * 256 + 8192)
            .map_err(|_| CompanionFault::Ceiling)?;
        let mut scan = Scan::new(progress.cursor);
        for (id, account) in executor
            .state
            .owners
            .after(progress.cursor)
            .take(MAX_EXPIRY_ACCOUNTS)
        {
            if !scan.admit(id, account, now) {
                break;
            }
        }
        // Nothing is staged from a snapshot alone: every candidate is
        // rechecked against the live accounts before the receipt applies.
        (scan
            .changes
            .iter()
            .all(|change| change.matches(&executor.state)))
        .then_some(())
        .ok_or(CompanionFault::Storage)?;
        Ok(Self {
            next: progress.advanced(&scan),
            changes: scan.changes,
            _backing: reserved,
        })
    }

    /// Whether this pass deletes nothing; the progress row still advances.
    pub(crate) fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The continuation a commit installs.
    #[cfg(test)]
    pub(crate) const fn next_progress(&self) -> Progress {
        self.next
    }

    /// Whether this pass reached the last account and wrapped.
    pub(crate) fn completes_cycle(&self) -> bool {
        self.next.cursor.is_none()
    }

    /// The object bodies, their ownership accounts and the advanced
    /// continuation, as one batch.
    pub(crate) fn writes(&self, revision: u64) -> Result<Vec<Write>, crate::RuntimeError> {
        let mut writes = Vec::with_capacity(self.changes.len() * 2 + 1);
        for change in &self.changes {
            writes.push(Write::delete(TableId::E2eeObject, object_key(&change.id)?)?);
            writes.push(Write::delete(
                TableId::E2eeState,
                ObjectOwnerRow::key(&change.id)?,
            )?);
        }
        writes.push(progress_write(self.next, revision)?);
        Ok(writes)
    }

    /// Publishes the committed pass: the accounts and their charges drop,
    /// the resident bodies and their backing are released, and the
    /// continuation advances. A candidate that no longer matches refuses the
    /// receipt rather than publishing a deletion the batch did not make.
    pub(crate) fn apply(&self, executor: &mut CompanionCoordinator) -> Result<(), CompanionFault> {
        self.changes
            .iter()
            .all(|change| change.matches(&executor.state))
            .then_some(())
            .ok_or(CompanionFault::Storage)?;
        for change in &self.changes {
            release(&mut executor.state, change);
        }
        owners::sync_charges(&mut executor.state);
        executor.state.object_expiry = self.next;
        Ok(())
    }
}

/// Drops one committed object's account, charge, resident body and backing.
fn release(state: &mut CompanionState, change: &Change) {
    state.owners.remove(&change.id);
    let Some(bytes) = state.objects.remove(&change.id) else {
        return;
    };
    state.object_memory.remove(&change.id);
    state.object_bytes = state.object_bytes.saturating_sub(bytes.len());
    if change.kind == ArcWireObjectKind::DeviceRoster.value() {
        super::roster_snapshots::forget(state, &change.id, &bytes);
    }
}

/// The `object-expiry/v1` row this pass stages at the batch revision.
fn progress_write(progress: Progress, revision: u64) -> Result<Write, crate::RuntimeError> {
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        EXPIRY_PROGRESS_ROW_KIND,
        revision,
        0,
        None,
        Vec::new(),
        progress.row().encode()?,
    )?;
    Write::put(
        TableId::E2eeState,
        ObjectExpiryProgressRow::key()?,
        value.encode()?,
    )
}
