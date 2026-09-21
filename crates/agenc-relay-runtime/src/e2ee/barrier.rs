//! The cross-profile barrier as the edge assembles it (architecture 20.8):
//! one target-specific mutation delivers `B` base parts followed by `E`
//! companion parts under one mutation identity, each part is staged as an
//! immutable row as it arrives, and the complete set applies in one
//! transaction that advances both cursors and writes one receipt.
//!
//! This module holds the pure assembly rules; the edge owner stages rows,
//! applies events, and sends the two final acknowledgements.

use std::collections::BTreeMap;

use agenc_relay_storage::e2ee_records::barrier::{
    BarrierIdentity, BarrierPart, BarrierReceipt, BarrierReceiptEntry, BarrierStage,
    CrossProfileStream, MAX_PART_COUNT, MIN_PART_COUNT,
};

/// The largest aggregate of event plus payload bytes one barrier may carry.
pub const MAX_AGGREGATE_BYTES: u64 = 16 * 1024 * 1024;

/// Why a part or the assembled set was refused; every arm is fatal for the
/// link that delivered it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierFault {
    /// The tuple names a count outside `2..=2048` or an index at or past it.
    Tuple,
    /// The part names another identity than the open barrier.
    Identity,
    /// A second barrier opened before the first finished.
    SecondBarrier,
    /// The same index arrived again with different bytes.
    Conflict,
    /// The aggregate bytes crossed the ceiling.
    Aggregate,
    /// The streams are not contiguous or the indices do not partition.
    Partition,
    /// A stream position does not follow the applied cursor.
    Cursor,
}

impl std::fmt::Display for BarrierFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Tuple => "cross-profile tuple out of range",
            Self::Identity => "part names another barrier",
            Self::SecondBarrier => "second barrier before the first finished",
            Self::Conflict => "repeated part index with different bytes",
            Self::Aggregate => "barrier aggregate bytes over the ceiling",
            Self::Partition => "barrier parts do not partition the streams",
            Self::Cursor => "barrier stream does not continue the cursor",
        })
    }
}

impl std::error::Error for BarrierFault {}

/// The delivery position a stream must continue from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamCursor {
    /// The delivery generation.
    pub generation: u64,
    /// The next expected delivery sequence.
    pub next_sequence: u64,
}

/// What one staged part did to the assembly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Staged {
    /// A new part was recorded; `complete` says whether the set is full.
    Recorded {
        /// Whether every part is now present.
        complete: bool,
    },
    /// The identical part arrived again; nothing changed.
    Duplicate,
}

/// The open barrier: its head, its immutable parts, and the base and
/// companion positions the parts occupy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BarrierAssembly {
    stage: BarrierStage,
    parts: BTreeMap<u16, BarrierPart>,
}

impl BarrierAssembly {
    /// Opens a barrier for `identity`; the part count must be in range.
    pub fn open(identity: BarrierIdentity) -> Result<Self, BarrierFault> {
        if !(MIN_PART_COUNT..=MAX_PART_COUNT).contains(&identity.part_count) {
            return Err(BarrierFault::Tuple);
        }
        Ok(Self {
            stage: BarrierStage::empty(identity),
            parts: BTreeMap::new(),
        })
    }

    /// Restores a barrier from its durable head and parts after a restart.
    pub fn restore(stage: BarrierStage, parts: Vec<BarrierPart>) -> Result<Self, BarrierFault> {
        let mut assembly = Self {
            stage: BarrierStage::empty(stage.identity),
            parts: BTreeMap::new(),
        };
        for part in parts {
            assembly.stage(part)?;
        }
        if assembly.stage != stage {
            return Err(BarrierFault::Identity);
        }
        Ok(assembly)
    }

    /// The identity.
    #[must_use]
    pub const fn identity(&self) -> &BarrierIdentity {
        &self.stage.identity
    }

    /// The head as it must be written after the last staged part.
    #[must_use]
    pub const fn head(&self) -> &BarrierStage {
        &self.stage
    }

    /// Whether every part is present.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.stage.is_complete()
    }

    /// Records one part. The same index with identical bytes is a
    /// duplicate; with different bytes it is a conflict.
    pub fn stage(&mut self, part: BarrierPart) -> Result<Staged, BarrierFault> {
        if part.identity != self.stage.identity {
            return Err(BarrierFault::Identity);
        }
        if part.part_index >= self.stage.identity.part_count {
            return Err(BarrierFault::Tuple);
        }
        if let Some(existing) = self.parts.get(&part.part_index) {
            return if *existing == part {
                Ok(Staged::Duplicate)
            } else {
                Err(BarrierFault::Conflict)
            };
        }
        let bytes = part
            .contributed_bytes()
            .map_err(|_| BarrierFault::Aggregate)?;
        if self
            .stage
            .aggregate_event_payload_bytes
            .saturating_add(bytes)
            > MAX_AGGREGATE_BYTES
        {
            return Err(BarrierFault::Aggregate);
        }
        self.stage
            .mark_received(part.part_index, bytes)
            .map_err(|_| BarrierFault::Conflict)?;
        self.parts.insert(part.part_index, part);
        Ok(Staged::Recorded {
            complete: self.stage.is_complete(),
        })
    }

    /// The parts of one stream in index order.
    #[must_use]
    pub fn stream(&self, stream: CrossProfileStream) -> Vec<&BarrierPart> {
        self.parts
            .values()
            .filter(|part| part.stream == stream)
            .collect()
    }

    /// Checks the complete set against the partition and cursor rules:
    /// base indices `0..B`, companion indices `B..count`, both nonempty,
    /// each stream contiguous from its cursor in index order.
    pub fn verify(
        &self,
        base: StreamCursor,
        companion: StreamCursor,
    ) -> Result<Partition, BarrierFault> {
        if !self.is_complete() {
            return Err(BarrierFault::Partition);
        }
        let base_parts = self.stream(CrossProfileStream::Base);
        let companion_parts = self.stream(CrossProfileStream::Companion);
        if base_parts.is_empty() || companion_parts.is_empty() {
            return Err(BarrierFault::Partition);
        }
        let base_count = u16::try_from(base_parts.len()).map_err(|_| BarrierFault::Partition)?;
        let indices_partition = base_parts
            .iter()
            .enumerate()
            .all(|(index, part)| usize::from(part.part_index) == index)
            && companion_parts.iter().enumerate().all(|(index, part)| {
                usize::from(part.part_index) == index + usize::from(base_count)
            });
        if !indices_partition {
            return Err(BarrierFault::Partition);
        }
        let base_last = contiguous(&base_parts, base)?;
        let companion_last = contiguous(&companion_parts, companion)?;
        Ok(Partition {
            base_parts: base_count,
            base_last,
            companion_last,
        })
    }

    /// The compact receipt of the applied set.
    pub fn receipt(
        &self,
        applied_storage_commit_sequence: u64,
        applied_local_state_generation: u64,
        applied_at: u64,
        retain_until: u64,
    ) -> BarrierReceipt {
        let entries: Vec<BarrierReceiptEntry> = self
            .parts
            .values()
            .map(BarrierPart::receipt_entry)
            .collect();
        BarrierReceipt {
            identity: self.stage.identity,
            applied_storage_commit_sequence,
            applied_local_state_generation,
            applied_at,
            retain_until,
            aggregate_event_payload_bytes: self.stage.aggregate_event_payload_bytes,
            entries,
        }
    }

    /// The parts in index order.
    #[must_use]
    pub fn parts(&self) -> Vec<&BarrierPart> {
        self.parts.values().collect()
    }
}

/// The verified partition of one complete barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Partition {
    /// Base parts, indices `0..base_parts`.
    pub base_parts: u16,
    /// The last base delivery position.
    pub base_last: (u64, u64, [u8; 16]),
    /// The last companion delivery position.
    pub companion_last: (u64, u64, [u8; 16]),
}

/// Checks that `parts` continue `cursor` one sequence at a time under one
/// generation; returns the last position.
fn contiguous(
    parts: &[&BarrierPart],
    cursor: StreamCursor,
) -> Result<(u64, u64, [u8; 16]), BarrierFault> {
    let mut expected = cursor.next_sequence;
    let mut last = None;
    for part in parts {
        if part.delivery_generation != cursor.generation || part.delivery_sequence != expected {
            return Err(BarrierFault::Cursor);
        }
        expected = expected.checked_add(1).ok_or(BarrierFault::Cursor)?;
        last = Some((
            part.delivery_generation,
            part.delivery_sequence,
            part.event_id,
        ));
    }
    last.ok_or(BarrierFault::Partition)
}

/// Whether a retained receipt answers a replayed part: the part must match
/// the receipt's entry at its index exactly.
#[must_use]
pub fn replay_matches(receipt: &BarrierReceipt, part: &BarrierPart) -> bool {
    receipt.identity == part.identity
        && receipt
            .entries
            .iter()
            .any(|entry| *entry == part.receipt_entry())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn identity(part_count: u16) -> BarrierIdentity {
        BarrierIdentity {
            network_id: [1; 32],
            coordinator_server_id: [2; 16],
            coordinator_server_incarnation: [3; 16],
            coordinator_recovery_epoch: [4; 16],
            target_server_id: [5; 16],
            target_server_incarnation: [6; 16],
            mutation_id: [7; 16],
            coordinator_state_generation: 9,
            part_count,
        }
    }

    fn part(
        identity: BarrierIdentity,
        stream: CrossProfileStream,
        index: u16,
        sequence: u64,
    ) -> BarrierPart {
        BarrierPart {
            identity,
            stream,
            part_index: index,
            delivery_generation: 1,
            delivery_sequence: sequence,
            event_id: [u8::try_from(index % 250).unwrap_or(0); 16],
            event_object_id: [8; 32],
            encoded_event_object: vec![9; 40],
            payload_object_id: None,
            payload_object_bytes: 0,
        }
    }

    fn cursor(next_sequence: u64) -> StreamCursor {
        StreamCursor {
            generation: 1,
            next_sequence,
        }
    }

    #[test]
    fn parts_assemble_in_any_order_and_partition_by_stream() -> TestResult {
        let identity = identity(4);
        let mut assembly = BarrierAssembly::open(identity)?;
        let first = part(identity, CrossProfileStream::Companion, 3, 11);
        let rest = [
            part(identity, CrossProfileStream::Base, 0, 5),
            part(identity, CrossProfileStream::Companion, 2, 10),
            part(identity, CrossProfileStream::Base, 1, 6),
        ];
        assert_eq!(
            assembly.stage(first.clone())?,
            Staged::Recorded { complete: false }
        );
        assert_eq!(assembly.stage(first.clone())?, Staged::Duplicate);
        let mut different = first.clone();
        different.encoded_event_object = vec![1; 40];
        assert_eq!(assembly.stage(different), Err(BarrierFault::Conflict));
        assert_eq!(
            assembly.verify(cursor(5), cursor(10)),
            Err(BarrierFault::Partition)
        );
        for part in &rest {
            assembly.stage(part.clone())?;
        }
        let parts: Vec<BarrierPart> = std::iter::once(first).chain(rest).collect();
        assert!(assembly.is_complete());
        let partition = assembly.verify(cursor(5), cursor(10))?;
        assert_eq!(partition.base_parts, 2);
        assert_eq!(partition.base_last, (1, 6, [1; 16]));
        assert_eq!(partition.companion_last, (1, 11, [3; 16]));
        // A cursor gap or another generation on either stream is fatal.
        assert_eq!(
            assembly.verify(cursor(4), cursor(10)),
            Err(BarrierFault::Cursor)
        );
        assert_eq!(
            assembly.verify(
                cursor(5),
                StreamCursor {
                    generation: 2,
                    next_sequence: 10
                }
            ),
            Err(BarrierFault::Cursor)
        );
        let receipt = assembly.receipt(1, 9, 100, 200);
        assert_eq!(receipt.entries.len(), 4);
        let companion = parts.get(2).ok_or("the third part")?;
        assert!(replay_matches(&receipt, companion));
        let mut foreign = companion.clone();
        foreign.event_id = [99; 16];
        assert!(!replay_matches(&receipt, &foreign));
        let restored = BarrierAssembly::restore(assembly.head().clone(), parts.clone())?;
        assert_eq!(restored, assembly);
        Ok(())
    }

    #[test]
    fn the_tuple_identity_and_partition_rules_are_enforced() -> TestResult {
        assert_eq!(
            BarrierAssembly::open(identity(1)).err(),
            Some(BarrierFault::Tuple)
        );
        assert_eq!(
            BarrierAssembly::open(identity(2_049)).err(),
            Some(BarrierFault::Tuple)
        );
        let identity = identity(2);
        let mut assembly = BarrierAssembly::open(identity)?;
        let mut other = identity;
        other.mutation_id = [8; 16];
        assert_eq!(
            assembly.stage(part(other, CrossProfileStream::Base, 0, 0)),
            Err(BarrierFault::Identity)
        );
        assert_eq!(
            assembly.stage(part(identity, CrossProfileStream::Base, 2, 0)),
            Err(BarrierFault::Tuple)
        );
        // Two base parts and no companion part do not partition.
        assembly.stage(part(identity, CrossProfileStream::Base, 0, 0))?;
        assembly.stage(part(identity, CrossProfileStream::Base, 1, 1))?;
        assert_eq!(
            assembly.verify(cursor(0), cursor(0)),
            Err(BarrierFault::Partition)
        );
        // Companion before base does not partition either.
        let mut swapped = BarrierAssembly::open(identity)?;
        swapped.stage(part(identity, CrossProfileStream::Companion, 0, 0))?;
        swapped.stage(part(identity, CrossProfileStream::Base, 1, 0))?;
        assert_eq!(
            swapped.verify(cursor(0), cursor(0)),
            Err(BarrierFault::Partition)
        );
        Ok(())
    }

    #[test]
    fn the_aggregate_ceiling_and_the_largest_part_count_hold() -> TestResult {
        let identity = identity(MAX_PART_COUNT);
        let mut assembly = BarrierAssembly::open(identity)?;
        for index in 0..MAX_PART_COUNT {
            let stream = if index < 2 {
                CrossProfileStream::Base
            } else {
                CrossProfileStream::Companion
            };
            let sequence = if index < 2 {
                u64::from(index)
            } else {
                u64::from(index) - 2
            };
            assembly.stage(part(identity, stream, index, sequence))?;
        }
        let partition = assembly.verify(cursor(0), cursor(0))?;
        assert_eq!(partition.base_parts, 2);
        assert_eq!(partition.companion_last.1, u64::from(MAX_PART_COUNT) - 3);
        let mut heavy = BarrierAssembly::open(self::identity(2))?;
        let mut big = part(self::identity(2), CrossProfileStream::Base, 0, 0);
        big.encoded_event_object = vec![0; 262_344];
        heavy.stage(big)?;
        let mut companion = part(self::identity(2), CrossProfileStream::Companion, 1, 0);
        companion.payload_object_id = Some([1; 32]);
        companion.payload_object_bytes = 4_194_304;
        heavy.stage(companion)?;
        let mut over = BarrierAssembly::open(self::identity(5))?;
        for index in 0..4 {
            let mut part = part(
                self::identity(5),
                CrossProfileStream::Companion,
                index + 1,
                u64::from(index),
            );
            part.payload_object_id = Some([1; 32]);
            part.payload_object_bytes = 4_194_304;
            if index == 3 {
                assert_eq!(over.stage(part), Err(BarrierFault::Aggregate));
            } else {
                over.stage(part)?;
            }
        }
        Ok(())
    }
}
