//! Validated history selectors and bounded selection over immutable metadata.

use std::cmp::Ordering;

use agenc_relay_types::MessageId;

/// Greatest number of immutable message identities frozen by one query.
pub const MAX_HISTORY_RESULTS: u16 = 100;

/// A nonzero, exact UTC millisecond reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryTimestamp(u64);

impl HistoryTimestamp {
    /// Rejects the zero value reserved for absent references on the wire.
    pub const fn new(milliseconds: u64) -> Result<Self, HistoryError> {
        if milliseconds == 0 {
            return Err(HistoryError::InvalidTimestamp);
        }
        Ok(Self(milliseconds))
    }

    /// Returns the exact UTC millisecond value.
    #[must_use]
    pub const fn milliseconds(self) -> u64 {
        self.0
    }
}

/// An exclusive endpoint, except for the included `AROUND` pivot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryReference {
    /// Resolve the immutable ID to its event position, never lexical ID order.
    Message(MessageId),
    /// Compare authoritative receive timestamps at millisecond precision.
    Timestamp(HistoryTimestamp),
}

/// The five pinned draft selectors. `Between` preserves request direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistorySelector {
    /// The newest rows, optionally newer than the exclusive reference.
    Latest(Option<HistoryReference>),
    /// The nearest rows older than the exclusive reference.
    Before(HistoryReference),
    /// The nearest rows newer than the exclusive reference.
    After(HistoryReference),
    /// A balanced selection including the resolved pivot.
    Around(HistoryReference),
    /// Nearest rows moving from the first endpoint toward the second.
    Between(HistoryReference, HistoryReference),
}

/// A selector whose result limit has already been validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryQuery {
    selector: HistorySelector,
    limit: u16,
}

impl HistoryQuery {
    /// Validates the closed 1..100 result limit.
    pub const fn new(selector: HistorySelector, limit: u16) -> Result<Self, HistoryError> {
        if limit == 0 || limit > MAX_HISTORY_RESULTS {
            return Err(HistoryError::InvalidLimit);
        }
        Ok(Self { selector, limit })
    }

    /// Returns the validated selector.
    #[must_use]
    pub const fn selector(self) -> HistorySelector {
        self.selector
    }

    /// Returns the validated result limit.
    #[must_use]
    pub const fn limit(self) -> u16 {
        self.limit
    }
}

/// Immutable ordering metadata; this type contains no message body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryPosition {
    channel_sequence: u64,
    message_id: MessageId,
    received_unix_milliseconds: u64,
}

impl HistoryPosition {
    /// Constructs a position from authenticated, nonzero ordering metadata.
    pub const fn new(
        channel_sequence: u64,
        message_id: MessageId,
        received_unix_milliseconds: u64,
    ) -> Result<Self, HistoryError> {
        if channel_sequence == 0 || received_unix_milliseconds == 0 {
            return Err(HistoryError::InvalidPosition);
        }
        Ok(Self {
            channel_sequence,
            message_id,
            received_unix_milliseconds,
        })
    }

    /// Returns the channel event position.
    #[must_use]
    pub const fn channel_sequence(self) -> u64 {
        self.channel_sequence
    }

    /// Returns the immutable message identity.
    #[must_use]
    pub const fn message_id(self) -> MessageId {
        self.message_id
    }

    /// Returns the original authoritative receive time.
    #[must_use]
    pub const fn received_unix_milliseconds(self) -> u64 {
        self.received_unix_milliseconds
    }

    fn compare(self, other: Self) -> Ordering {
        (self.channel_sequence, self.message_id.as_bytes())
            .cmp(&(other.channel_sequence, other.message_id.as_bytes()))
    }
}

/// At most 100 selected positions in chronological order, including the empty result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistorySelection(Vec<HistoryPosition>);

impl HistorySelection {
    /// An empty successful selection, which still renders a history batch.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// Validates an immutable selection loaded from retained replay metadata.
    pub fn new(positions: Vec<HistoryPosition>) -> Result<Self, HistoryError> {
        if positions.len() > usize::from(MAX_HISTORY_RESULTS) {
            return Err(HistoryError::InvalidLimit);
        }
        validate_positions(&positions)?;
        Ok(Self(positions))
    }

    /// Borrows the complete immutable selection.
    #[must_use]
    pub fn positions(&self) -> &[HistoryPosition] {
        &self.0
    }
}

/// A malformed selector or inconsistent metadata cannot become a query result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// The requested count is outside 1..100.
    InvalidLimit,
    /// Zero cannot represent a timestamp reference.
    InvalidTimestamp,
    /// A stored event position or receive time is zero.
    InvalidPosition,
    /// Metadata is duplicated or violates its chronological ordering.
    InvalidOrder,
    /// The requested message ID does not exist in this authorized index.
    UnknownReference,
    /// The bounded result allocation could not be admitted.
    AllocationFailed,
}

impl std::fmt::Display for HistoryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "history limit is outside 1..100",
            Self::InvalidTimestamp => "history timestamp is zero",
            Self::InvalidPosition => "history position has a zero sequence or timestamp",
            Self::InvalidOrder => "history positions are not strictly ordered",
            Self::UnknownReference => "history message reference is unavailable",
            Self::AllocationFailed => "history selection allocation failed",
        })
    }
}

impl std::error::Error for HistoryError {}

/// Selects from an authorized, retention-filtered metadata index supplied by the owner.
///
/// The owner bounds and charges the input index. This function scans it without copying
/// message bodies and allocates only the validated output limit. It does not authorize
/// reads or decide retention. Unknown initial references may be rendered as empty by the
/// caller; a missing identity from an existing frozen selection instead expires replay.
pub fn select_history(
    query: &HistoryQuery,
    positions: &[HistoryPosition],
) -> Result<HistorySelection, HistoryError> {
    select_history_iter(query, positions.iter().copied())
}

/// Selects directly from a bounded metadata index without materializing the input.
pub fn select_history_iter<I>(
    query: &HistoryQuery,
    positions: I,
) -> Result<HistorySelection, HistoryError>
where
    I: ExactSizeIterator<Item = HistoryPosition> + Clone,
{
    validate_position_iter(positions.clone())?;
    let limit = usize::from(query.limit());
    let range = selected_range(query.selector(), limit, positions.clone())?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(range.len())
        .map_err(|_| HistoryError::AllocationFailed)?;
    result.extend(positions.skip(range.start).take(range.len()));
    HistorySelection::new(result)
}

fn validate_positions(positions: &[HistoryPosition]) -> Result<(), HistoryError> {
    validate_position_iter(positions.iter().copied())
}

fn validate_position_iter(
    positions: impl Iterator<Item = HistoryPosition>,
) -> Result<(), HistoryError> {
    let mut previous: Option<HistoryPosition> = None;
    for next in positions {
        if previous.is_some_and(|previous| {
            previous.compare(next) != Ordering::Less
                || previous.received_unix_milliseconds > next.received_unix_milliseconds
        }) {
            return Err(HistoryError::InvalidOrder);
        }
        previous = Some(next);
    }
    Ok(())
}

/// The slice strictly before and strictly after one endpoint.
struct Boundary {
    before: usize,
    after: usize,
}

fn boundary(
    reference: HistoryReference,
    positions: impl ExactSizeIterator<Item = HistoryPosition>,
) -> Result<Boundary, HistoryError> {
    match reference {
        HistoryReference::Message(message_id) => {
            let index = positions
                .enumerate()
                .find(|(_, position)| position.message_id == message_id)
                .map(|(index, _)| index)
                .ok_or(HistoryError::UnknownReference)?;
            Ok(Boundary {
                before: index,
                after: index + 1,
            })
        }
        HistoryReference::Timestamp(timestamp) => Ok(timestamp_boundary(timestamp, positions)),
    }
}

fn timestamp_boundary(
    timestamp: HistoryTimestamp,
    positions: impl Iterator<Item = HistoryPosition>,
) -> Boundary {
    let mut result = Boundary {
        before: 0,
        after: 0,
    };
    for position in positions
        .take_while(|position| position.received_unix_milliseconds <= timestamp.milliseconds())
    {
        result.after += 1;
        result.before +=
            usize::from(position.received_unix_milliseconds < timestamp.milliseconds());
    }
    result
}

fn selected_range<I>(
    selector: HistorySelector,
    limit: usize,
    positions: I,
) -> Result<std::ops::Range<usize>, HistoryError>
where
    I: ExactSizeIterator<Item = HistoryPosition> + Clone,
{
    let length = positions.len();
    match selector {
        HistorySelector::Latest(reference) => {
            let start = reference
                .map(|value| boundary(value, positions))
                .transpose()?
                .map_or(0, |value| value.after);
            Ok(length.saturating_sub(limit).max(start)..length)
        }
        HistorySelector::Before(reference) => {
            let end = boundary(reference, positions)?.before;
            Ok(end.saturating_sub(limit)..end)
        }
        HistorySelector::After(reference) => {
            let start = boundary(reference, positions)?.after;
            Ok(start..start.saturating_add(limit).min(length))
        }
        HistorySelector::Around(reference) => {
            let pivot = boundary(reference, positions)?.before;
            Ok(around_range(pivot, limit, length))
        }
        HistorySelector::Between(first, second) => Ok(between_range(
            boundary(first, positions.clone())?,
            boundary(second, positions)?,
            limit,
        )),
    }
}

fn around_range(pivot: usize, limit: usize, length: usize) -> std::ops::Range<usize> {
    if length == 0 {
        return 0..0;
    }
    let pivot = pivot.min(length - 1);
    let before = (limit - 1) / 2;
    let start = pivot.saturating_sub(before);
    let end = start.saturating_add(limit).min(length);
    end.saturating_sub(limit)..end
}

fn between_range(first: Boundary, second: Boundary, limit: usize) -> std::ops::Range<usize> {
    if first.after <= second.before {
        return first.after..first.after.saturating_add(limit).min(second.before);
    }
    if second.after <= first.before {
        return first.before.saturating_sub(limit).max(second.after)..first.before;
    }
    0..0
}
