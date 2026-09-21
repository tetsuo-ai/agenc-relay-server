//! Directory query pages and their one-use HMAC cursors (spec 20.4, B.3).
//!
//! A query renders to reply frames exactly like a local query, then the
//! frames are cut into `reply_page` results of at most 512 replies and
//! 65,536 encoded bytes. A nonfinal page installs one precomputed successor
//! cursor in the live table; the remaining frames stay in memory under that
//! cursor for the bounded cursor lifetime.

use std::collections::BTreeMap;

use agenc_relay_client_wire::WireMessage;
use agenc_relay_crypto::{QueryCursorKey, authenticate_query_cursor};
use agenc_relay_domain::federation::{
    ContinuationRequest, CursorCounter, QueryCursorBinding, QueryCursorTable,
};
use agenc_relay_domain::{DomainError, QueryPlan};
use agenc_relay_federation_wire::SchemaObject;
use agenc_relay_types::{
    AccountId, FederationDirectoryQueryKind, Generation, MonotonicTick, NetworkId, ServerId,
    SessionId, UserId,
};

use super::Violation;
use crate::federation::codec::results::{ResultArm, reply_object};
use crate::query_pages::{ReplySize, page_count};
use crate::state_core::StateCoreContext;
use crate::sync::Arc;

mod backing;
mod expiry;
mod shape;
use backing::DirectoryQueryReservation;
pub(super) use backing::QueryReceipt;

/// The fixed per-page ceilings (spec 20.4).
/// Live cursors held at once across every edge.
const MAX_LIVE_CURSORS: usize = 4_096;
/// The registered failure code for any cursor problem.
const QUERY_EXPIRED: &str = "QUERY_EXPIRED";

#[cfg(test)]
#[path = "tests/query_admission.rs"]
mod admission;
#[cfg(test)]
pub(super) use admission::names_query_fixture;

/// The process-local query cursor state.
pub(super) struct Queries {
    key: QueryCursorKey,
    process_nonce: [u8; 16],
    counter: CursorCounter,
    cursors: QueryCursorTable,
    retained: BTreeMap<[u8; 32], Retained>,
    expiry_armed: Option<(MonotonicTick, crate::state_core::timers::TimerGeneration)>,
    // Empty BTree roots survive removal; both tables must drop before this owner.
    root_backing: Option<backing::CursorRootReservation>,
}

/// The frames of a query beyond the pages already answered.
struct Retained {
    replies: Vec<SchemaObject>,
    sizes: Vec<ReplySize>,
    terminal_count: usize,
    snapshot_token: [u8; 32],
    created_at: MonotonicTick,
    expires_at: MonotonicTick,
    // Both page and retained allocations are destroyed before this owner.
    reservation: Option<Arc<DirectoryQueryReservation>>,
}

/// The identity of one directory query as the edge named it.
pub(super) struct QueryIdentity {
    pub(super) session_id: SessionId,
    pub(super) user_id: UserId,
    pub(super) account: Option<(AccountId, Generation)>,
    pub(super) kind: FederationDirectoryQueryKind,
    pub(super) arm: Vec<u8>,
}

/// One answered page.
pub(super) struct Page {
    pub(super) arm: ResultArm,
    pub(super) replies: Vec<SchemaObject>,
    pub(super) receipt: Option<QueryReceipt>,
}

/// The fixed origin of every cursor this process computes.
pub(super) struct CursorScope {
    pub(super) coordinator: ServerId,
    pub(super) network_id: NetworkId,
}

impl Queries {
    pub(super) fn new(key: [u8; 32], process_nonce: [u8; 16]) -> Self {
        Self {
            key: QueryCursorKey::from_bytes(key),
            process_nonce,
            counter: CursorCounter::default(),
            cursors: QueryCursorTable::new(),
            retained: BTreeMap::new(),
            expiry_armed: None,
            root_backing: None,
        }
    }

    /// Drops every expired cursor and its retained frames.
    pub(super) fn expire(&mut self, now: MonotonicTick) {
        let _dropped = self.cursors.expire(now);
        self.retained
            .retain(|cursor, _| self.cursors.contains(cursor));
    }

    /// Returns the number of live cursors.
    #[must_use]
    pub(super) fn live_cursors(&self) -> usize {
        self.cursors.len()
    }

    /// Renders the first page of a fresh query.
    pub(super) fn first_page(
        &mut self,
        context: &mut StateCoreContext,
        scope: &CursorScope,
        identity: &QueryIdentity,
        plan: &QueryPlan,
    ) -> Result<Page, DomainError> {
        if self.retained.len() >= MAX_LIVE_CURSORS {
            return Err(DomainError::ServerBusy);
        }
        let mut retained = render_retained(context, identity, plan)?;
        if retained.replies.is_empty()
            && identity.kind == FederationDirectoryQueryKind::MonitorStatus
        {
            return Ok(Page {
                arm: ResultArm::NoContent,
                replies: Vec::new(),
                receipt: None,
            });
        }
        context
            .entropy_mut()
            .fill_exact(&mut retained.snapshot_token)
            .map_err(|_| DomainError::ServerBusy)?;
        let token = retained.snapshot_token;
        let owner = Arc::clone(
            retained
                .reservation
                .as_ref()
                .ok_or(DomainError::InvariantViolation)?,
        );
        let page = take_page(&mut retained).map_err(|_| DomainError::ServerBusy)?;
        let next_cursor = if retained.replies.is_empty() {
            None
        } else {
            self.reserve_roots(context)?;
            let binding =
                self.binding(scope, identity, context.domain().revision().get(), token, 1)?;
            let cursor = self.cursor_of(&binding)?;
            self.reserve_expiry(context, retained.expires_at)?;
            self.cursors
                .install_new(cursor, binding, context.now())
                .map_err(|_| DomainError::InvariantViolation)?;
            self.retained.insert(cursor, retained);
            Some(cursor)
        };
        Ok(Page {
            arm: ResultArm::ReplyPage {
                snapshot_token: token,
                page_sequence: 0,
                next_cursor,
            },
            replies: page,
            receipt: Some(QueryReceipt {
                successor: next_cursor,
                owner,
            }),
        })
    }

    /// Answers a continuation, consuming the cursor. Any cursor problem is
    /// exactly `failed(QUERY_EXPIRED)`.
    pub(super) fn next_page(
        &mut self,
        context: &mut StateCoreContext,
        scope: &CursorScope,
        identity: &QueryIdentity,
        cursor: [u8; 32],
    ) -> Result<Page, Violation> {
        let request = ContinuationRequest {
            session_id: identity.session_id,
            user_id: identity.user_id,
            account: identity.account,
            query_kind: identity.kind,
            query_arm: identity.arm.as_slice(),
        };
        let now = context.now();
        let Ok(live) = self.cursors.check(&cursor, &request, now) else {
            return Ok(expired_page());
        };
        let sequence = live.binding.next_page_sequence;
        let state_generation = live.binding.state_generation;
        let Some(retained) = self.retained.remove(&cursor) else {
            let _released = self.cursors.replace(&cursor, None, now);
            return Ok(expired_page());
        };
        let owner = retained.reservation.clone();
        let result = self.continue_retained(
            context,
            scope,
            identity,
            cursor,
            (sequence, state_generation),
            retained,
        );
        if result.is_err() {
            let _released = self.cursors.replace(&cursor, None, now);
        }
        drop(owner);
        result
    }

    fn continue_retained(
        &mut self,
        context: &mut StateCoreContext,
        scope: &CursorScope,
        identity: &QueryIdentity,
        cursor: [u8; 32],
        progress: (u32, u64),
        mut retained: Retained,
    ) -> Result<Page, Violation> {
        let (sequence, state_generation) = progress;
        let now = context.now();
        retained.expires_at =
            expiry::deadline(retained.created_at, now).map_err(|_| Violation::Ceiling)?;
        let token = retained.snapshot_token;
        let owner = Arc::clone(retained.reservation.as_ref().ok_or(Violation::Ceiling)?);
        let page = take_page(&mut retained)?;
        let successor = if retained.replies.is_empty() {
            None
        } else {
            let next_sequence = sequence.checked_add(1).ok_or(Violation::Ceiling)?;
            let binding = self
                .binding(scope, identity, state_generation, token, next_sequence)
                .map_err(|_| Violation::Ceiling)?;
            let next = self.cursor_of(&binding).map_err(|_| Violation::Ceiling)?;
            self.reserve_expiry(context, retained.expires_at)
                .map_err(|_| Violation::Ceiling)?;
            Some((next, binding))
        };
        let next_cursor = successor.as_ref().map(|(next, _)| *next);
        self.cursors
            .replace(&cursor, successor, now)
            .map_err(|_| Violation::Ceiling)?;
        if let Some(next) = next_cursor {
            self.retained.insert(next, retained);
        }
        Ok(Page {
            arm: ResultArm::ReplyPage {
                snapshot_token: token,
                page_sequence: sequence,
                next_cursor,
            },
            replies: page,
            receipt: Some(QueryReceipt {
                successor: next_cursor,
                owner,
            }),
        })
    }

    fn binding(
        &mut self,
        scope: &CursorScope,
        identity: &QueryIdentity,
        state_generation: u64,
        snapshot_token: [u8; 32],
        next_page_sequence: u32,
    ) -> Result<QueryCursorBinding, DomainError> {
        let cursor_counter = self.counter.draw().ok_or(DomainError::ServerBusy)?;
        Ok(QueryCursorBinding {
            network_id: scope.network_id,
            coordinator_server_id: scope.coordinator,
            process_nonce: self.process_nonce,
            session_id: identity.session_id,
            user_id: identity.user_id,
            account: identity.account,
            query_kind: identity.kind,
            query_arm: identity.arm.clone(),
            state_generation,
            snapshot_token,
            next_page_sequence,
            cursor_counter,
        })
    }

    /// Computes the cursor as the keyed authenticator of the binding TBS.
    fn cursor_of(&self, binding: &QueryCursorBinding) -> Result<[u8; 32], DomainError> {
        let tbs = encode_binding(binding)?;
        authenticate_query_cursor(&self.key, &tbs)
            .map(|authenticator| *authenticator.expose_for_storage())
            .map_err(|_| DomainError::InvariantViolation)
    }
}

/// The exact `QueryCursorBindingTBS` TLS encoding (spec B.3).
fn encode_binding(binding: &QueryCursorBinding) -> Result<Vec<u8>, DomainError> {
    let account_text = binding.account.map(|(account, _)| account.to_text());
    let account_bytes = account_text.as_deref().map_or(&[][..], str::as_bytes);
    let arm_len = u16::try_from(binding.query_arm.len()).map_err(|_| DomainError::LimitExceeded)?;
    let mut tbs = Vec::new();
    tbs.try_reserve_exact(binding.query_arm.len().saturating_add(224))
        .map_err(|_| DomainError::AllocationFailed)?;
    tbs.extend_from_slice(&1_u16.to_be_bytes());
    tbs.extend_from_slice(binding.network_id.as_bytes());
    tbs.extend_from_slice(binding.coordinator_server_id.as_bytes());
    tbs.extend_from_slice(&binding.process_nonce);
    tbs.extend_from_slice(binding.session_id.as_bytes());
    tbs.extend_from_slice(binding.user_id.as_bytes());
    tbs.push(u8::try_from(account_bytes.len()).map_err(|_| DomainError::LimitExceeded)?);
    tbs.extend_from_slice(account_bytes);
    tbs.extend_from_slice(
        &binding
            .account
            .map_or(0, |(_, generation)| generation.get())
            .to_be_bytes(),
    );
    tbs.extend_from_slice(&binding.query_kind.wire_value().to_be_bytes());
    tbs.extend_from_slice(&arm_len.to_be_bytes());
    tbs.extend_from_slice(&binding.query_arm);
    tbs.extend_from_slice(&binding.state_generation.to_be_bytes());
    tbs.extend_from_slice(&binding.snapshot_token);
    tbs.extend_from_slice(&binding.next_page_sequence.to_be_bytes());
    tbs.extend_from_slice(&binding.cursor_counter.to_be_bytes());
    Ok(tbs)
}

/// Admission precedes the renderer, all nested objects, and entropy use.
fn render_retained(
    context: &StateCoreContext,
    identity: &QueryIdentity,
    plan: &QueryPlan,
) -> Result<Retained, DomainError> {
    let bounds = shape::bounds(context, identity.user_id, plan)?;
    let reservation = DirectoryQueryReservation::prepare(context, identity, &bounds)?;
    let frames =
        crate::query_render::federated_query_frames(context, identity.user_id, false, plan)
            .map_err(|_| DomainError::ServerBusy)?;
    if frames.len() > bounds.frames
        || frames
            .iter()
            .any(|frame| frame.middle().len() > bounds.middle_parameters)
    {
        return Err(DomainError::InvariantViolation);
    }
    let mut retained = Retained {
        replies: Vec::new(),
        sizes: Vec::new(),
        terminal_count: frames
            .iter()
            .rev()
            .take_while(|frame| frame.command() == "366")
            .count(),
        snapshot_token: [0; 32],
        created_at: context.now(),
        expires_at: expiry::deadline(context.now(), context.now())?,
        reservation: Some(Arc::clone(&reservation)),
    };
    retained
        .replies
        .try_reserve_exact(frames.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    retained
        .sizes
        .try_reserve_exact(frames.len())
        .map_err(|_| DomainError::AllocationFailed)?;
    for frame in &frames {
        let (object, encoded, rendered) = measure(frame)?;
        retained.replies.push(object);
        retained.sizes.push(ReplySize {
            encoded,
            rendered,
            names_users: if frame.command() == "353" {
                frame
                    .trailing()
                    .map_or(0, |text| text.split_ascii_whitespace().count())
            } else {
                0
            },
        });
    }
    Ok(retained)
}

/// Encodes one reply and returns it with its encoded and rendered sizes.
fn measure(frame: &WireMessage) -> Result<(SchemaObject, usize, usize), DomainError> {
    let object = reply_object(frame).map_err(|_| DomainError::InvalidArgument)?;
    let encoded = object
        .encoded_len()
        .map_err(|_| DomainError::InvalidArgument)?;
    let rendered = frame
        .measure()
        .map_err(|_| DomainError::InvalidArgument)?
        .bytes();
    Ok((object, encoded, rendered))
}

/// Moves the next page out of the retained frames: as many replies as fit
/// under the reply count, encoded result, and rendered frame ceilings.
fn take_page(retained: &mut Retained) -> Result<Vec<SchemaObject>, Violation> {
    let count =
        page_count(&retained.sizes, retained.terminal_count).map_err(|_| Violation::Ceiling)?;
    if count == retained.replies.len() {
        retained.terminal_count = 0;
    }
    retained.sizes.drain(..count);
    Ok(retained.replies.drain(..count).collect())
}

fn expired_page() -> Page {
    Page {
        arm: ResultArm::Failed {
            code: QUERY_EXPIRED.to_owned(),
            context: String::new(),
        },
        replies: Vec::new(),
        receipt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_monitor_status_completes_without_a_reply_page()
    -> Result<(), Box<dyn core::error::Error>> {
        use crate::test_support::{StateCoreFixture, plan_live, seed_session};
        use agenc_relay_domain::{CanonicalCommand, PlanDecision, PresenceCommand};
        let mut fixture = StateCoreFixture::new(vec![1; 32])?;
        let context = fixture.context_mut()?;
        let user = seed_session(context, 1, "EmptyMonitor", None)?;
        let PlanDecision::Query(plan) = plan_live(context, user, &|| {
            CanonicalCommand::presence(PresenceCommand::MonitorStatus)
        })?
        else {
            return Err("MONITOR status was not a query".into());
        };
        let identity = QueryIdentity {
            session_id: user.session_id,
            user_id: user.user_id,
            account: None,
            kind: FederationDirectoryQueryKind::MonitorStatus,
            arm: Vec::new(),
        };
        let scope = CursorScope {
            coordinator: ServerId::from_bytes([2; 16]),
            network_id: NetworkId::from_bytes([3; 32]),
        };
        let page = Queries::new([4; 32], [5; 16]).first_page(context, &scope, &identity, &plan)?;
        assert!(matches!(page.arm, ResultArm::NoContent));
        assert!(page.replies.is_empty());
        Ok(())
    }

    fn retained(sizes: &[(usize, usize)]) -> Retained {
        let mut replies = Vec::new();
        for _ in sizes {
            let object = SchemaObject::new(
                "FederationReply",
                vec![
                    agenc_relay_federation_wire::access::opaque(b"353")
                        .unwrap_or(agenc_relay_federation_wire::WireValue::Unsigned(0)),
                    agenc_relay_federation_wire::WireValue::Vector(Vec::new()),
                    agenc_relay_federation_wire::WireValue::Unsigned(0),
                    agenc_relay_federation_wire::WireValue::Opaque(Vec::new()),
                ],
            );
            if let Ok(object) = object {
                replies.push(object);
            }
        }
        Retained {
            replies,
            sizes: sizes
                .iter()
                .map(|(encoded, rendered)| ReplySize {
                    encoded: *encoded,
                    rendered: *rendered,
                    names_users: 0,
                })
                .collect(),
            terminal_count: 0,
            snapshot_token: [1; 32],
            created_at: MonotonicTick::from_ticks(0),
            expires_at: MonotonicTick::from_ticks(60_000),
            reservation: None,
        }
    }

    #[test]
    fn pages_stop_before_either_byte_ceiling_and_never_return_empty() -> Result<(), Violation> {
        let mut big = retained(&[(60_000, 10), (10_000, 10), (10, 65_530), (10, 10)]);
        assert_eq!(
            take_page(&mut big)?.len(),
            1,
            "the second reply crosses the encoded bound"
        );
        assert_eq!(
            take_page(&mut big)?.len(),
            1,
            "the third reply crosses the rendered bound"
        );
        assert_eq!(
            take_page(&mut big)?.len(),
            1,
            "a reply within the fixed ceiling forms its own page"
        );
        assert_eq!(take_page(&mut big)?.len(), 1);
        assert!(take_page(&mut big)?.is_empty());
        let mut many = retained(&vec![(1, 1); 600]);
        assert_eq!(
            take_page(&mut many)?.len(),
            crate::query_pages::MAX_PAGE_REPLIES
        );
        assert_eq!(take_page(&mut many)?.len(), 88);
        Ok(())
    }

    #[test]
    fn names_pages_never_split_the_terminal_channel_group() -> Result<(), Violation> {
        let mut snapshot = retained(&vec![(10, 10); 530]);
        snapshot.terminal_count = 20;
        assert_eq!(take_page(&mut snapshot)?.len(), 510);
        assert_eq!(snapshot.terminal_count, 20);
        assert_eq!(take_page(&mut snapshot)?.len(), 20);
        assert!(snapshot.replies.is_empty());
        assert_eq!(snapshot.terminal_count, 0);
        Ok(())
    }

    #[test]
    fn names_pages_charge_member_rows_instead_of_numeric_line_count() -> Result<(), Violation> {
        let mut snapshot = retained(&[(10, 10); 4]);
        for size in &mut snapshot.sizes {
            size.names_users = 200;
        }
        assert_eq!(take_page(&mut snapshot)?.len(), 2);
        assert_eq!(take_page(&mut snapshot)?.len(), 2);
        Ok(())
    }

    #[test]
    fn cursor_binding_encoding_is_deterministic_and_counter_sensitive() -> Result<(), DomainError> {
        let scope = CursorScope {
            coordinator: ServerId::from_bytes([1; 16]),
            network_id: NetworkId::from_bytes([2; 32]),
        };
        let identity = QueryIdentity {
            session_id: SessionId::from_bytes([3; 16]),
            user_id: UserId::from_bytes([4; 16]),
            account: None,
            kind: FederationDirectoryQueryKind::List,
            arm: vec![5, 6, 7],
        };
        let mut queries = Queries::new([8; 32], [9; 16]);
        let first = queries.binding(&scope, &identity, 10, [11; 32], 1)?;
        let second = queries.binding(&scope, &identity, 10, [11; 32], 1)?;
        assert_eq!(first.cursor_counter + 1, second.cursor_counter);
        assert_eq!(
            encode_binding(&first)?.len(),
            2 + 32 + 16 + 16 + 16 + 16 + 1 + 8 + 2 + 2 + 3 + 8 + 32 + 4 + 8
        );
        assert_ne!(queries.cursor_of(&first)?, queries.cursor_of(&second)?);
        assert_eq!(queries.cursor_of(&first)?, queries.cursor_of(&first)?);
        Ok(())
    }
}
