//! Bounded public nickname history (spec 14.5). Historical authority and
//! audience identities are never retained; disclosure requires a currently
//! visible session with the same independently random public cloak.

use std::collections::LinkedList;

use agenc_relay_domain::{
    AccountLabelValue, DomainEvent, DomainState, MutationPlan, NicknameValue, ProjectionDecision,
};
use agenc_relay_types::{MonotonicTick, PublicCloak, UserId, UtcSecond};

use crate::budget::{
    BoundedMemoryCharges, MemoryBudget, MemoryBudgetPort, MemoryCharge, MemoryPermit,
};

const MAX_RECORDS: usize = 10_000;
const RETENTION_MILLIS: u64 = 900_000;

pub(crate) struct WhowasRecord {
    pub(crate) nickname: NicknameValue,
    pub(crate) cloak: PublicCloak,
    pub(crate) label: Option<AccountLabelValue>,
    pub(crate) disconnected_at: UtcSecond,
    expires_at: MonotonicTick,
    _permit: MemoryPermit,
}

pub(crate) struct WhowasHistory {
    records: LinkedList<WhowasRecord>,
    limit: usize,
}

pub(super) struct PreparedWhowas(LinkedList<WhowasRecord>);

impl WhowasHistory {
    pub(super) const fn new() -> Self {
        Self {
            records: LinkedList::new(),
            limit: MAX_RECORDS,
        }
    }

    pub(super) fn configure(&mut self, config: &agenc_relay_config::Config, now: MonotonicTick) {
        self.limit = if config.network.role == agenc_relay_config::NodeRole::Edge {
            0
        } else {
            usize::try_from(config.privacy.whowas_records)
                .unwrap_or(0)
                .min(MAX_RECORDS)
        };
        self.expire(now);
        self.trim_to(self.limit);
    }

    pub(super) fn next_deadline(&self) -> Option<MonotonicTick> {
        self.records.front().map(|record| record.expires_at)
    }

    pub(super) fn expire(&mut self, now: MonotonicTick) {
        while self.next_deadline().is_some_and(|deadline| deadline <= now) {
            self.records.pop_front();
        }
    }

    fn trim_to(&mut self, count: usize) {
        while self.records.len() > count {
            self.records.pop_front();
        }
    }

    /// Reserves and copies only the public preimage. Allocation refusal is
    /// cache omission and cannot invalidate a mutation already committed by storage.
    pub(super) fn prepare(
        &mut self,
        domain: &DomainState,
        plan: &MutationPlan,
        now: MonotonicTick,
        wall: Option<UtcSecond>,
        budget: &MemoryBudget,
    ) -> PreparedWhowas {
        let mut prepared = PreparedWhowas(LinkedList::new());
        if self.limit == 0 || plan.expected_revision() != domain.revision() {
            return prepared;
        }
        let (Ok(expires_at), Some(disconnected_at)) = (now.checked_add(RETENTION_MILLIS), wall)
        else {
            return prepared;
        };
        self.expire(now);
        for user in plan.events().iter().filter_map(retired_user) {
            if prepared.0.len() == self.limit {
                prepared.0.pop_front();
            }
            self.trim_to(self.limit.saturating_sub(prepared.0.len() + 1));
            if let Some(record) = prepare_record(domain, user, expires_at, disconnected_at, budget)
            {
                prepared.0.push_back(record);
            }
        }
        prepared
    }

    /// Linked-list transfer allocates nothing after the domain mutation succeeds.
    pub(super) fn committed(&mut self, mut prepared: PreparedWhowas) {
        self.records.append(&mut prepared.0);
    }

    pub(crate) fn visible<'a>(
        &'a self,
        domain: &'a DomainState,
        requester: UserId,
        nickname: &'a NicknameValue,
        now: MonotonicTick,
    ) -> impl Iterator<Item = &'a WhowasRecord> {
        self.records.iter().rev().filter(move |record| {
            record.expires_at > now
                && record.nickname == *nickname
                && domain
                    .user_for_public_cloak(record.cloak)
                    .is_some_and(|user| {
                        matches!(
                            domain.project_session(requester, user),
                            ProjectionDecision::Visible(_)
                        )
                    })
        })
    }
}

fn retired_user(event: &DomainEvent) -> Option<UserId> {
    match event {
        DomainEvent::NicknameChanged(user) | DomainEvent::SessionHidden(user) => Some(*user),
        _ => None,
    }
}

fn prepare_record(
    domain: &DomainState,
    user: UserId,
    expires_at: MonotonicTick,
    disconnected_at: UtcSecond,
    budget: &MemoryBudget,
) -> Option<WhowasRecord> {
    let ProjectionDecision::Visible(session) = domain.project_session(user, user) else {
        return None;
    };
    let nickname = session.nickname();
    let label = session.account_label();
    let charges = [
        MemoryCharge::allocation(
            u64::try_from(std::mem::size_of::<WhowasRecord>() + 2 * std::mem::size_of::<usize>())
                .ok()?,
        )
        .ok()?,
        MemoryCharge::allocation(u64::try_from(nickname.presentation().len()).ok()?).ok()?,
        MemoryCharge::allocation(u64::try_from(nickname.canonical().len()).ok()?).ok()?,
        MemoryCharge::allocation(
            u64::try_from(label.map_or(0, |label| label.as_str().len())).ok()?,
        )
        .ok()?,
    ];
    let charges = BoundedMemoryCharges::new(&charges).ok()?;
    let permit = budget
        .try_acquire_batch(charges)
        .ok()?
        .split_exact(charges.total())?;
    Some(WhowasRecord {
        nickname: nickname.clone(),
        cloak: session.public_cloak(),
        label: label.cloned(),
        disconnected_at,
        expires_at,
        _permit: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_core::StateCoreContext;
    use crate::test_support::{
        StateCoreFixture, TestResult, apply_live_plan, golden_config, plan_live, seed_session,
    };
    use agenc_relay_domain::{
        CanonicalCommand, ChannelNameValue, ChannelTarget, DomainError, PlanDecision, UserQuery,
    };
    use agenc_relay_testkit::{DeterministicMonotonicClock, DomainTestIdentity};

    fn mutation(
        context: &mut StateCoreContext,
        identity: DomainTestIdentity,
        command: &dyn Fn() -> Result<CanonicalCommand, DomainError>,
    ) -> TestResult {
        let PlanDecision::Mutation(plan) = plan_live(context, identity, command)? else {
            return Err("expected mutation".into());
        };
        apply_live_plan(context, plan)
    }

    fn rename(
        context: &mut StateCoreContext,
        identity: DomainTestIdentity,
        name: &str,
    ) -> TestResult {
        mutation(context, identity, &|| {
            Ok(CanonicalCommand::nick(NicknameValue::parse(name)?))
        })
    }

    fn join(context: &mut StateCoreContext, identity: DomainTestIdentity) -> TestResult {
        mutation(context, identity, &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(
                ChannelNameValue::parse("#whowas")?,
                false,
            )])
        })
    }

    fn query(
        context: &StateCoreContext,
        requester: DomainTestIdentity,
        name: &str,
        count: u8,
    ) -> TestResult<Vec<agenc_relay_client_wire::WireMessage>> {
        let PlanDecision::Query(plan) = plan_live(context, requester, &|| {
            CanonicalCommand::user_query(UserQuery::Whowas(NicknameValue::parse(name)?, count))
        })?
        else {
            return Err("expected query".into());
        };
        Ok(crate::query_render::federated_query_frames(
            context,
            requester.user_id,
            false,
            &plan,
        )?)
    }

    fn codes(frames: &[agenc_relay_client_wire::WireMessage]) -> Vec<&str> {
        frames
            .iter()
            .map(agenc_relay_client_wire::WireMessage::command)
            .collect()
    }

    #[test]
    fn whowas_old_nickname_requires_its_original_cloak_and_current_visibility() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let owner = seed_session(context, 1, "Before", None)?;
        let viewer = seed_session(context, 2, "Viewer", None)?;
        join(context, owner)?;
        join(context, viewer)?;
        rename(context, owner, "After")?;
        assert_eq!(
            codes(&query(context, viewer, "Before", 1)?),
            ["314", "312", "369"]
        );
        let reused = seed_session(context, 3, "Before", None)?;
        join(context, reused)?;
        mutation(context, owner, &|| Ok(CanonicalCommand::part_all()))?;
        assert_eq!(codes(&query(context, viewer, "Before", 1)?), ["406", "369"]);
        join(context, owner)?;
        assert_eq!(
            codes(&query(context, viewer, "Before", 1)?),
            ["314", "312", "369"]
        );
        let plan = context.domain().plan_session_disconnected(owner.user_id)?;
        apply_live_plan(context, plan)?;
        assert_eq!(context.whowas.records.len(), 2);
        assert_eq!(codes(&query(context, viewer, "Before", 1)?), ["406", "369"]);
        assert_eq!(codes(&query(context, viewer, "After", 1)?), ["406", "369"]);
        assert_eq!(
            codes(&query(context, viewer, "NeverPresent", 1)?),
            ["406", "369"]
        );
        Ok(())
    }

    #[test]
    fn whowas_authority_fence_hides_retained_public_cloak() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let owner = seed_session(context, 4, "Before", None)?;
        rename(context, owner, "After")?;
        let name = NicknameValue::parse("Before")?;
        assert_eq!(
            context
                .whowas
                .visible(context.domain(), owner.user_id, &name, context.now())
                .count(),
            1
        );
        context.fence_federation_peer(agenc_relay_types::ServerId::from_bytes(
            agenc_relay_testkit::bytes(240),
        ));
        assert_eq!(
            context
                .whowas
                .visible(context.domain(), owner.user_id, &name, context.now())
                .count(),
            0
        );
        Ok(())
    }

    #[test]
    fn whowas_deadline_wakes_the_actor_and_releases_all_history_memory() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let state = fixture.state_mut()?;
        let owner = seed_session(&mut state.context, 5, "Before", None)?;
        let available = state.context.budget.available();
        rename(&mut state.context, owner, "After")?;
        assert!(state.context.budget.available() < available);
        assert_eq!(
            state.context.next_wake(),
            Some(MonotonicTick::from_ticks(900_010))
        );
        state.context.monotonic = Box::new(DeterministicMonotonicClock::at(900_009));
        assert_eq!(
            codes(&query(&state.context, owner, "Before", 1)?),
            ["314", "312", "369"]
        );
        assert!(state.step_wake().is_none());
        assert_eq!(state.context.whowas.records.len(), 1);
        state.context.monotonic = Box::new(DeterministicMonotonicClock::at(900_010));
        assert_eq!(
            codes(&query(&state.context, owner, "Before", 1)?),
            ["406", "369"]
        );
        assert!(state.step_wake().is_none());
        assert!(state.context.whowas.records.is_empty());
        assert_eq!(state.context.budget.available(), available);
        assert_eq!(state.context.whowas.next_deadline(), None);
        Ok(())
    }

    #[test]
    fn whowas_configured_cap_evicts_oldest_and_reload_disables_edge_history() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let owner = seed_session(context, 6, "First", None)?;
        let mut config = golden_config()?;
        config.privacy.whowas_records = 2;
        context.whowas.configure(&config, context.now());
        let available = context.budget.available();
        for name in ["Second", "Third", "Fourth"] {
            rename(context, owner, name)?;
        }
        assert_eq!(context.whowas.records.len(), 2);
        assert_eq!(codes(&query(context, owner, "First", 1)?), ["406", "369"]);
        assert_eq!(
            codes(&query(context, owner, "Second", 1)?),
            ["314", "312", "369"]
        );
        let two_records_available = context.budget.available();
        config.privacy.whowas_records = 1;
        context.whowas.configure(&config, context.now());
        assert_eq!(context.whowas.records.len(), 1);
        assert!(context.budget.available() > two_records_available);
        assert_eq!(codes(&query(context, owner, "Second", 1)?), ["406", "369"]);
        config.network.role = agenc_relay_config::NodeRole::Edge;
        context.whowas.configure(&config, context.now());
        assert_eq!(context.budget.available(), available);
        rename(context, owner, "Fifth")?;
        assert!(context.whowas.records.is_empty());
        Ok(())
    }

    #[test]
    fn whowas_failed_mutation_and_budget_refusal_never_corrupt_committed_state() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let owner = seed_session(context, 7, "Before", None)?;
        let PlanDecision::Mutation(stale) = plan_live(context, owner, &|| {
            Ok(CanonicalCommand::nick(NicknameValue::parse("Stale")?))
        })?
        else {
            return Err("expected mutation".into());
        };
        let _other = seed_session(context, 8, "Other", None)?;
        assert!(matches!(
            context.apply_plan(stale),
            Err(DomainError::StaleRevision)
        ));
        assert!(context.whowas.records.is_empty());
        let PlanDecision::Mutation(committed) = plan_live(context, owner, &|| {
            Ok(CanonicalCommand::nick(NicknameValue::parse("After")?))
        })?
        else {
            return Err("expected mutation".into());
        };
        let held = context
            .budget
            .try_acquire_batch(BoundedMemoryCharges::new(&[MemoryCharge::fixed(
                context.budget.available(),
            )])?)
            .map_err(|_| "hold budget")?;
        context.apply_plan(committed)?;
        assert_eq!(
            context
                .domain()
                .session(owner.user_id)
                .ok_or("session")?
                .nickname()
                .presentation(),
            "After"
        );
        assert!(context.whowas.records.is_empty());
        drop(held);
        assert_eq!(codes(&query(context, owner, "Before", 1)?), ["406", "369"]);
        Ok(())
    }
    #[test]
    fn whowas_count_and_rows_contain_only_retired_public_facts() -> TestResult {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let account = crate::test_support::seed_account(context, 9, 1)?;
        let owner = seed_session(context, 9, "Before", Some(account))?;
        mutation(context, owner, &|| {
            Ok(CanonicalCommand::account(
                agenc_relay_domain::AccountCommand::Label(Some(AccountLabelValue::parse(
                    "PublicLabel",
                )?)),
            ))
        })?;
        rename(context, owner, "After")?;
        rename(context, owner, "Before")?;
        rename(context, owner, "AfterAgain")?;
        let one = query(context, owner, "Before", 1)?;
        assert_eq!(codes(&one), ["314", "312", "369"]);
        assert_eq!(
            codes(&query(context, owner, "Before", 2)?),
            ["314", "312", "314", "312", "369"]
        );
        let row = one.first().ok_or("WHOWAS row")?;
        let cloak = context
            .domain()
            .session(owner.user_id)
            .ok_or("session")?
            .public_cloak();
        assert_eq!(
            row.middle(),
            &[
                "AfterAgain",
                "Before",
                std::str::from_utf8(cloak.user_component())?,
                std::str::from_utf8(cloak.host_component())?,
                "*"
            ]
        );
        assert_eq!(row.trailing(), Some("PublicLabel"));
        let time = one.get(1).ok_or("WHOWAS second")?;
        assert_eq!(
            time.middle(),
            &["AfterAgain", "Before", context.server_prefix()]
        );
        assert_eq!(
            time.trailing(),
            Some(context.utc_now()?.get().to_string().as_str())
        );
        Ok(())
    }
}
