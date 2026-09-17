#![forbid(unsafe_code)]

//! CAP-01: the advertised capacity workload matrix (spec 19.2, 19.3, 28.7).
//!
//! Section 28.7 asks for two separate proofs at the published limits: the
//! default four-GiB budget admits the default idle client population, and the
//! advertised active connection/member/channel configuration runs on named
//! hardware. Both are per node. A campaign that spreads one aggregate
//! population across three daemons proves neither, so the matrix below always
//! derives the per-node population first and treats the aggregate as its
//! consequence.
//!
//! Everything here is pure arithmetic over the production functions
//! (`startup_arithmetic` and the Section 19.3 percentages), so a development
//! pilot computes exactly the same requirements as a production campaign and
//! can name every one the selected population cannot meet.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use agenc_ircd_runtime::admission::overload::{
    CONNECTION_STOP_PERCENT, EVICTION_PERCENT, GUEST_STOP_PERCENT,
};
use agenc_ircd_runtime::budget::{CLIENT_CONNECTION_BASE_BYTES, PermitPool, startup_arithmetic};
use agenc_ircd_runtime::purpose::ListenerPurpose;

use super::*;

/// Appendix C.2 default `server.memory_budget_bytes`.
pub(super) const DEFAULT_BUDGET_BYTES: u64 = 6_442_450_944;
/// Appendix C.2 default `server.crypto_worker_threads`.
const DEFAULT_CRYPTO_WORKERS: u64 = 4;
/// Appendix C.6 default `parsed_arena_bytes`.
const DEFAULT_PARSED_ARENA_BYTES: u64 = 32_768;
/// Section 19.2 default simultaneous client connections, per node.
pub(super) const DEFAULT_CLIENT_CONNECTIONS: u64 = 50_000;
/// Section 19.2 hard maximum simultaneous client connections, per node.
pub(super) const MAX_CLIENT_CONNECTIONS: u64 = 250_000;
/// Section 19.2 default members per channel.
const DEFAULT_MEMBERS_PER_CHANNEL: u64 = 4_096;
/// Section 19.2 hard maximum direct connections from one IPv4 /32.
const MAX_DIRECT_CONNECTIONS_PER_ADDRESS: u64 = 256;
/// Generator source addresses placed in one loopback /24. The new-connection
/// and TLS-handshake buckets are keyed by the source /24, so the generator
/// spreads its addresses over many of them instead of filling one.
const ADDRESSES_PER_SUBNET: u64 = 8;
/// Usable third-octet values of a generator source address.
const MAX_SUBNETS: u64 = 254;
/// Nodes that admit campaign clients: the two edges.
pub(super) const CLIENT_NODES: usize = 2;
/// First loopback second octet reserved for generator source addresses;
/// 127.0.0.1 stays the daemons' own listener address.
const GENERATOR_OCTET_BASE: u8 = 64;

/// Which qualification a campaign population can close.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Profile {
    /// Every client-admitting node holds at least the Section 19.2 default
    /// population simultaneously.
    Production,
    /// Any smaller population. It exercises the harness and never closes the
    /// production capacity claim, whatever else it measures. The seven-day
    /// soak's 256-client minimum is deliberately one of these.
    BelowDefault,
}

impl Profile {
    /// The name the record carries.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::BelowDefault => "below-default",
        }
    }
}

/// A named reason the selected population cannot close production capacity on
/// the default configuration. Each one is a harness input, not a test failure:
/// the pilot records them so the campaign owner holds the blocker before the
/// final run rather than after it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Blocker {
    /// The population is below the Section 19.2 per-node default.
    PopulationBelowDefault,
    /// The per-node idle base charges exceed the default live pool `P`.
    IdleChargesExceedPool,
    /// Section 19.3 stops new connections before the population is admitted
    /// although every charge fits `P` (issue #113).
    OverloadStopsAdmission,
    /// One edge would need more loopback source addresses than the generator
    /// layout provides.
    GeneratorAddressSpace,
}

impl Blocker {
    /// The record's stable name for this blocker.
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::PopulationBelowDefault => "population_below_default",
            Self::IdleChargesExceedPool => "idle_charges_exceed_pool",
            Self::OverloadStopsAdmission => "overload_stops_admission",
            Self::GeneratorAddressSpace => "generator_address_space",
        }
    }
}

/// The Section 19.2 startup arithmetic of one default node and the Section
/// 19.3 populations its overload classes admit.
#[derive(Clone, Copy)]
pub(super) struct NodeBudget {
    pool: PermitPool,
}

impl NodeBudget {
    /// Computes `B`, `H`, `D`, `C` and `P` with the production function for a
    /// node running the default client and local-admin listeners.
    pub(super) fn default_node() -> TestResult<Self> {
        let pool = startup_arithmetic(
            DEFAULT_BUDGET_BYTES,
            DEFAULT_CRYPTO_WORKERS,
            &[ListenerPurpose::ClientTls, ListenerPurpose::AdminLocal],
            DEFAULT_PARSED_ARENA_BYTES,
        )
        .map_err(|error| failure(format!("default node budget: {error:?}")))?;
        Ok(Self { pool })
    }

    /// Returns `B`, `H`, `D`, `C` and `P` in that order.
    pub(super) fn parts(&self) -> [u64; 5] {
        [
            self.pool.budget_bytes(),
            self.pool.headroom_bytes(),
            self.pool.storage_handoff_bytes(),
            self.pool.crypto_pool_bytes(),
            self.pool.protocol_pool_bytes(),
        ]
    }

    /// The live protocol permit pool `P`.
    pub(super) fn protocol_pool_bytes(&self) -> u64 {
        self.pool.protocol_pool_bytes()
    }

    /// Idle base charges one population of admitted clients holds.
    pub(super) fn idle_charge_bytes(&self, connections: u64) -> TestResult<u64> {
        connections
            .checked_mul(CLIENT_CONNECTION_BASE_BYTES)
            .ok_or_else(|| failure("idle base charge overflows"))
    }

    /// Idle clients admitted before the Section 19.3 class at `percent`
    /// engages against the same live pool.
    pub(super) fn clients_at_percent(&self, percent: u64) -> u64 {
        percent * self.pool.protocol_pool_bytes() / 100 / CLIENT_CONNECTION_BASE_BYTES
    }
}

/// Where one edge's load generator sources its connections.
///
/// Section 19.2 admits 256 direct connections from one IPv4 /32 at its hard
/// maximum, so a 50,000-client edge needs at least 196 distinct source
/// addresses. Raising the ceiling instead would make the population prove
/// something the published configuration does not allow.
#[derive(Clone, Copy)]
pub(super) struct GeneratorPlan {
    per_node_connections: u64,
}

impl GeneratorPlan {
    /// The per-/32 ceiling the campaign configures; never above Section 19.2.
    pub(super) const fn connections_per_address(&self) -> u64 {
        MAX_DIRECT_CONNECTIONS_PER_ADDRESS
    }

    /// Distinct source /32s one edge's generator must hold.
    pub(super) fn addresses_per_node(&self) -> u64 {
        self.per_node_connections
            .div_ceil(MAX_DIRECT_CONNECTIONS_PER_ADDRESS)
            .max(1)
    }

    /// Distinct source /24s one edge's generator spreads those addresses over.
    pub(super) fn subnets_per_node(&self) -> u64 {
        self.addresses_per_node().div_ceil(ADDRESSES_PER_SUBNET)
    }

    /// The loopback source address worker `index` on `edge` binds before it
    /// connects. Consecutive indices land on alternating edges, so the slot
    /// within one edge is `index / CLIENT_NODES`.
    pub(super) fn source_address(&self, edge: usize, index: usize) -> TestResult<Ipv4Addr> {
        let slot = u64::try_from(index / CLIENT_NODES)?;
        let address = slot % self.addresses_per_node();
        let subnet = address / ADDRESSES_PER_SUBNET;
        let host = address % ADDRESSES_PER_SUBNET;
        if subnet >= MAX_SUBNETS {
            return Err(failure("generator source address space is exhausted"));
        }
        let second = GENERATOR_OCTET_BASE
            .checked_add(u8::try_from(edge)?)
            .ok_or_else(|| failure("generator edge index is outside the loopback range"))?;
        Ok(Ipv4Addr::new(
            127,
            second,
            u8::try_from(subnet + 1)?,
            u8::try_from(host + 1)?,
        ))
    }
}

/// The selected workload: the per-node population, the active channel and
/// member configuration it produces, the budget it must leave untouched, and
/// every blocker between it and a closed production capacity claim.
pub(super) struct Workload {
    profile: Profile,
    per_node_connections: u64,
    total_connections: u64,
    budget: NodeBudget,
    generator: GeneratorPlan,
    blockers: Vec<Blocker>,
}

impl Workload {
    /// Derives the workload from the driver's total population.
    ///
    /// The total is split evenly across the client-admitting edges, so the
    /// per-node population, not the aggregate, decides the profile.
    pub(super) fn select(total_connections: u64) -> TestResult<Self> {
        let nodes = u64::try_from(CLIENT_NODES)?;
        let per_node_connections = total_connections / nodes;
        let budget = NodeBudget::default_node()?;
        let generator = GeneratorPlan {
            per_node_connections,
        };
        let profile = if per_node_connections >= DEFAULT_CLIENT_CONNECTIONS {
            Profile::Production
        } else {
            Profile::BelowDefault
        };
        let blockers = blockers_for(per_node_connections, &budget, &generator)?;
        Ok(Self {
            profile,
            per_node_connections,
            total_connections: per_node_connections * nodes,
            budget,
            generator,
            blockers,
        })
    }

    /// The selected profile.
    pub(super) const fn profile(&self) -> Profile {
        self.profile
    }

    /// The population every client-admitting edge holds simultaneously.
    pub(super) const fn per_node_connections(&self) -> u64 {
        self.per_node_connections
    }

    /// The population across every client-admitting edge.
    pub(super) const fn total_connections(&self) -> u64 {
        self.total_connections
    }

    /// The default node budget this workload must leave untouched.
    pub(super) const fn budget(&self) -> NodeBudget {
        self.budget
    }

    /// The generator layout one edge uses.
    pub(super) const fn generator(&self) -> GeneratorPlan {
        self.generator
    }

    /// Every blocker between this workload and a closed capacity claim.
    pub(super) fn blockers(&self) -> &[Blocker] {
        &self.blockers
    }

    /// Whether this run can close the production capacity claim at all. A
    /// development pilot never can, and neither can a production population
    /// with an open blocker.
    pub(super) fn qualifying(&self) -> bool {
        self.profile == Profile::Production && self.blockers.is_empty()
    }

    /// Channels the load population is partitioned into so no channel exceeds
    /// the Section 19.2 default member ceiling.
    pub(super) fn load_channels(&self) -> u64 {
        self.total_connections
            .div_ceil(DEFAULT_MEMBERS_PER_CHANNEL)
            .max(1)
    }

    /// The load channel worker `index` joins.
    pub(super) fn load_channel(&self, index: usize) -> TestResult<String> {
        let index = u64::try_from(index)?;
        Ok(format!(
            "{LOAD_CHANNEL_PREFIX}{}",
            index % self.load_channels()
        ))
    }

    /// Registrations one generator source address paces in sequence. The
    /// pre-authentication bucket is keyed by the source address, so only the
    /// workers that share one address wait for each other; spreading the
    /// population over many addresses is what keeps the warm-up bounded.
    pub(super) fn workers_per_address(&self) -> u64 {
        self.per_node_connections
            .div_ceil(self.generator.addresses_per_node())
            .max(1)
    }

    /// The paced slot worker `index` occupies within its source address.
    pub(super) fn slot_index(&self, index: usize) -> TestResult<u64> {
        let within_edge = u64::try_from(index / CLIENT_NODES)?;
        Ok(within_edge / self.generator.addresses_per_node())
    }

    /// The listener ceiling one node is configured with: the per-node
    /// population plus the controller's own probes.
    pub(super) fn listener_ceiling(&self, probes: u64) -> TestResult<u64> {
        self.per_node_connections
            .checked_add(probes)
            .filter(|ceiling| *ceiling <= MAX_CLIENT_CONNECTIONS)
            .ok_or_else(|| failure("listener ceiling exceeds the Section 19.2 hard maximum"))
    }
}

/// Every reason the selected per-node population cannot close production
/// capacity on the unchanged default configuration.
fn blockers_for(
    per_node_connections: u64,
    budget: &NodeBudget,
    generator: &GeneratorPlan,
) -> TestResult<Vec<Blocker>> {
    let mut blockers = Vec::new();
    if per_node_connections < DEFAULT_CLIENT_CONNECTIONS {
        blockers.push(Blocker::PopulationBelowDefault);
    }
    if budget.idle_charge_bytes(per_node_connections)? > budget.protocol_pool_bytes() {
        blockers.push(Blocker::IdleChargesExceedPool);
    }
    if per_node_connections > budget.clients_at_percent(CONNECTION_STOP_PERCENT) {
        blockers.push(Blocker::OverloadStopsAdmission);
    }
    if generator.subnets_per_node() > MAX_SUBNETS {
        blockers.push(Blocker::GeneratorAddressSpace);
    }
    Ok(blockers)
}

/// The production population is per node, and the aggregate is twice it.
#[test]
fn the_production_population_is_per_node() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    assert_eq!(workload.profile(), Profile::Production);
    assert_eq!(workload.profile().label(), "production");
    assert_eq!(workload.per_node_connections(), DEFAULT_CLIENT_CONNECTIONS);
    assert_eq!(workload.total_connections(), 100_000);
    Ok(())
}

/// An aggregate that meets the per-node default only when the daemons are
/// summed is below the default, not production capacity.
#[test]
fn an_aggregate_only_population_is_below_the_default() -> TestResult {
    let workload = Workload::select(DEFAULT_CLIENT_CONNECTIONS)?;
    assert_eq!(workload.profile(), Profile::BelowDefault);
    assert_eq!(workload.per_node_connections(), 25_000);
    assert!(!workload.qualifying());
    assert_eq!(
        workload.blockers(),
        [Blocker::PopulationBelowDefault].as_slice(),
        "an aggregate substitute must name its per-node shortfall"
    );
    Ok(())
}

/// The 64-client development run the launcher used cannot close the
/// production claim and says so.
#[test]
fn the_sixty_four_client_development_run_cannot_qualify() -> TestResult {
    let workload = Workload::select(64)?;
    assert_eq!(workload.profile(), Profile::BelowDefault);
    assert_eq!(workload.profile().label(), "below-default");
    assert!(!workload.qualifying());
    assert_eq!(
        workload.blockers(),
        [Blocker::PopulationBelowDefault].as_slice(),
        "a 64-client run has no other blocker: it is simply too small"
    );
    assert_eq!(
        Blocker::PopulationBelowDefault.label(),
        "population_below_default"
    );
    Ok(())
}

/// The default node budget is the published Section 19.2 arithmetic, and the
/// workload never changes any part of it.
#[test]
fn the_default_node_budget_is_the_published_arithmetic() -> TestResult {
    let budget = NodeBudget::default_node()?;
    assert_eq!(
        budget.parts(),
        [
            6_442_450_944,
            805_306_368,
            117_440_480,
            301_989_888,
            5_217_714_208
        ]
    );
    assert_eq!(
        budget.idle_charge_bytes(DEFAULT_CLIENT_CONNECTIONS)?,
        3_276_800_000
    );
    Ok(())
}

/// Section 28.7 admits the default population's charges, and Section 19.3
/// stops new connections first. The pilot must report that blocker with the
/// population that provokes it (issue #113).
#[test]
fn the_default_population_is_charged_within_the_pool_but_stopped_by_overload() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    let budget = workload.budget();
    assert!(
        budget.idle_charge_bytes(DEFAULT_CLIENT_CONNECTIONS)? <= budget.protocol_pool_bytes(),
        "the default population's charges fit the live pool"
    );
    assert_eq!(budget.clients_at_percent(GUEST_STOP_PERCENT), 40_755);
    assert_eq!(budget.clients_at_percent(CONNECTION_STOP_PERCENT), 45_849);
    assert_eq!(budget.clients_at_percent(EVICTION_PERCENT), 48_396);
    assert_eq!(
        workload.blockers(),
        [Blocker::OverloadStopsAdmission].as_slice()
    );
    assert!(!workload.qualifying(), "the blocker is open");
    Ok(())
}

/// The largest population Section 19.3 admits today has no admission blocker
/// and is still not production: it is below the per-node default.
#[test]
fn the_largest_admissible_population_is_still_below_the_default() -> TestResult {
    let budget = NodeBudget::default_node()?;
    let admissible = budget.clients_at_percent(CONNECTION_STOP_PERCENT);
    let workload = Workload::select(2 * admissible)?;
    assert_eq!(workload.per_node_connections(), admissible);
    assert_eq!(
        workload.blockers(),
        [Blocker::PopulationBelowDefault].as_slice()
    );
    Ok(())
}

/// The generator holds the per-/32 ceiling at its Section 19.2 hard maximum
/// and spreads the addresses it needs over distinct /24s.
#[test]
fn the_generator_spreads_sources_within_the_published_ceiling() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    let generator = workload.generator();
    assert_eq!(
        generator.connections_per_address(),
        MAX_DIRECT_CONNECTIONS_PER_ADDRESS
    );
    assert_eq!(generator.addresses_per_node(), 196);
    assert_eq!(generator.subnets_per_node(), 25);
    Ok(())
}

/// Every worker's source address is inside loopback, the two edges never
/// share one, and no more than the configured ceiling lands on any /32.
#[test]
fn every_generator_source_address_is_distinct_and_bounded() -> TestResult {
    let workload = Workload::select(4_096)?;
    let generator = workload.generator();
    let mut counts = BTreeMap::<Ipv4Addr, u64>::new();
    for index in 0..4_096_usize {
        let address = generator.source_address(index % CLIENT_NODES, index)?;
        assert_eq!(address.octets().first().copied(), Some(127));
        let entry = counts.entry(address).or_default();
        *entry += 1;
    }
    assert!(
        counts
            .values()
            .all(|count| *count <= generator.connections_per_address()),
        "no source /32 exceeds the configured per-address ceiling"
    );
    let edges: BTreeSet<Option<u8>> = counts
        .keys()
        .map(|address| address.octets().get(1).copied())
        .collect();
    assert_eq!(
        edges,
        [
            Some(GENERATOR_OCTET_BASE),
            Some(GENERATOR_OCTET_BASE.saturating_add(1))
        ]
        .into_iter()
        .collect::<BTreeSet<Option<u8>>>(),
        "each edge sources from its own loopback block"
    );
    Ok(())
}

/// The load population is partitioned so no channel exceeds the Section 19.2
/// default member ceiling.
#[test]
fn load_channels_stay_within_the_default_member_ceiling() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    assert_eq!(workload.load_channels(), 25);
    let mut members = BTreeMap::<String, u64>::new();
    let total = usize::try_from(workload.total_connections())?;
    for index in 0..total {
        let entry = members.entry(workload.load_channel(index)?).or_default();
        *entry += 1;
    }
    assert_eq!(members.len(), 25);
    assert!(
        members
            .values()
            .all(|count| *count <= DEFAULT_MEMBERS_PER_CHANNEL),
        "no load channel exceeds 4,096 members"
    );
    Ok(())
}

/// A pilot population still joins exactly one load channel.
#[test]
fn a_pilot_population_uses_one_load_channel() -> TestResult {
    let workload = Workload::select(64)?;
    assert_eq!(workload.load_channels(), 1);
    assert_eq!(workload.load_channel(63)?, "#load0");
    Ok(())
}

/// Spreading the generator over source addresses is what keeps the paced
/// warm-up of a production population bounded.
#[test]
fn the_generator_spread_bounds_the_paced_warm_up() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    assert_eq!(workload.workers_per_address(), 256);
    assert_eq!(workload.slot_index(0)?, 0);
    // Consecutive indices alternate edges, and consecutive slots on one edge
    // are on different source addresses, so the first 196 of them wait none.
    assert_eq!(workload.slot_index(2 * 195)?, 0);
    assert_eq!(workload.slot_index(2 * 196)?, 1);
    let pilot = Workload::select(64)?;
    assert_eq!(pilot.workers_per_address(), 32);
    assert_eq!(pilot.slot_index(63)?, 31);
    Ok(())
}

/// The listener ceiling stays inside the Section 19.2 hard maximum and
/// refuses a population that would need more.
#[test]
fn the_listener_ceiling_respects_the_hard_maximum() -> TestResult {
    let workload = Workload::select(2 * DEFAULT_CLIENT_CONNECTIONS)?;
    assert_eq!(workload.listener_ceiling(16)?, 50_016);
    let largest = Workload::select(2 * MAX_CLIENT_CONNECTIONS)?;
    assert!(
        largest.listener_ceiling(16).is_err(),
        "a ceiling above the hard maximum must be refused, not clamped"
    );
    Ok(())
}
