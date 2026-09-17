#![forbid(unsafe_code)]

//! CAP-01: the linear domain scans measured at the advertised populations.
//!
//! Section 19.2 publishes 100,000 live global channels, 10,000 local channels
//! per edge, 4,096 members per channel, 256 invites per channel and 100,000
//! outstanding invites network-wide. `TODO.md` records that
//! `reserved_nickname_owner`, `validate_new_invite_id`, the invite purge in
//! `apply_close_session` and the network invite total scan their maps linearly
//! per command, which was "fine at Stage 06 scale". This module builds those
//! advertised populations and measures each scan, so the campaign's profiling
//! obligation rests on a number rather than on an opinion.
//!
//! These are measurements, not deadline assertions: the ceiling below only
//! fails a pathological regression. The printed line is the deliverable and is
//! copied into `docs/stage-10-capacity-workload.md` with its host.

use std::time::{Duration, Instant};

use agenc_ircd_types::{AccountRandomId, Generation, PublicCloak, ServerId};

use super::*;
use crate::ChannelState;

/// Section 19.2 default live global channels.
const GLOBAL_CHANNELS: usize = 100_000;
/// Section 19.2 default live local channels per edge.
const LOCAL_CHANNELS: usize = 10_000;
/// Section 19.2 default outstanding invites network-wide.
const NETWORK_INVITES: usize = 100_000;
/// Section 19.2 default outstanding invites per channel.
const INVITES_PER_CHANNEL: usize = 256;
/// Section 19.2 default members per channel.
const MEMBERS_PER_CHANNEL_TARGET: usize = 4_096;
/// Accounts holding one reserved nickname each: the Section 19.2 default
/// client population of one node.
const ACCOUNTS: usize = 50_000;
/// Sessions the measured state holds.
const SESSIONS: usize = 1_024;
/// A generous ceiling for one measured scan in an unoptimized build. The
/// measurement is the deliverable; this only fails a pathological regression.
const SCAN_CEILING: Duration = Duration::from_secs(30);
/// The fraction of the advertised population the default suite exercises, so
/// the harness itself is covered without adding the full build to every run.
const CONTROL_DIVISOR: usize = 100;
/// The cloak alphabet: lowercase base32 without `0`, `1`, `8` and `9`.
const CLOAK_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The advertised populations one measurement builds.
#[derive(Clone, Copy)]
struct Population {
    global_channels: usize,
    local_channels: usize,
    network_invites: usize,
    members: usize,
    accounts: usize,
    sessions: usize,
}

impl Population {
    /// The Section 19.2 defaults.
    const fn advertised() -> Self {
        Self {
            global_channels: GLOBAL_CHANNELS,
            local_channels: LOCAL_CHANNELS,
            network_invites: NETWORK_INVITES,
            members: MEMBERS_PER_CHANNEL_TARGET,
            accounts: ACCOUNTS,
            sessions: SESSIONS,
        }
    }

    /// The same shape at a fraction of the size.
    const fn reduced(divisor: usize) -> Self {
        Self {
            global_channels: GLOBAL_CHANNELS / divisor,
            local_channels: LOCAL_CHANNELS / divisor,
            network_invites: NETWORK_INVITES / divisor,
            members: MEMBERS_PER_CHANNEL_TARGET / divisor,
            accounts: ACCOUNTS / divisor,
            sessions: SESSIONS / divisor,
        }
    }

    /// Channels the state holds.
    const fn channels(&self) -> usize {
        self.global_channels + self.local_channels
    }
}

/// A distinct sixteen-byte identity for one index within one class.
fn identity(class: u8, index: usize) -> Result<[u8; 16], DomainError> {
    let mut bytes = [class; 16];
    let value = u64::try_from(index).map_err(|_error| DomainError::Overflow)?;
    let (head, _rest) = bytes.split_at_mut(8);
    head.copy_from_slice(&value.to_be_bytes());
    Ok(bytes)
}

/// The same for the thirty-two-byte connection-bound values.
fn identity32(class: u8, index: usize) -> Result<[u8; 32], DomainError> {
    let mut bytes = [class; 32];
    let value = u64::try_from(index).map_err(|_error| DomainError::Overflow)?;
    let (head, _rest) = bytes.split_at_mut(8);
    head.copy_from_slice(&value.to_be_bytes());
    Ok(bytes)
}

/// Encodes `index` in the cloak's lowercase base32 alphabet.
fn cloak_component(index: usize, width: usize) -> String {
    let mut value = index;
    let mut text = String::new();
    for _ in 0..width {
        let digit = CLOAK_ALPHABET.get(value % CLOAK_ALPHABET.len()).copied();
        text.push(char::from(digit.unwrap_or(b'a')));
        value /= CLOAK_ALPHABET.len();
    }
    text
}

fn user(index: usize) -> Result<UserId, DomainError> {
    Ok(UserId::from_bytes(identity(1, index)?))
}

fn account(index: usize) -> Result<AccountId, DomainError> {
    Ok(AccountId::from_random(AccountRandomId::from_bytes(
        identity(2, index)?,
    )))
}

fn channel_instance(index: usize) -> Result<ChannelInstanceId, DomainError> {
    Ok(ChannelInstanceId::from_bytes(identity(3, index)?))
}

fn invitation(index: usize) -> Result<InviteId, DomainError> {
    Ok(InviteId::from_bytes(identity(4, index)?))
}

/// Builds one channel at `index`; the first `global` indices are global and
/// the rest are local, as the two Section 19.2 rows separate them.
fn channel(index: usize, global: usize) -> Result<ChannelState, DomainError> {
    let name = if index < global {
        ChannelNameValue::parse(&format!("#global{index:07}"))?
    } else {
        ChannelNameValue::parse(&format!("&local{index:07}"))?
    };
    let owner = user(index)?;
    Ok(ChannelState::new_ephemeral(
        channel_instance(index)?,
        name,
        Principal::Guest(owner),
        Membership::new(owner, None, Role::Owner),
        UtcSecond::from_unix_seconds(1_000),
        Revision::new(1)?,
    ))
}

/// Builds one live invitation targeted at a guest principal.
fn invite(index: usize, target: UserId) -> Result<Invite, DomainError> {
    Ok(Invite {
        invite_id: invitation(index)?,
        target: Principal::Guest(target),
        inviter: user(0)?,
        creation_revision: Revision::new(1)?,
        expires_at: MonotonicTick::from_ticks(INVITE_LIFETIME_MILLIS),
        expires_at_utc: UtcSecond::from_unix_seconds(1_600),
    })
}

/// Builds one session with a distinct nickname and cloak.
fn session(index: usize) -> Result<SessionState, DomainError> {
    let cloak = PublicCloak::parse(&cloak_component(index, 10), &cloak_component(index, 16))?;
    Ok(SessionState::from_seed(SessionSeed {
        session_id: SessionId::from_bytes(identity(5, index)?),
        user_id: user(index)?,
        home_server_id: ServerId::from_bytes(identity(6, 0)?),
        account_id: Some(account(index)?),
        account_session_generation: Generation::new(1)?,
        generation: Generation::new(1)?,
        nickname: NicknameValue::parse(&format!("user{index:06}"))?,
        display_name: DisplayNameValue::prepare(&format!("User {index}"))?,
        public_cloak: cloak,
        connection_nonce: identity32(7, index)?,
        negotiated_capability_hash: identity32(8, index)?,
        created_at_utc: UtcSecond::from_unix_seconds(10),
        revision: Revision::new(1)?,
    }))
}

/// Fills channels' invite maps up to the network total, at most the Section
/// 19.2 per-channel default in each one.
fn install_invites(state: &mut DomainState, total: usize) -> Result<(), DomainError> {
    let mut placed = 0_usize;
    let ids: Vec<ChannelInstanceId> = state.channels.keys().copied().collect();
    for id in ids {
        if placed >= total {
            break;
        }
        let channel = state
            .channels
            .get_mut(&id)
            .ok_or(DomainError::InvariantViolation)?;
        let wanted = INVITES_PER_CHANNEL.min(total - placed);
        for slot in 0..wanted {
            let target = user(placed + slot)?;
            channel
                .invites
                .insert(invitation(placed + slot)?, invite(placed + slot, target)?);
        }
        placed = placed.saturating_add(wanted);
    }
    Ok(())
}

/// Fills the first channel with the advertised member population.
fn install_members(state: &mut DomainState, members: usize) -> Result<(), DomainError> {
    let id = channel_instance(0)?;
    let channel = state
        .channels
        .get_mut(&id)
        .ok_or(DomainError::InvariantViolation)?;
    for index in 0..members {
        let member = user(index)?;
        channel
            .memberships
            .insert(member, Membership::new(member, None, Role::Member));
    }
    Ok(())
}

/// Installs the account population, each with one reserved nickname.
fn install_accounts(state: &mut DomainState, accounts: usize) -> Result<(), DomainError> {
    for index in 0..accounts {
        let id = account(index)?;
        let mut held = AccountState::new(id, Generation::new(1)?, Revision::new(0)?);
        held.reserved_nicknames
            .insert(NicknameValue::parse(&format!("reserved{index:06}"))?);
        state.accounts.insert(id, held);
    }
    Ok(())
}

/// Builds the advertised state: channels of both scopes, the network invite
/// population, one full channel, accounts with reserved nicknames, and
/// sessions that belong to accounts.
fn advertised_state(population: Population) -> Result<DomainState, DomainError> {
    let mut state = DomainState::new()?;
    for index in 0..population.channels() {
        let built = channel(index, population.global_channels)?;
        state
            .channel_names
            .insert(built.name.clone(), built.channel_id);
        state.channels.insert(built.channel_id, built);
    }
    install_invites(&mut state, population.network_invites)?;
    install_members(&mut state, population.members)?;
    install_accounts(&mut state, population.accounts)?;
    for index in 0..population.sessions {
        let built = session(index)?;
        state
            .nicknames
            .insert(built.nickname().clone(), built.user_id());
        state
            .session_ids
            .insert(built.session_id(), built.user_id());
        state
            .public_cloaks
            .insert(built.public_cloak(), built.user_id());
        state.sessions.insert(built.user_id(), built);
    }
    Ok(state)
}

/// Every measured scan of one built state, in microseconds.
struct Measurements {
    operational_usage: u128,
    channel_scope_counts: u128,
    validate_new_invite_id: u128,
    invite_capacity: u128,
    reserved_nickname_owner: u128,
    close_session_invite_purge: u128,
}

/// Measures the four read-only scans, checking on the way that each one really
/// saw the advertised population.
fn measure_reads(state: &DomainState, population: Population) -> Result<[u128; 4], DomainError> {
    let started = Instant::now();
    let usage = state.operational_usage()?;
    let usage_time = started.elapsed().as_micros();
    assert_eq!(usage.global_channels, population.global_channels);
    assert_eq!(usage.local_channels, population.local_channels);
    assert_eq!(usage.invites_global, population.network_invites);
    assert_eq!(usage.members_per_channel, population.members);

    let started = Instant::now();
    let (local, global) = state.channel_scope_counts();
    let scope_time = started.elapsed().as_micros();
    assert_eq!(local, population.local_channels);
    assert_eq!(global, population.global_channels);

    // The worst case of the per-command uniqueness check: an identifier no
    // channel holds, so every channel's invite map is probed.
    let fresh = invitation(usize::MAX / 2)?;
    let started = Instant::now();
    let unique = state.validate_new_invite_id(fresh);
    let invite_id_time = started.elapsed().as_micros();
    assert!(unique.is_ok(), "a fresh invitation identity must be unique");

    let first = *state
        .channels
        .keys()
        .next()
        .ok_or(DomainError::InvariantViolation)?;
    let subject = state
        .channels
        .get(&first)
        .ok_or(DomainError::InvariantViolation)?;
    let started = Instant::now();
    let _capacity = state.validate_invite_capacity(
        subject,
        Principal::Guest(user(usize::MAX / 4)?),
        MonotonicTick::from_ticks(0),
    );
    let capacity_time = started.elapsed().as_micros();
    Ok([usage_time, scope_time, invite_id_time, capacity_time])
}

/// Measures every scan the profiling matrix names.
fn measure_state(
    state: &mut DomainState,
    population: Population,
) -> Result<Measurements, DomainError> {
    let [usage_time, scope_time, invite_id_time, capacity_time] = measure_reads(state, population)?;
    // The worst case of the reserved-nickname scan: a nickname no account
    // reserved, so every account is visited.
    let absent = NicknameValue::parse("absentnick")?;
    let started = Instant::now();
    let owner = state.reserved_nickname_owner(&absent);
    let nickname_time = started.elapsed().as_micros();
    assert!(owner.is_none(), "no account reserved the probe nickname");

    let leaving = user(0)?;
    let started = Instant::now();
    state.apply_close_session(leaving, Revision::new(2)?);
    let purge_time = started.elapsed().as_micros();
    assert!(
        !state.sessions.contains_key(&leaving),
        "the closed session was removed"
    );
    Ok(Measurements {
        operational_usage: usage_time,
        channel_scope_counts: scope_time,
        validate_new_invite_id: invite_id_time,
        invite_capacity: capacity_time,
        reserved_nickname_owner: nickname_time,
        close_session_invite_purge: purge_time,
    })
}

/// Prints one measurement set and refuses a pathological scan.
fn report(label: &str, population: Population, measured: &Measurements) {
    println!(
        "advertised scans [{label}]: channels={} invites={} members={} accounts={} sessions={} \
         operational_usage_us={} channel_scope_counts_us={} validate_new_invite_id_us={} \
         invite_capacity_us={} reserved_nickname_owner_us={} close_session_invite_purge_us={}",
        population.channels(),
        population.network_invites,
        population.members,
        population.accounts,
        population.sessions,
        measured.operational_usage,
        measured.channel_scope_counts,
        measured.validate_new_invite_id,
        measured.invite_capacity,
        measured.reserved_nickname_owner,
        measured.close_session_invite_purge
    );
    let ceiling = SCAN_CEILING.as_micros();
    for (name, value) in [
        ("operational_usage", measured.operational_usage),
        ("channel_scope_counts", measured.channel_scope_counts),
        ("validate_new_invite_id", measured.validate_new_invite_id),
        ("invite_capacity", measured.invite_capacity),
        ("reserved_nickname_owner", measured.reserved_nickname_owner),
        (
            "close_session_invite_purge",
            measured.close_session_invite_purge,
        ),
    ] {
        assert!(value < ceiling, "{name} took {value} us at {label}");
    }
}

/// The reduced control: the harness builds the same shape and every scan sees
/// the population it was given. This runs in the default suite.
#[test]
fn every_advertised_scan_is_measured_at_a_reduced_population() -> Result<(), DomainError> {
    let population = Population::reduced(CONTROL_DIVISOR);
    let mut state = advertised_state(population)?;
    let measured = measure_state(&mut state, population)?;
    report("reduced", population, &measured);
    Ok(())
}

/// The profiling matrix at the Section 19.2 advertised populations. The whole
/// state costs about 400 ms to build and about 100 MB, so it stays in the
/// default suite and the measurement cannot rot.
#[test]
fn every_advertised_scan_is_measured_at_the_published_limits() -> Result<(), DomainError> {
    let population = Population::advertised();
    let started = Instant::now();
    let mut state = advertised_state(population)?;
    println!(
        "advertised scans: built {} channels in {} ms",
        population.channels(),
        started.elapsed().as_millis()
    );
    let measured = measure_state(&mut state, population)?;
    report("advertised", population, &measured);
    Ok(())
}
