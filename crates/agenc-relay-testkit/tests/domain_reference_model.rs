#![forbid(unsafe_code)]

//! Stage-03 independent model and generated state-machine comparisons.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt;

use agenc_relay_domain::{
    CanonicalCommand, ChannelNameValue, ChannelTarget, DomainError, ExternalInputs, ModeChange,
    ModeOperation, NicknameValue, PersistencePolicy, Principal, Role, Visibility, VisibilityMode,
};
use agenc_relay_testkit::{
    ALL_REFERENCE_COMMAND_KINDS, DomainTestIdentity, ReferenceCommand, ReferenceCommandKind,
    ReferenceDomainError, ReferenceDomainModel, ReferenceDomainStep, ReferenceMessageTarget,
    ReferenceModeChange, ReferenceModeOperation, ReferencePrincipal, ReferenceRole,
    ReferenceVisibility, ReferenceVisibilityMode, account_id, apply_command, apply_plan, bytes,
    channel_id, create_account, deterministic_cloak, generation, open_session,
    registered_admission,
};
use agenc_relay_types::{
    AccountId, InviteId, MonotonicTick, PublicCloak, SessionId, UserId, UtcSecond,
};

const GENERATED_SEEDS: &str =
    include_str!("../../../test-data/property/domain-stage-three-v1.steps");
const ACCOUNT_SEED_END: u8 = 8;
const SESSION_SEED_START: u8 = 16;
const SESSION_SEED_END: u8 = 47;
const CHANNEL_SEED_START: u8 = 64;
const CHANNEL_SEED_END: u8 = 79;
const INVITE_SEED_START: u8 = 96;
const INVITE_SEED_END: u8 = 111;

#[test]
fn reference_model_executes_every_command_with_real_behavior() -> Result<(), Box<dyn Error>> {
    let mut observed = BTreeSet::new();
    for command in ALL_REFERENCE_COMMAND_KINDS {
        let (mut model, operation, mutating) = reference_command_fixture(*command)?;
        let revision = model.snapshot().revision;
        model.apply(ReferenceDomainStep::ExecuteCommand {
            user: 2,
            command: operation,
        })?;
        let snapshot = model.snapshot();
        assert_eq!(snapshot.revision, revision + u64::from(mutating));
        assert!(snapshot.observed_commands.contains(command));
        observed.insert(*command);
    }
    assert_eq!(
        observed.into_iter().collect::<Vec<_>>(),
        ALL_REFERENCE_COMMAND_KINDS
    );
    Ok(())
}

fn reference_command_fixture(
    kind: ReferenceCommandKind,
) -> Result<(ReferenceDomainModel, ReferenceCommand, bool), ReferenceDomainError> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 7,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 1,
        user: 2,
        account: Some(1),
        account_generation: 7,
        session_generation: 1,
        nickname: "registry-owner".to_owned(),
        cloak: 3,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 4,
        user: 5,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "registry-member".to_owned(),
        cloak: 6,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 2,
        channel: "#registry".to_owned(),
        instance: 8,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 5,
        channel: "#registry".to_owned(),
        instance: 8,
    })?;
    let mutating = !matches!(
        kind,
        ReferenceCommandKind::Privmsg
            | ReferenceCommandKind::Notice
            | ReferenceCommandKind::Tagmsg
            | ReferenceCommandKind::Names
            | ReferenceCommandKind::List
            | ReferenceCommandKind::Motd
            | ReferenceCommandKind::Lusers
            | ReferenceCommandKind::Version
            | ReferenceCommandKind::Time
            | ReferenceCommandKind::Admin
            | ReferenceCommandKind::Info
            | ReferenceCommandKind::Links
            | ReferenceCommandKind::Who
            | ReferenceCommandKind::Whois
            | ReferenceCommandKind::Whowas
            | ReferenceCommandKind::Ison
            | ReferenceCommandKind::Userhost
            | ReferenceCommandKind::Chathistory
    );
    let command = match kind {
        ReferenceCommandKind::Nick => ReferenceCommand::Nick {
            nickname: "registry-renamed".to_owned(),
        },
        ReferenceCommandKind::Quit => ReferenceCommand::Quit,
        ReferenceCommandKind::Join => ReferenceCommand::Join {
            channel: "#registry-two".to_owned(),
            instance: 9,
        },
        ReferenceCommandKind::Part => ReferenceCommand::Part { instance: 8 },
        ReferenceCommandKind::Mode => ReferenceCommand::ModeVisibility {
            instance: 8,
            visibility: ReferenceVisibility::Secret,
        },
        ReferenceCommandKind::Topic => ReferenceCommand::TopicSet { instance: 8 },
        ReferenceCommandKind::Invite => ReferenceCommand::Invite {
            target: 5,
            instance: 8,
            invite: 10,
            expires_at: 100,
        },
        ReferenceCommandKind::Kick => ReferenceCommand::Kick {
            target: 5,
            instance: 8,
        },
        ReferenceCommandKind::Privmsg
        | ReferenceCommandKind::Notice
        | ReferenceCommandKind::Tagmsg => ReferenceCommand::Message {
            kind,
            target: ReferenceMessageTarget::Channel(8),
        },
        ReferenceCommandKind::Away => ReferenceCommand::Away { enabled: true },
        ReferenceCommandKind::Monitor => ReferenceCommand::MonitorAdd {
            nickname: "registry-member".to_owned(),
        },
        ReferenceCommandKind::Setname => ReferenceCommand::Setname {
            display_name: "Registry Owner".to_owned(),
        },
        ReferenceCommandKind::Acct => ReferenceCommand::AccountUpdate,
        ReferenceCommandKind::Chanctl => ReferenceCommand::ChannelRegistration {
            instance: 8,
            registered: true,
        },
        ReferenceCommandKind::Chathistory => {
            model.apply(ReferenceDomainStep::ExecuteCommand {
                user: 2,
                command: ReferenceCommand::ChannelRegistration {
                    instance: 8,
                    registered: true,
                },
            })?;
            ReferenceCommand::Chathistory { instance: 8 }
        }
        ReferenceCommandKind::Names
        | ReferenceCommandKind::List
        | ReferenceCommandKind::Motd
        | ReferenceCommandKind::Lusers
        | ReferenceCommandKind::Version
        | ReferenceCommandKind::Time
        | ReferenceCommandKind::Admin
        | ReferenceCommandKind::Info
        | ReferenceCommandKind::Links
        | ReferenceCommandKind::Who
        | ReferenceCommandKind::Whois
        | ReferenceCommandKind::Whowas
        | ReferenceCommandKind::Ison
        | ReferenceCommandKind::Userhost => ReferenceCommand::Query(kind),
    };
    Ok((model, command, mutating))
}

#[test]
fn rejected_reference_steps_leave_every_snapshot_field_unchanged() -> Result<(), Box<dyn Error>> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 7,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 10,
        user: 20,
        account: Some(1),
        account_generation: 7,
        session_generation: 1,
        nickname: "owner".to_owned(),
        cloak: 30,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 11,
        user: 21,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "member".to_owned(),
        cloak: 31,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 20,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 21,
        channel: "#reference".to_owned(),
        instance: 40,
    })?;

    let baseline = model.snapshot();
    assert_eq!(
        model.apply(ReferenceDomainStep::OpenSession {
            session: 12,
            user: 22,
            account: None,
            account_generation: 0,
            session_generation: 1,
            nickname: "member".to_owned(),
            cloak: 32,
        }),
        Err(ReferenceDomainError::Duplicate)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::Join {
            user: 21,
            channel: "#reference".to_owned(),
            instance: 41,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::DeleteAccount {
            account: 1,
            expected_generation: 6,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::SetRole {
            actor: 21,
            target: 20,
            instance: 40,
            role: ReferenceRole::Owner,
        }),
        Err(ReferenceDomainError::Forbidden)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::SwitchAccount {
            user: 20,
            account: None,
            expected_session_generation: 0,
            account_generation: 0,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), baseline);
    assert_eq!(
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 2,
        }),
        Err(ReferenceDomainError::Gap)
    );
    assert_eq!(model.snapshot(), baseline);

    model.apply(ReferenceDomainStep::FederationApply {
        origin: 5,
        sequence: 1,
    })?;
    let after_sequence = model.snapshot();
    assert_eq!(
        model.apply(ReferenceDomainStep::FederationApply {
            origin: 5,
            sequence: 1,
        }),
        Err(ReferenceDomainError::Stale)
    );
    assert_eq!(model.snapshot(), after_sequence);
    Ok(())
}

#[test]
fn reference_mode_vectors_follow_client_order_and_reject_duplicates_atomically()
-> Result<(), Box<dyn Error>> {
    let mut model = ReferenceDomainModel::new();
    model.apply(ReferenceDomainStep::CreateAccount {
        account: 1,
        generation: 1,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 11,
        user: 1,
        account: Some(1),
        account_generation: 1,
        session_generation: 1,
        nickname: "vector-owner".to_owned(),
        cloak: 1,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 12,
        user: 2,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "vector-member".to_owned(),
        cloak: 2,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 1,
        channel: "#vector".to_owned(),
        instance: 20,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 2,
        channel: "#vector".to_owned(),
        instance: 20,
    })?;
    model.apply(ReferenceDomainStep::SetRole {
        actor: 1,
        target: 2,
        instance: 20,
        role: ReferenceRole::Voice,
    })?;

    model.apply(ReferenceDomainStep::ApplyModeVector {
        actor: 1,
        instance: 20,
        changes: vec![
            ReferenceModeChange::Visibility {
                operation: ReferenceModeOperation::Add,
                mode: ReferenceVisibilityMode::Unlisted,
            },
            ReferenceModeChange::Visibility {
                operation: ReferenceModeOperation::Add,
                mode: ReferenceVisibilityMode::Secret,
            },
            ReferenceModeChange::Visibility {
                operation: ReferenceModeOperation::Remove,
                mode: ReferenceVisibilityMode::Unlisted,
            },
            ReferenceModeChange::Role {
                operation: ReferenceModeOperation::Add,
                target: 2,
                role: ReferenceRole::HalfOperator,
            },
            ReferenceModeChange::Role {
                operation: ReferenceModeOperation::Remove,
                target: 2,
                role: ReferenceRole::HalfOperator,
            },
            ReferenceModeChange::Visibility {
                operation: ReferenceModeOperation::Remove,
                mode: ReferenceVisibilityMode::Secret,
            },
        ],
    })?;
    let snapshot = model.snapshot();
    let channel = snapshot
        .channels
        .first()
        .ok_or("reference channel is absent")?;
    assert_eq!(channel.visibility, ReferenceVisibility::Listed);
    assert_eq!(
        channel.members.iter().find(|(user, _)| *user == 2),
        Some(&(2, ReferenceRole::Voice))
    );

    let before = model.snapshot();
    assert_eq!(
        model.apply(ReferenceDomainStep::ApplyModeVector {
            actor: 1,
            instance: 20,
            changes: vec![
                ReferenceModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
                ReferenceModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
            ],
        }),
        Err(ReferenceDomainError::Invalid)
    );
    assert_eq!(model.snapshot(), before);
    Ok(())
}

#[test]
fn reference_invitation_snapshots_retain_complete_principal_and_revision_fields()
-> Result<(), Box<dyn Error>> {
    let mut model = ReferenceDomainModel::new();
    for account in [1, 2] {
        model.apply(ReferenceDomainStep::CreateAccount {
            account,
            generation: 1,
        })?;
    }
    model.apply(ReferenceDomainStep::OpenSession {
        session: 11,
        user: 1,
        account: Some(1),
        account_generation: 1,
        session_generation: 1,
        nickname: "invite-owner".to_owned(),
        cloak: 1,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 12,
        user: 2,
        account: None,
        account_generation: 0,
        session_generation: 1,
        nickname: "invite-guest".to_owned(),
        cloak: 2,
    })?;
    model.apply(ReferenceDomainStep::OpenSession {
        session: 13,
        user: 3,
        account: Some(2),
        account_generation: 1,
        session_generation: 1,
        nickname: "invite-account".to_owned(),
        cloak: 3,
    })?;
    model.apply(ReferenceDomainStep::Join {
        user: 1,
        channel: "#invites".to_owned(),
        instance: 20,
    })?;

    let guest_creation_revision = model
        .snapshot()
        .revision
        .checked_add(1)
        .ok_or("reference revision overflowed")?;
    model.apply(ReferenceDomainStep::Invite {
        actor: 1,
        target: 2,
        instance: 20,
        invite: 30,
        expires_at: 700_000,
    })?;
    let snapshot = model.snapshot();
    let guest = snapshot
        .channels
        .first()
        .and_then(|channel| channel.invites.first())
        .ok_or("guest invitation is absent")?;
    assert_eq!(guest.invite, 30);
    assert_eq!(guest.target, ReferencePrincipal::Guest(2));
    assert_eq!(guest.inviter, 1);
    assert_eq!(guest.creation_revision, guest_creation_revision);
    assert_eq!(guest.expires_at, 700_000);

    model.apply(ReferenceDomainStep::CloseSession { user: 2 })?;
    assert!(
        model
            .snapshot()
            .channels
            .first()
            .is_some_and(|channel| channel.invites.is_empty())
    );
    model.apply(ReferenceDomainStep::Invite {
        actor: 1,
        target: 3,
        instance: 20,
        invite: 31,
        expires_at: 800_000,
    })?;
    model.apply(ReferenceDomainStep::CloseSession { user: 3 })?;
    let snapshot = model.snapshot();
    let account = snapshot
        .channels
        .first()
        .and_then(|channel| channel.invites.first())
        .ok_or("account invitation is absent")?;
    assert_eq!(account.target, ReferencePrincipal::Account(2));
    assert_eq!(account.inviter, 1);
    assert_eq!(account.expires_at, 800_000);
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelOperation {
    CreateAccount {
        account: u8,
        generation: u64,
    },
    OpenSession {
        seed: u8,
        nickname: String,
        account: Option<u8>,
        account_generation: u64,
    },
    SwitchAccount {
        seed: u8,
        account: Option<u8>,
        expected_session_generation: u64,
        account_generation: u64,
    },
    Rename {
        seed: u8,
        nickname: String,
    },
    CloseSession {
        seed: u8,
    },
    Join {
        seed: u8,
        channel: String,
        instance: u8,
    },
    Part {
        seed: u8,
        channel: String,
        instance: u8,
    },
    SetRole {
        actor: u8,
        target: u8,
        target_nickname: String,
        channel: String,
        instance: u8,
        role: ReferenceRole,
    },
    SetVisibility {
        actor: u8,
        channel: String,
        instance: u8,
        visibility: ReferenceVisibility,
    },
    ApplyModeVector {
        actor: u8,
        channel: String,
        instance: u8,
        changes: Vec<ModelModeChange>,
    },
    Invite {
        actor: u8,
        target: u8,
        target_nickname: String,
        channel: String,
        instance: u8,
        invite: u8,
        monotonic_now: u64,
    },
    DeleteAccount {
        account: u8,
        expected_generation: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelModeChange {
    Visibility {
        operation: ReferenceModeOperation,
        mode: ReferenceVisibilityMode,
    },
    Role {
        operation: ReferenceModeOperation,
        target: u8,
        target_nickname: String,
        role: ReferenceRole,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetainedRegression {
    name: String,
    seed: u64,
    steps: usize,
    fingerprint: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeedManifest {
    schema_version: u32,
    generator_version: u32,
    seed_count: usize,
    max_steps: usize,
    snapshot_cadence: String,
    seed_base: u64,
    seed_stride: u64,
    regressions: Vec<RetainedRegression>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct SequenceStats {
    accepted: usize,
    rejected: usize,
}

impl SequenceStats {
    fn checked_add(self, other: Self) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            accepted: self
                .accepted
                .checked_add(other.accepted)
                .ok_or("accepted-step count overflowed")?,
            rejected: self
                .rejected
                .checked_add(other.rejected)
                .ok_or("rejected-step count overflowed")?,
        })
    }

    fn record(&mut self, accepted: bool) -> Result<(), &'static str> {
        let counter = if accepted {
            &mut self.accepted
        } else {
            &mut self.rejected
        };
        *counter = counter
            .checked_add(1)
            .ok_or("per-seed step count overflowed")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepOutcome {
    error: Option<String>,
}

impl StepOutcome {
    fn accepted(&self) -> bool {
        self.error.is_none()
    }

    fn production(result: Result<(), DomainError>) -> Self {
        Self {
            error: result.err().map(|error| format!("{error:?}")),
        }
    }

    fn reference(result: Result<(), ReferenceDomainError>) -> Self {
        Self {
            error: result.err().map(|error| format!("{error:?}")),
        }
    }
}

#[derive(Debug)]
struct SequenceFailure {
    seed: u64,
    step: usize,
    minimal_failing_prefix: usize,
    operation: String,
    production: StepOutcome,
    reference: StepOutcome,
    detail: String,
    fingerprint: u64,
    prefix: String,
}

struct StepContext<'a> {
    seed: u64,
    step: usize,
    operations: &'a [ModelOperation],
    operation: &'a ModelOperation,
    production_outcome: &'a StepOutcome,
    reference_outcome: &'a StepOutcome,
}

impl StepContext<'_> {
    fn failure(&self, detail: impl Into<String>) -> SequenceFailure {
        SequenceFailure::at_step(
            self.seed,
            self.step,
            self.operations,
            self.operation,
            self.production_outcome.clone(),
            self.reference_outcome.clone(),
            detail,
        )
    }
}

struct SnapshotPair<'a> {
    production: &'a CanonicalDomainSnapshot,
    reference: &'a CanonicalDomainSnapshot,
}

impl SequenceFailure {
    fn initial(seed: u64, error: DomainError) -> Self {
        Self {
            seed,
            step: 0,
            minimal_failing_prefix: 0,
            operation: "initialize".to_owned(),
            production: StepOutcome {
                error: Some(format!("{error:?}")),
            },
            reference: StepOutcome { error: None },
            detail: "production state initialization failed".to_owned(),
            fingerprint: 0,
            prefix: String::new(),
        }
    }

    fn at_step(
        seed: u64,
        step: usize,
        operations: &[ModelOperation],
        operation: &ModelOperation,
        production: StepOutcome,
        reference: StepOutcome,
        detail: impl Into<String>,
    ) -> Self {
        let minimal_failing_prefix = step.saturating_add(1);
        let prefix = operations
            .iter()
            .take(minimal_failing_prefix)
            .enumerate()
            .map(|(index, operation)| format!("{index}:{operation:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        Self {
            seed,
            step,
            minimal_failing_prefix,
            operation: format!("{operation:?}"),
            production,
            reference,
            detail: detail.into(),
            fingerprint: operation_fingerprint(operations.iter().take(minimal_failing_prefix)),
            prefix,
        }
    }
}

impl fmt::Display for SequenceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Stage-03 model mismatch\nseed=0x{:016x}\nstep={}\n\
             minimal_failing_prefix={}\nfingerprint=0x{:016x}\n\
             operation={}\nproduction={:?}\nreference={:?}\ndetail={}\n\
             replay=AGENC_STAGE3_SEED=0x{:016x} AGENC_STAGE3_STEPS={} \
             cargo test -p agenc-relay-testkit --test domain_reference_model \
             seeded_valid_and_invalid_sequences_match_complete_snapshots -- --exact\n\
             promotion_record=REGRESSION|failure-{:016x}|0x{:016x}|{}|0x{:016x}\n\
             operations:\n{}",
            self.seed,
            self.step,
            self.minimal_failing_prefix,
            self.fingerprint,
            self.operation,
            self.production,
            self.reference,
            self.detail,
            self.seed,
            self.minimal_failing_prefix,
            self.fingerprint,
            self.seed,
            self.minimal_failing_prefix,
            self.fingerprint,
            self.prefix,
        )
    }
}

impl Error for SequenceFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalSessionSnapshot {
    seed: u8,
    session_seed: u8,
    account: Option<u8>,
    account_generation: u64,
    generation: u64,
    nickname: String,
    cloak: u8,
    channels: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalChannelSnapshot {
    instance: u8,
    name: String,
    visibility: ReferenceVisibility,
    members: Vec<(u8, ReferenceRole)>,
    invites: Vec<CanonicalInviteSnapshot>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CanonicalInviteSnapshot {
    invite: u8,
    target: ReferencePrincipal,
    inviter: u8,
    creation_revision: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalDomainSnapshot {
    revision: u64,
    accounts: Vec<(u8, u64)>,
    sessions: Vec<CanonicalSessionSnapshot>,
    channels: Vec<CanonicalChannelSnapshot>,
    federation_sequences: Vec<(u16, u64)>,
    away_users: Vec<u8>,
    monitors: Vec<(u8, Vec<String>)>,
    display_names: Vec<(u8, String)>,
    account_updates: Vec<(u8, u64)>,
    topics: Vec<u8>,
    registered_channels: Vec<u8>,
    observed_commands: Vec<ReferenceCommandKind>,
}

#[test]
fn seeded_valid_and_invalid_sequences_match_complete_snapshots() -> Result<(), Box<dyn Error>> {
    let manifest = parse_seed_manifest(GENERATED_SEEDS)?;
    validate_seed_manifest(&manifest)?;
    if let Some((seed, steps)) = replay_override(&manifest)? {
        assert_mixed_outcomes(run_seed(seed, steps)?, "replay")?;
        return Ok(());
    }

    for regression in &manifest.regressions {
        assert_mixed_outcomes(
            run_seed(regression.seed, regression.steps)?,
            &regression.name,
        )?;
    }

    let seeds = expand_seed_range(&manifest)?;
    let mut totals = SequenceStats::default();
    for seed in &seeds {
        let stats = run_seed(*seed, manifest.max_steps)?;
        assert_mixed_outcomes(stats, "generated seed")?;
        totals = totals.checked_add(stats)?;
    }
    let minimum_each = seeds
        .len()
        .checked_mul(20)
        .ok_or("model-test coverage floor overflowed")?;
    assert!(totals.accepted >= minimum_each);
    assert!(totals.rejected >= minimum_each);
    Ok(())
}

fn assert_mixed_outcomes(stats: SequenceStats, label: &str) -> Result<(), Box<dyn Error>> {
    if stats.accepted == 0 || stats.rejected == 0 {
        return Err(format!("{label} did not exercise accepted and rejected operations").into());
    }
    Ok(())
}

fn parse_seed_manifest(input: &str) -> Result<SeedManifest, Box<dyn Error>> {
    let mut schema_version = None;
    let mut generator_version = None;
    let mut seed_count = None;
    let mut max_steps = None;
    let mut snapshot_cadence = None;
    let mut seed_range: Option<(u64, u64, usize)> = None;
    let mut regressions = Vec::new();

    for line in input.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('|').collect();
        match fields.as_slice() {
            ["CONFIG", "schema-version", value] => {
                set_once(&mut schema_version, value.parse()?)?;
            }
            ["CONFIG", "generator-version", value] => {
                set_once(&mut generator_version, value.parse()?)?;
            }
            ["CONFIG", "seed-count", value] => {
                set_once(&mut seed_count, value.parse()?)?;
            }
            ["CONFIG", "max-steps", value] => {
                set_once(&mut max_steps, value.parse()?)?;
            }
            ["CONFIG", "snapshot-cadence", value] => {
                set_once(&mut snapshot_cadence, (*value).to_owned())?;
            }
            ["SEED-RANGE", base, stride, count] => {
                set_once(
                    &mut seed_range,
                    (parse_seed(base)?, parse_seed(stride)?, count.parse()?),
                )?;
            }
            ["REGRESSION", name, seed, steps, fingerprint] => {
                regressions.push(RetainedRegression {
                    name: (*name).to_owned(),
                    seed: parse_seed(seed)?,
                    steps: steps.parse()?,
                    fingerprint: parse_seed(fingerprint)?,
                })
            }
            _ => return Err("generated Stage-03 seed record is malformed".into()),
        }
    }

    let (seed_base, seed_stride, range_count) =
        seed_range.ok_or("generated Stage-03 seed range is absent")?;
    let seed_count = seed_count.ok_or("generated Stage-03 seed count is absent")?;
    if range_count != seed_count {
        return Err("generated Stage-03 seed counts disagree".into());
    }
    Ok(SeedManifest {
        schema_version: schema_version.ok_or("generated Stage-03 schema is absent")?,
        generator_version: generator_version
            .ok_or("generated Stage-03 generator version is absent")?,
        seed_count,
        max_steps: max_steps.ok_or("generated Stage-03 step bound is absent")?,
        snapshot_cadence: snapshot_cadence
            .ok_or("generated Stage-03 snapshot cadence is absent")?,
        seed_base,
        seed_stride,
        regressions,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), Box<dyn Error>> {
    if slot.replace(value).is_some() {
        return Err("generated Stage-03 seed field is duplicated".into());
    }
    Ok(())
}

fn parse_seed(value: &str) -> Result<u64, Box<dyn Error>> {
    let hexadecimal = value
        .strip_prefix("0x")
        .ok_or("generated Stage-03 seed lacks a hexadecimal prefix")?;
    Ok(u64::from_str_radix(hexadecimal, 16)?)
}

fn validate_seed_manifest(manifest: &SeedManifest) -> Result<(), Box<dyn Error>> {
    if manifest.schema_version != 2
        || manifest.generator_version != 2
        || manifest.seed_count < 128
        || !(32..=128).contains(&manifest.max_steps)
        || manifest.snapshot_cadence != "after-every-step"
        || manifest.seed_stride == 0
        || manifest.regressions.is_empty()
    {
        return Err("generated Stage-03 seed manifest has invalid execution bounds".into());
    }
    if manifest
        .regressions
        .iter()
        .any(|regression| regression.steps == 0 || regression.steps > manifest.max_steps)
    {
        return Err("generated Stage-03 regression prefix exceeds the execution bound".into());
    }
    for regression in &manifest.regressions {
        let operations = generate_operations(regression.seed, regression.steps);
        let actual = operation_fingerprint(operations.iter());
        if actual != regression.fingerprint {
            return Err(format!(
                "generated Stage-03 regression fingerprint is stale: {} actual=0x{actual:016x}",
                regression.name
            )
            .into());
        }
    }
    let names: BTreeSet<&str> = manifest
        .regressions
        .iter()
        .map(|regression| regression.name.as_str())
        .collect();
    if names.len() != manifest.regressions.len() {
        return Err("generated Stage-03 regression name is duplicated".into());
    }
    Ok(())
}

fn replay_override(manifest: &SeedManifest) -> Result<Option<(u64, usize)>, Box<dyn Error>> {
    let Some(seed) = env::var_os("AGENC_STAGE3_SEED") else {
        return Ok(None);
    };
    let seed = parse_seed(
        seed.to_str()
            .ok_or("AGENC_STAGE3_SEED is not valid UTF-8")?,
    )?;
    let steps = match env::var("AGENC_STAGE3_STEPS") {
        Ok(value) => value.parse()?,
        Err(env::VarError::NotPresent) => manifest.max_steps,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("AGENC_STAGE3_STEPS is not valid UTF-8".into());
        }
    };
    if steps == 0 || steps > manifest.max_steps {
        return Err("AGENC_STAGE3_STEPS is outside the generated bound".into());
    }
    Ok(Some((seed, steps)))
}

fn expand_seed_range(manifest: &SeedManifest) -> Result<Vec<u64>, Box<dyn Error>> {
    (0..manifest.seed_count)
        .map(|index| {
            let index = u64::try_from(index)?;
            Ok(manifest
                .seed_stride
                .wrapping_mul(index)
                .wrapping_add(manifest.seed_base))
        })
        .collect()
}

fn run_seed(seed: u64, steps: usize) -> Result<SequenceStats, Box<SequenceFailure>> {
    let operations = generate_operations(seed, steps);
    let mut production = agenc_relay_domain::DomainState::new()
        .map_err(|error| Box::new(SequenceFailure::initial(seed, error)))?;
    let mut reference = ReferenceDomainModel::new();
    let mut stats = SequenceStats::default();

    for (step, operation) in operations.iter().enumerate() {
        let production_before = production_snapshot(&production).map_err(|detail| {
            sequence_snapshot_failure(seed, step, &operations, operation, detail)
        })?;
        let reference_before = reference_snapshot(&reference).map_err(|detail| {
            sequence_snapshot_failure(seed, step, &operations, operation, detail)
        })?;
        let production_outcome =
            StepOutcome::production(apply_production(&mut production, operation));
        let reference_outcome = StepOutcome::reference(apply_reference(&mut reference, operation));
        let context = StepContext {
            seed,
            step,
            operations: &operations,
            operation,
            production_outcome: &production_outcome,
            reference_outcome: &reference_outcome,
        };
        validate_step_models(&context, &production, &reference)?;
        let production_after = production_snapshot(&production).map_err(|detail| {
            sequence_snapshot_failure(seed, step, &operations, operation, detail)
        })?;
        let reference_after = reference_snapshot(&reference).map_err(|detail| {
            sequence_snapshot_failure(seed, step, &operations, operation, detail)
        })?;
        compare_step(
            &context,
            SnapshotPair {
                production: &production_before,
                reference: &reference_before,
            },
            SnapshotPair {
                production: &production_after,
                reference: &reference_after,
            },
        )?;
        stats
            .record(production_outcome.accepted())
            .map_err(|detail| Box::new(context.failure(detail)))?;
    }
    Ok(stats)
}

fn validate_step_models(
    context: &StepContext<'_>,
    production: &agenc_relay_domain::DomainState,
    reference: &ReferenceDomainModel,
) -> Result<(), Box<SequenceFailure>> {
    if let Err(error) = production.validate() {
        return Err(Box::new(
            context.failure(format!("production invariant failure: {error:?}")),
        ));
    }
    if let Err(error) = reference.validate_invariants() {
        return Err(Box::new(
            context.failure(format!("reference invariant failure: {error:?}")),
        ));
    }
    Ok(())
}

fn compare_step(
    context: &StepContext<'_>,
    before: SnapshotPair<'_>,
    after: SnapshotPair<'_>,
) -> Result<(), Box<SequenceFailure>> {
    if context.production_outcome.accepted() != context.reference_outcome.accepted() {
        return Err(Box::new(
            context.failure("production and reference acceptance differ"),
        ));
    }
    if !context.production_outcome.accepted()
        && (before.production != after.production || before.reference != after.reference)
    {
        return Err(Box::new(
            context.failure("a rejected operation changed authoritative state"),
        ));
    }
    if after.production != after.reference {
        return Err(Box::new(context.failure(format!(
            "canonical complete snapshots differ: production={:?}; reference={:?}",
            after.production, after.reference
        ))));
    }
    Ok(())
}

fn sequence_snapshot_failure(
    seed: u64,
    step: usize,
    operations: &[ModelOperation],
    operation: &ModelOperation,
    detail: String,
) -> Box<SequenceFailure> {
    Box::new(SequenceFailure::at_step(
        seed,
        step,
        operations,
        operation,
        StepOutcome {
            error: Some("snapshot-construction-failed".to_owned()),
        },
        StepOutcome { error: None },
        detail,
    ))
}

fn operation_fingerprint<'a>(operations: impl Iterator<Item = &'a ModelOperation>) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    operations.fold(OFFSET, |hash, operation| {
        format!("{operation:?}\n")
            .bytes()
            .fold(hash, |value, byte| {
                value.wrapping_mul(PRIME) ^ u64::from(byte)
            })
    })
}

fn generate_operations(seed: u64, max_steps: usize) -> Vec<ModelOperation> {
    let mut generator = SplitMix64::new(seed);
    let mut operations = Vec::with_capacity(max_steps);
    let mut round = 0_u8;
    while operations.len() < max_steps {
        let remaining = max_steps.saturating_sub(operations.len());
        operations.extend(
            generate_round(seed, round, &mut generator)
                .into_iter()
                .take(remaining),
        );
        round = round.wrapping_add(1);
    }
    operations
}

fn generate_round(seed: u64, round: u8, generator: &mut SplitMix64) -> Vec<ModelOperation> {
    let suffix = format!("{:04x}", seed as u16);
    let account = 1 + ((seed.wrapping_add(u64::from(round))) % u64::from(ACCOUNT_SEED_END)) as u8;
    let session_group = ((seed >> 16) % 8) as u8;
    let owner = SESSION_SEED_START + session_group.saturating_mul(4);
    let member = owner.saturating_add(1);
    let duplicate = owner.saturating_add(2);
    let extra = owner.saturating_add(3);
    let instance = CHANNEL_SEED_START + ((u64::from(round).wrapping_add(seed >> 24)) % 16) as u8;
    let invite = INVITE_SEED_START + ((u64::from(round).wrapping_add(seed >> 32)) % 16) as u8;
    let names = RoundNames {
        channel: format!("#model-{suffix}"),
        owner: format!("owner{suffix}"),
        member: format!("member{suffix}"),
        renamed: format!("renamed{suffix}"),
        extra: format!("extra{suffix}"),
    };
    let role = if generator.bounded(2) == 0 {
        ReferenceRole::Voice
    } else {
        ReferenceRole::HalfOperator
    };
    let visibility = if generator.bounded(2) == 0 {
        ReferenceVisibility::Unlisted
    } else {
        ReferenceVisibility::Secret
    };
    let monotonic_now = 10_000_u64
        .saturating_add(u64::from(round))
        .saturating_add(generator.bounded(1_000));
    build_round(
        RoundIdentities {
            account,
            owner,
            member,
            duplicate,
            extra,
            instance,
            invite,
        },
        names,
        role,
        visibility,
        monotonic_now,
    )
}

struct RoundIdentities {
    account: u8,
    owner: u8,
    member: u8,
    duplicate: u8,
    extra: u8,
    instance: u8,
    invite: u8,
}

struct RoundNames {
    channel: String,
    owner: String,
    member: String,
    renamed: String,
    extra: String,
}

fn build_round(
    ids: RoundIdentities,
    names: RoundNames,
    role: ReferenceRole,
    visibility: ReferenceVisibility,
    monotonic_now: u64,
) -> Vec<ModelOperation> {
    let raised_role = match role {
        ReferenceRole::Voice => ReferenceRole::HalfOperator,
        ReferenceRole::HalfOperator => ReferenceRole::Operator,
        ReferenceRole::Member
        | ReferenceRole::Operator
        | ReferenceRole::Administrator
        | ReferenceRole::Owner => ReferenceRole::Owner,
    };
    vec![
        ModelOperation::CreateAccount {
            account: ids.account,
            generation: 1,
        },
        ModelOperation::CreateAccount {
            account: ids.account,
            generation: 2,
        },
        ModelOperation::OpenSession {
            seed: ids.owner,
            nickname: names.owner.clone(),
            account: Some(ids.account),
            account_generation: 1,
        },
        ModelOperation::OpenSession {
            seed: ids.member,
            nickname: names.member.clone(),
            account: None,
            account_generation: 0,
        },
        ModelOperation::OpenSession {
            seed: ids.duplicate,
            nickname: names.member.clone(),
            account: None,
            account_generation: 0,
        },
        ModelOperation::Join {
            seed: ids.owner,
            channel: names.channel.clone(),
            instance: ids.instance,
        },
        ModelOperation::Join {
            seed: ids.member,
            channel: names.channel.clone(),
            instance: ids.instance,
        },
        ModelOperation::SetRole {
            actor: ids.member,
            target: ids.owner,
            target_nickname: names.owner.clone(),
            channel: names.channel.clone(),
            instance: ids.instance,
            role: ReferenceRole::Owner,
        },
        ModelOperation::SetRole {
            actor: ids.owner,
            target: ids.member,
            target_nickname: names.member.clone(),
            channel: names.channel.clone(),
            instance: ids.instance,
            role,
        },
        ModelOperation::SetVisibility {
            actor: ids.member,
            channel: names.channel.clone(),
            instance: ids.instance,
            visibility: ReferenceVisibility::Secret,
        },
        ModelOperation::SetVisibility {
            actor: ids.owner,
            channel: names.channel.clone(),
            instance: ids.instance,
            visibility,
        },
        ModelOperation::ApplyModeVector {
            actor: ids.owner,
            channel: names.channel.clone(),
            instance: ids.instance,
            changes: vec![
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Secret,
                },
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Remove,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
                ModelModeChange::Role {
                    operation: ReferenceModeOperation::Add,
                    target: ids.member,
                    target_nickname: names.member.clone(),
                    role: raised_role,
                },
                ModelModeChange::Role {
                    operation: ReferenceModeOperation::Remove,
                    target: ids.member,
                    target_nickname: names.member.clone(),
                    role: raised_role,
                },
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Remove,
                    mode: ReferenceVisibilityMode::Secret,
                },
            ],
        },
        ModelOperation::ApplyModeVector {
            actor: ids.owner,
            channel: names.channel.clone(),
            instance: ids.instance,
            changes: vec![
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
                ModelModeChange::Visibility {
                    operation: ReferenceModeOperation::Add,
                    mode: ReferenceVisibilityMode::Unlisted,
                },
            ],
        },
        ModelOperation::Part {
            seed: ids.member,
            channel: names.channel.clone(),
            instance: ids.instance,
        },
        ModelOperation::Part {
            seed: ids.member,
            channel: names.channel.clone(),
            instance: ids.instance,
        },
        ModelOperation::Invite {
            actor: ids.owner,
            target: ids.member,
            target_nickname: names.member,
            channel: names.channel.clone(),
            instance: ids.instance,
            invite: ids.invite,
            monotonic_now,
        },
        ModelOperation::SwitchAccount {
            seed: ids.member,
            account: Some(ids.account),
            expected_session_generation: 0,
            account_generation: 1,
        },
        ModelOperation::SwitchAccount {
            seed: ids.member,
            account: Some(ids.account),
            expected_session_generation: 1,
            account_generation: 1,
        },
        ModelOperation::Rename {
            seed: ids.member,
            nickname: names.renamed.clone(),
        },
        ModelOperation::Rename {
            seed: ids.owner,
            nickname: names.renamed,
        },
        ModelOperation::Join {
            seed: ids.member,
            channel: names.channel.clone(),
            instance: ids.instance,
        },
        ModelOperation::CloseSession { seed: ids.member },
        ModelOperation::CloseSession { seed: ids.member },
        ModelOperation::DeleteAccount {
            account: ids.account,
            expected_generation: 2,
        },
        ModelOperation::OpenSession {
            seed: ids.extra,
            nickname: names.extra,
            account: Some(ids.account),
            account_generation: 1,
        },
        ModelOperation::DeleteAccount {
            account: ids.account,
            expected_generation: 1,
        },
        ModelOperation::CloseSession { seed: ids.extra },
        ModelOperation::Part {
            seed: ids.owner,
            channel: names.channel,
            instance: ids.instance,
        },
        ModelOperation::DeleteAccount {
            account: ids.account,
            expected_generation: 1,
        },
        ModelOperation::DeleteAccount {
            account: ids.account,
            expected_generation: 1,
        },
    ]
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bounded(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}

fn apply_reference(
    model: &mut ReferenceDomainModel,
    operation: &ModelOperation,
) -> Result<(), ReferenceDomainError> {
    model.apply(reference_step(operation)?)
}

fn reference_step(operation: &ModelOperation) -> Result<ReferenceDomainStep, ReferenceDomainError> {
    let step = match operation {
        ModelOperation::CreateAccount {
            account,
            generation,
        } => ReferenceDomainStep::CreateAccount {
            account: u16::from(*account),
            generation: *generation,
        },
        ModelOperation::OpenSession {
            seed,
            nickname,
            account,
            account_generation,
        } => ReferenceDomainStep::OpenSession {
            session: u16::from(*seed),
            user: reference_user(*seed),
            account: account.map(u16::from),
            account_generation: *account_generation,
            session_generation: 1,
            nickname: nickname.clone(),
            cloak: u32::from(*seed),
        },
        ModelOperation::SwitchAccount {
            seed,
            account,
            expected_session_generation,
            account_generation,
        } => ReferenceDomainStep::SwitchAccount {
            user: reference_user(*seed),
            account: account.map(u16::from),
            expected_session_generation: *expected_session_generation,
            account_generation: *account_generation,
        },
        ModelOperation::Rename { seed, nickname } => ReferenceDomainStep::Rename {
            user: reference_user(*seed),
            nickname: nickname.clone(),
        },
        ModelOperation::CloseSession { seed } => ReferenceDomainStep::CloseSession {
            user: reference_user(*seed),
        },
        ModelOperation::Join {
            seed,
            channel,
            instance,
        } => ReferenceDomainStep::Join {
            user: reference_user(*seed),
            channel: channel.clone(),
            instance: u16::from(*instance),
        },
        ModelOperation::Part { seed, instance, .. } => ReferenceDomainStep::Part {
            user: reference_user(*seed),
            instance: u16::from(*instance),
        },
        ModelOperation::SetRole {
            actor,
            target,
            instance,
            role,
            ..
        } => ReferenceDomainStep::SetRole {
            actor: reference_user(*actor),
            target: reference_user(*target),
            instance: u16::from(*instance),
            role: *role,
        },
        ModelOperation::SetVisibility {
            actor,
            instance,
            visibility,
            ..
        } => ReferenceDomainStep::SetVisibility {
            actor: reference_user(*actor),
            instance: u16::from(*instance),
            visibility: *visibility,
        },
        ModelOperation::ApplyModeVector {
            actor,
            instance,
            changes,
            ..
        } => ReferenceDomainStep::ApplyModeVector {
            actor: reference_user(*actor),
            instance: u16::from(*instance),
            changes: changes.iter().map(reference_mode_change).collect(),
        },
        ModelOperation::Invite {
            actor,
            target,
            instance,
            invite,
            monotonic_now,
            ..
        } => ReferenceDomainStep::Invite {
            actor: reference_user(*actor),
            target: reference_user(*target),
            instance: u16::from(*instance),
            invite: u16::from(*invite),
            expires_at: monotonic_now
                .checked_add(600_000)
                .ok_or(ReferenceDomainError::Overflow)?,
        },
        ModelOperation::DeleteAccount {
            account,
            expected_generation,
        } => ReferenceDomainStep::DeleteAccount {
            account: u16::from(*account),
            expected_generation: *expected_generation,
        },
    };
    Ok(step)
}

fn apply_production(
    state: &mut agenc_relay_domain::DomainState,
    operation: &ModelOperation,
) -> Result<(), DomainError> {
    match operation {
        ModelOperation::CreateAccount {
            account,
            generation: account_generation,
        } => create_account(state, *account, *account_generation).map(|_| ()),
        ModelOperation::OpenSession {
            seed,
            nickname,
            account,
            account_generation,
        } => {
            let authority = production_authority(*account, *account_generation)?;
            open_session(state, *seed, nickname, authority).map(|_| ())
        }
        ModelOperation::SwitchAccount {
            seed,
            account,
            expected_session_generation,
            account_generation,
        } => {
            let plan = state.plan_session_account_switch(
                production_user(*seed),
                generation(*expected_session_generation)?,
                production_authority(*account, *account_generation)?,
            )?;
            apply_plan(state, plan).map(|_| ())
        }
        ModelOperation::Rename { seed, nickname } => apply_production_command(
            state,
            *seed,
            CanonicalCommand::nick(NicknameValue::parse(nickname)?),
            None,
        ),
        ModelOperation::CloseSession { seed } => {
            apply_production_command(state, *seed, CanonicalCommand::quit(None), None)
        }
        ModelOperation::Join {
            seed,
            channel,
            instance,
        } => apply_production_join(state, *seed, channel, *instance),
        ModelOperation::Part { seed, channel, .. } => apply_production_command(
            state,
            *seed,
            CanonicalCommand::part(vec![ChannelNameValue::parse(channel)?], None)?,
            None,
        ),
        ModelOperation::SetRole {
            actor,
            target_nickname,
            channel,
            role,
            ..
        } => apply_production_command(
            state,
            *actor,
            CanonicalCommand::mode(
                ChannelNameValue::parse(channel)?,
                vec![ModeChange::Role {
                    operation: ModeOperation::Add,
                    target: NicknameValue::parse(target_nickname)?,
                    role: production_role(*role),
                }],
            )?,
            None,
        ),
        ModelOperation::SetVisibility {
            actor,
            channel,
            visibility,
            ..
        } => {
            let mode = match visibility {
                ReferenceVisibility::Unlisted => VisibilityMode::Unlisted,
                ReferenceVisibility::Secret => VisibilityMode::Secret,
                ReferenceVisibility::Listed => return Err(DomainError::InvalidArgument),
            };
            apply_production_command(
                state,
                *actor,
                CanonicalCommand::mode(
                    ChannelNameValue::parse(channel)?,
                    vec![ModeChange::Visibility {
                        operation: ModeOperation::Add,
                        mode,
                    }],
                )?,
                None,
            )
        }
        ModelOperation::ApplyModeVector {
            actor,
            channel,
            changes,
            ..
        } => apply_production_command(
            state,
            *actor,
            CanonicalCommand::mode(
                ChannelNameValue::parse(channel)?,
                changes
                    .iter()
                    .map(production_mode_change)
                    .collect::<Result<Vec<_>, _>>()?,
            )?,
            None,
        ),
        ModelOperation::Invite {
            actor,
            target_nickname,
            channel,
            invite,
            monotonic_now,
            ..
        } => apply_production_command(
            state,
            *actor,
            CanonicalCommand::invite(
                NicknameValue::parse(target_nickname)?,
                ChannelNameValue::parse(channel)?,
            ),
            Some(ExternalInputs {
                monotonic_now: Some(MonotonicTick::from_ticks(*monotonic_now)),
                utc_now: Some(UtcSecond::from_unix_seconds(
                    1_700_500_000_u64.saturating_add(*monotonic_now),
                )),
                invite_ids: vec![InviteId::from_bytes(bytes(*invite))],
                ..ExternalInputs::default()
            }),
        ),
        ModelOperation::DeleteAccount {
            account,
            expected_generation,
        } => {
            let plan = state
                .plan_account_deleted(account_id(*account), generation(*expected_generation)?)?;
            apply_plan(state, plan).map(|_| ())
        }
    }
}

fn production_authority(
    account: Option<u8>,
    account_generation: u64,
) -> Result<Option<(AccountId, agenc_relay_types::Generation)>, DomainError> {
    account
        .map(|account| Ok((account_id(account), generation(account_generation)?)))
        .transpose()
}

fn apply_production_command(
    state: &mut agenc_relay_domain::DomainState,
    seed: u8,
    command: CanonicalCommand,
    external: Option<ExternalInputs>,
) -> Result<(), DomainError> {
    let identity = production_identity(state, seed)?;
    apply_command(
        state,
        identity,
        command,
        &registered_admission(identity.user_id)?,
        external,
    )
    .map(|_| ())
}

fn apply_production_join(
    state: &mut agenc_relay_domain::DomainState,
    seed: u8,
    channel: &str,
    instance: u8,
) -> Result<(), DomainError> {
    let channel_name = ChannelNameValue::parse(channel)?;
    let channel_ids = state
        .resolve_channel(&channel_name)
        .is_none()
        .then(|| channel_id(instance))
        .into_iter()
        .collect();
    let external = Some(ExternalInputs {
        utc_now: Some(UtcSecond::from_unix_seconds(
            1_700_500_000_u64.saturating_add(u64::from(instance)),
        )),
        channel_ids,
        ..ExternalInputs::default()
    });
    apply_production_command(
        state,
        seed,
        CanonicalCommand::join(vec![ChannelTarget::new(channel_name, false)])?,
        external,
    )
}

fn production_identity(
    state: &agenc_relay_domain::DomainState,
    seed: u8,
) -> Result<DomainTestIdentity, DomainError> {
    let user_id = production_user(seed);
    if let Some(session) = state.session(user_id) {
        return Ok(DomainTestIdentity {
            session_id: session.session_id(),
            user_id,
            generation: session.generation(),
            account_id: session.account_id(),
        });
    }
    Ok(DomainTestIdentity {
        session_id: SessionId::from_bytes(bytes(seed)),
        user_id,
        generation: generation(1)?,
        account_id: None,
    })
}

fn production_user(seed: u8) -> UserId {
    UserId::from_bytes(bytes(seed.wrapping_add(64)))
}

fn reference_user(seed: u8) -> u16 {
    u16::from(seed) + 64
}

fn production_role(role: ReferenceRole) -> Role {
    match role {
        ReferenceRole::Member => Role::Member,
        ReferenceRole::Voice => Role::Voice,
        ReferenceRole::HalfOperator => Role::HalfOperator,
        ReferenceRole::Operator => Role::Operator,
        ReferenceRole::Administrator => Role::Administrator,
        ReferenceRole::Owner => Role::Owner,
    }
}

fn reference_role(role: Role) -> ReferenceRole {
    match role {
        Role::Member => ReferenceRole::Member,
        Role::Voice => ReferenceRole::Voice,
        Role::HalfOperator => ReferenceRole::HalfOperator,
        Role::Operator => ReferenceRole::Operator,
        Role::Administrator => ReferenceRole::Administrator,
        Role::Owner => ReferenceRole::Owner,
    }
}

fn reference_mode_change(change: &ModelModeChange) -> ReferenceModeChange {
    match change {
        ModelModeChange::Visibility { operation, mode } => ReferenceModeChange::Visibility {
            operation: *operation,
            mode: *mode,
        },
        ModelModeChange::Role {
            operation,
            target,
            role,
            ..
        } => ReferenceModeChange::Role {
            operation: *operation,
            target: reference_user(*target),
            role: *role,
        },
    }
}

fn production_mode_change(change: &ModelModeChange) -> Result<ModeChange, DomainError> {
    match change {
        ModelModeChange::Visibility { operation, mode } => Ok(ModeChange::Visibility {
            operation: production_mode_operation(*operation),
            mode: production_visibility_mode(*mode),
        }),
        ModelModeChange::Role {
            operation,
            target_nickname,
            role,
            ..
        } => Ok(ModeChange::Role {
            operation: production_mode_operation(*operation),
            target: NicknameValue::parse(target_nickname)?,
            role: production_role(*role),
        }),
    }
}

const fn production_mode_operation(operation: ReferenceModeOperation) -> ModeOperation {
    match operation {
        ReferenceModeOperation::Add => ModeOperation::Add,
        ReferenceModeOperation::Remove => ModeOperation::Remove,
    }
}

const fn production_visibility_mode(mode: ReferenceVisibilityMode) -> VisibilityMode {
    match mode {
        ReferenceVisibilityMode::Unlisted => VisibilityMode::Unlisted,
        ReferenceVisibilityMode::Secret => VisibilityMode::Secret,
    }
}

fn reference_visibility(visibility: Visibility) -> ReferenceVisibility {
    match visibility {
        Visibility::Listed => ReferenceVisibility::Listed,
        Visibility::Unlisted => ReferenceVisibility::Unlisted,
        Visibility::Secret => ReferenceVisibility::Secret,
    }
}

fn production_snapshot(
    state: &agenc_relay_domain::DomainState,
) -> Result<CanonicalDomainSnapshot, String> {
    Ok(CanonicalDomainSnapshot {
        revision: state.revision().get(),
        accounts: production_accounts(state)?,
        sessions: production_sessions(state)?,
        channels: production_channels(state)?,
        federation_sequences: Vec::new(),
        away_users: production_away_users(state),
        monitors: production_monitors(state),
        display_names: production_display_names(state),
        account_updates: Vec::new(),
        topics: production_topics(state),
        registered_channels: production_registered_channels(state),
        observed_commands: Vec::new(),
    })
}

fn production_accounts(state: &agenc_relay_domain::DomainState) -> Result<Vec<(u8, u64)>, String> {
    let accounts: Vec<(u8, u64)> = (1..=ACCOUNT_SEED_END)
        .filter_map(|seed| {
            state
                .account(account_id(seed))
                .map(|account| (seed, account.session_generation().get()))
        })
        .collect();
    if accounts.len() != state.account_count() {
        return Err(
            "production snapshot found an account outside the generated identity pool".into(),
        );
    }
    Ok(accounts)
}

fn production_sessions(
    state: &agenc_relay_domain::DomainState,
) -> Result<Vec<CanonicalSessionSnapshot>, String> {
    let mut sessions = Vec::new();
    for seed in SESSION_SEED_START..=SESSION_SEED_END {
        let Some(session) = state.session(production_user(seed)) else {
            continue;
        };
        if session.session_id() != SessionId::from_bytes(bytes(seed)) {
            return Err("production session ID does not match its generated seed".into());
        }
        let account = session
            .account_id()
            .map(production_account_seed)
            .transpose()?;
        let channels = (CHANNEL_SEED_START..=CHANNEL_SEED_END)
            .filter(|instance| session.is_joined(channel_id(*instance)))
            .collect();
        sessions.push(CanonicalSessionSnapshot {
            seed,
            session_seed: seed,
            account,
            account_generation: session.account_session_generation().get(),
            generation: session.generation().get(),
            nickname: session.nickname().canonical().to_owned(),
            cloak: production_cloak_class(seed, session.public_cloak())?,
            channels,
        });
    }
    if sessions.len() != state.session_count() {
        return Err(
            "production snapshot found a session outside the generated identity pool".into(),
        );
    }
    Ok(sessions)
}

fn production_channels(
    state: &agenc_relay_domain::DomainState,
) -> Result<Vec<CanonicalChannelSnapshot>, String> {
    let mut channels = Vec::new();
    for instance in CHANNEL_SEED_START..=CHANNEL_SEED_END {
        let Some(channel) = state.channel(channel_id(instance)) else {
            continue;
        };
        let members: Vec<(u8, ReferenceRole)> = (SESSION_SEED_START..=SESSION_SEED_END)
            .filter_map(|seed| {
                channel
                    .role_of(production_user(seed))
                    .map(|role| (seed, reference_role(role)))
            })
            .collect();
        if members.len() != channel.member_count() {
            return Err(
                "production snapshot found a channel member outside the generated identity pool"
                    .into(),
            );
        }
        let mut invites = channel
            .pending_invites()
            .map(|(invite, target, inviter, creation_revision, expires_at)| {
                Ok(CanonicalInviteSnapshot {
                    invite: production_invite_seed(invite)?,
                    target: production_principal(target)?,
                    inviter: production_session_seed(inviter)?,
                    creation_revision: creation_revision.get(),
                    expires_at: expires_at.get(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        invites.sort_unstable_by_key(|invite| invite.invite);
        channels.push(CanonicalChannelSnapshot {
            instance,
            name: channel.name().canonical().to_owned(),
            visibility: reference_visibility(channel.visibility()),
            members,
            invites,
        });
    }
    if channels.len() != state.channel_count() {
        return Err(
            "production snapshot found a channel outside the generated identity pool".into(),
        );
    }
    Ok(channels)
}

fn production_away_users(state: &agenc_relay_domain::DomainState) -> Vec<u8> {
    (SESSION_SEED_START..=SESSION_SEED_END)
        .filter(|seed| {
            state
                .session(production_user(*seed))
                .is_some_and(|session| session.away().is_some())
        })
        .collect()
}

fn production_monitors(state: &agenc_relay_domain::DomainState) -> Vec<(u8, Vec<String>)> {
    (SESSION_SEED_START..=SESSION_SEED_END)
        .filter_map(|seed| {
            let session = state.session(production_user(seed))?;
            let nicknames: Vec<String> = session
                .monitored_nicknames()
                .map(|nickname| nickname.canonical().to_owned())
                .collect();
            (!nicknames.is_empty()).then_some((seed, nicknames))
        })
        .collect()
}

fn production_display_names(state: &agenc_relay_domain::DomainState) -> Vec<(u8, String)> {
    (SESSION_SEED_START..=SESSION_SEED_END)
        .filter_map(|seed| {
            state
                .session(production_user(seed))
                .map(|session| (seed, session.display_name().as_str().to_owned()))
        })
        .collect()
}

fn production_topics(state: &agenc_relay_domain::DomainState) -> Vec<u8> {
    (CHANNEL_SEED_START..=CHANNEL_SEED_END)
        .filter(|instance| {
            state
                .channel(channel_id(*instance))
                .is_some_and(|channel| channel.topic().is_some())
        })
        .collect()
}

fn production_registered_channels(state: &agenc_relay_domain::DomainState) -> Vec<u8> {
    (CHANNEL_SEED_START..=CHANNEL_SEED_END)
        .filter(|instance| {
            state.channel(channel_id(*instance)).is_some_and(|channel| {
                channel.persistence_policy() == PersistencePolicy::Registered
            })
        })
        .collect()
}

fn production_account_seed(account: AccountId) -> Result<u8, String> {
    (1..=ACCOUNT_SEED_END)
        .find(|seed| account_id(*seed) == account)
        .ok_or_else(|| "production account is outside the generated identity pool".to_owned())
}

fn production_session_seed(user: UserId) -> Result<u8, String> {
    (SESSION_SEED_START..=SESSION_SEED_END)
        .find(|seed| production_user(*seed) == user)
        .ok_or_else(|| "production user is outside the generated identity pool".to_owned())
}

fn production_principal(principal: Principal) -> Result<ReferencePrincipal, String> {
    match principal {
        Principal::Account(account) => Ok(ReferencePrincipal::Account(u16::from(
            production_account_seed(account)?,
        ))),
        Principal::Guest(user) => Ok(ReferencePrincipal::Guest(u16::from(
            production_session_seed(user)?,
        ))),
    }
}

fn production_invite_seed(invite: InviteId) -> Result<u8, String> {
    (INVITE_SEED_START..=INVITE_SEED_END)
        .find(|seed| InviteId::from_bytes(bytes(*seed)) == invite)
        .ok_or_else(|| "production invite is outside the generated identity pool".to_owned())
}

fn production_cloak_class(seed: u8, cloak: PublicCloak) -> Result<u8, String> {
    let expected = deterministic_cloak(seed)
        .map_err(|error| format!("generated cloak fixture is invalid: {error}"))?;
    if cloak != expected {
        return Err("production cloak differs from its generated canary".into());
    }
    Ok(seed)
}

fn reference_snapshot(model: &ReferenceDomainModel) -> Result<CanonicalDomainSnapshot, String> {
    let snapshot = model.snapshot();
    Ok(CanonicalDomainSnapshot {
        revision: snapshot.revision,
        accounts: snapshot
            .accounts
            .iter()
            .map(|(account, generation)| Ok((reference_account_seed(*account)?, *generation)))
            .collect::<Result<Vec<_>, String>>()?,
        sessions: snapshot
            .sessions
            .iter()
            .map(reference_session_snapshot)
            .collect::<Result<Vec<_>, _>>()?,
        channels: snapshot
            .channels
            .iter()
            .map(reference_channel_snapshot)
            .collect::<Result<Vec<_>, _>>()?,
        federation_sequences: snapshot.federation_sequences,
        away_users: snapshot
            .away_users
            .iter()
            .map(|user| reference_session_seed(*user))
            .collect::<Result<Vec<_>, _>>()?,
        monitors: snapshot
            .monitors
            .iter()
            .map(|(user, nicknames)| Ok((reference_session_seed(*user)?, nicknames.clone())))
            .collect::<Result<Vec<_>, String>>()?,
        display_names: snapshot
            .display_names
            .iter()
            .map(|(user, display_name)| Ok((reference_session_seed(*user)?, display_name.clone())))
            .collect::<Result<Vec<_>, String>>()?,
        account_updates: snapshot
            .account_updates
            .iter()
            .map(|(account, count)| Ok((reference_account_seed(*account)?, *count)))
            .collect::<Result<Vec<_>, String>>()?,
        topics: snapshot
            .topics
            .iter()
            .map(|instance| reference_channel_seed(*instance))
            .collect::<Result<Vec<_>, _>>()?,
        registered_channels: snapshot
            .registered_channels
            .iter()
            .map(|instance| reference_channel_seed(*instance))
            .collect::<Result<Vec<_>, _>>()?,
        observed_commands: snapshot.observed_commands,
    })
}

fn reference_session_snapshot(
    session: &agenc_relay_testkit::ReferenceSessionSnapshot,
) -> Result<CanonicalSessionSnapshot, String> {
    let seed = reference_session_seed(session.user)?;
    let session_seed =
        u8::try_from(session.session).map_err(|_| "reference session ID exceeds one byte")?;
    if session_seed != seed {
        return Err("reference session ID does not match its generated seed".into());
    }
    let cloak =
        u8::try_from(session.cloak).map_err(|_| "reference cloak canary exceeds one byte")?;
    if cloak != seed {
        return Err("reference cloak differs from its generated canary".into());
    }
    Ok(CanonicalSessionSnapshot {
        seed,
        session_seed,
        account: session.account.map(reference_account_seed).transpose()?,
        account_generation: session.account_generation,
        generation: session.generation,
        nickname: session.nickname.clone(),
        cloak,
        channels: session
            .channels
            .iter()
            .map(|instance| reference_channel_seed(*instance))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn reference_channel_snapshot(
    channel: &agenc_relay_testkit::ReferenceChannelSnapshot,
) -> Result<CanonicalChannelSnapshot, String> {
    Ok(CanonicalChannelSnapshot {
        instance: reference_channel_seed(channel.instance)?,
        name: channel.name.clone(),
        visibility: channel.visibility,
        members: channel
            .members
            .iter()
            .map(|(user, role)| Ok((reference_session_seed(*user)?, *role)))
            .collect::<Result<Vec<_>, String>>()?,
        invites: channel
            .invites
            .iter()
            .map(|invite| {
                Ok(CanonicalInviteSnapshot {
                    invite: reference_invite_seed(invite.invite)?,
                    target: canonical_reference_principal(invite.target)?,
                    inviter: reference_session_seed(invite.inviter)?,
                    creation_revision: invite.creation_revision,
                    expires_at: invite.expires_at,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

fn reference_account_seed(account: u16) -> Result<u8, String> {
    let seed = u8::try_from(account).map_err(|_| "reference account exceeds one byte")?;
    if !(1..=ACCOUNT_SEED_END).contains(&seed) {
        return Err("reference account is outside the generated identity pool".into());
    }
    Ok(seed)
}

fn reference_session_seed(user: u16) -> Result<u8, String> {
    let seed = user
        .checked_sub(64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| "reference user does not map to a generated session".to_owned())?;
    if !(SESSION_SEED_START..=SESSION_SEED_END).contains(&seed) {
        return Err("reference user is outside the generated identity pool".into());
    }
    Ok(seed)
}

fn reference_channel_seed(instance: u16) -> Result<u8, String> {
    let seed = u8::try_from(instance).map_err(|_| "reference channel exceeds one byte")?;
    if !(CHANNEL_SEED_START..=CHANNEL_SEED_END).contains(&seed) {
        return Err("reference channel is outside the generated identity pool".into());
    }
    Ok(seed)
}

fn reference_invite_seed(invite: u16) -> Result<u8, String> {
    let seed = u8::try_from(invite).map_err(|_| "reference invite exceeds one byte")?;
    if !(INVITE_SEED_START..=INVITE_SEED_END).contains(&seed) {
        return Err("reference invite is outside the generated identity pool".into());
    }
    Ok(seed)
}

fn canonical_reference_principal(
    principal: ReferencePrincipal,
) -> Result<ReferencePrincipal, String> {
    match principal {
        ReferencePrincipal::Account(account) => Ok(ReferencePrincipal::Account(u16::from(
            reference_account_seed(account)?,
        ))),
        ReferencePrincipal::Guest(user) => Ok(ReferencePrincipal::Guest(u16::from(
            reference_session_seed(user)?,
        ))),
    }
}
