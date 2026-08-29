//! The `[accounts]` table (spec C.5 9022-9037).

use std::path::PathBuf;

use toml::Table;

use crate::bounds::{
    AUTH_TRANSACTION_SECONDS, CREATE_TRANSACTION_SECONDS, CREDENTIAL_CHANGE_TRANSACTION_SECONDS,
    MAX_CONTACTS, MAX_RESERVED_NICKNAMES,
};
use crate::document::{check_keys, optional_boolean, optional_string, optional_unsigned, string};
use crate::error::{ConfigError, IssueSink, SchemaKey};
use crate::federation::optional_path;
use crate::paths::PathResolver;
use crate::scalar::{base64url_32, closed_enum};

pub(crate) const ACCOUNTS_KEYS: &[&str] = &[
    "accept_clients",
    "access_token_key_file",
    "account_service_hpke_private_key_file",
    "account_service_hpke_public_key",
    "allow_guests",
    "auth_transaction_seconds",
    "create_transaction_seconds",
    "credential_change_transaction_seconds",
    "default_allow_guest_dm",
    "default_direct_messages",
    "default_public_presence",
    "invite_verification_key_file",
    "max_contacts",
    "max_reserved_nicknames",
    "opaque_fake_credential_key_file",
    "opaque_server_setup_file",
    "registration",
];

/// Account registration policy (spec 9023).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum RegistrationPolicy {
    /// Anyone may create an account.
    Open,
    /// A signed invitation is required.
    Invite,
    /// No new accounts.
    Closed,
}

impl RegistrationPolicy {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Invite => "invite",
            Self::Closed => "closed",
        }
    }
}

/// Default direct-message policy copied at account creation (spec 9032).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DirectMessageDefault {
    /// Accept direct messages from anyone.
    Allow,
    /// Accept only from contacts.
    Contacts,
    /// Refuse direct messages.
    Deny,
}

impl DirectMessageDefault {
    /// Returns the configuration spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Contacts => "contacts",
            Self::Deny => "deny",
        }
    }
}

/// The validated `[accounts]` table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountsConfig {
    /// Whether this node serves clients at all.
    pub accept_clients: bool,
    /// Registration policy after the onion-only default rule.
    pub registration: RegistrationPolicy,
    /// Ed25519 invitation verification key, required for invite registration.
    pub invite_verification_key_file: Option<PathBuf>,
    /// Optional PASS admission token key.
    pub access_token_key_file: Option<PathBuf>,
    /// Pinned account-service HPKE public key.
    pub account_service_hpke_public_key: [u8; 32],
    /// Coordinator-only HPKE private key file.
    pub account_service_hpke_private_key_file: Option<PathBuf>,
    /// Coordinator-only OPAQUE server setup file.
    pub opaque_server_setup_file: Option<PathBuf>,
    /// Coordinator-only fake-credential key file.
    pub opaque_fake_credential_key_file: Option<PathBuf>,
    /// Whether guests may register.
    pub allow_guests: bool,
    /// Default public presence copied at creation.
    pub default_public_presence: bool,
    /// Default guest direct-message policy copied at creation.
    pub default_allow_guest_dm: bool,
    /// Default direct-message policy copied at creation.
    pub default_direct_messages: DirectMessageDefault,
    /// Contact ceiling per account.
    pub max_contacts: u64,
    /// Reserved nicknames per account, fixed at 5.
    pub max_reserved_nicknames: u64,
    /// Authentication transaction lifetime, fixed at 30 seconds.
    pub auth_transaction_seconds: u64,
    /// Creation transaction lifetime, fixed at 60 seconds.
    pub create_transaction_seconds: u64,
    /// Credential-change transaction lifetime, fixed at 60 seconds.
    pub credential_change_transaction_seconds: u64,
}

const TABLE: &str = "accounts";

pub(crate) fn parse(
    table: &Table,
    resolver: &PathResolver,
    onion_only: bool,
    sink: &mut IssueSink,
) -> Option<AccountsConfig> {
    let key = |field| SchemaKey::new(TABLE, field);
    sink.field(key(""), check_keys(table, ACCOUNTS_KEYS))?;
    let flags = parse_flags(table, sink);
    let registration = sink.field(key("registration"), parse_registration(table, onion_only));
    let paths = parse_paths(table, resolver, sink);
    let account_service_hpke_public_key = sink.field(
        key("account_service_hpke_public_key"),
        string(table, "account_service_hpke_public_key").and_then(base64url_32),
    );
    let default_direct_messages =
        sink.field(key("default_direct_messages"), parse_direct_messages(table));
    let numbers = parse_numbers(table, sink);
    let flags = flags?;
    let paths = paths?;
    let numbers = numbers?;
    Some(AccountsConfig {
        accept_clients: flags.accept_clients,
        registration: registration?,
        invite_verification_key_file: paths.invite_verification_key_file,
        access_token_key_file: paths.access_token_key_file,
        account_service_hpke_public_key: account_service_hpke_public_key?,
        account_service_hpke_private_key_file: paths.account_service_hpke_private_key_file,
        opaque_server_setup_file: paths.opaque_server_setup_file,
        opaque_fake_credential_key_file: paths.opaque_fake_credential_key_file,
        allow_guests: flags.allow_guests,
        default_public_presence: flags.default_public_presence,
        default_allow_guest_dm: flags.default_allow_guest_dm,
        default_direct_messages: default_direct_messages?,
        max_contacts: numbers.max_contacts,
        max_reserved_nicknames: numbers.max_reserved_nicknames,
        auth_transaction_seconds: numbers.auth_transaction_seconds,
        create_transaction_seconds: numbers.create_transaction_seconds,
        credential_change_transaction_seconds: numbers.credential_change_transaction_seconds,
    })
}

struct Flags {
    accept_clients: bool,
    allow_guests: bool,
    default_public_presence: bool,
    default_allow_guest_dm: bool,
}

fn parse_flags(table: &Table, sink: &mut IssueSink) -> Option<Flags> {
    let mut flag = |field: &'static str, default: bool| {
        sink.field(
            SchemaKey::new(TABLE, field),
            optional_boolean(table, field).map(|value| value.unwrap_or(default)),
        )
    };
    let accept_clients = flag("accept_clients", true);
    let allow_guests = flag("allow_guests", true);
    let default_public_presence = flag("default_public_presence", false);
    let default_allow_guest_dm = flag("default_allow_guest_dm", false);
    Some(Flags {
        accept_clients: accept_clients?,
        allow_guests: allow_guests?,
        default_public_presence: default_public_presence?,
        default_allow_guest_dm: default_allow_guest_dm?,
    })
}

fn parse_registration(table: &Table, onion_only: bool) -> Result<RegistrationPolicy, ConfigError> {
    // The default is `invite`, or `closed` for an onion-only endpoint (spec 9023).
    match optional_string(table, "registration")? {
        None if onion_only => Ok(RegistrationPolicy::Closed),
        None => Ok(RegistrationPolicy::Invite),
        Some(text) => closed_enum(
            text,
            &[
                ("open", RegistrationPolicy::Open),
                ("invite", RegistrationPolicy::Invite),
                ("closed", RegistrationPolicy::Closed),
            ],
        ),
    }
}

fn parse_direct_messages(table: &Table) -> Result<DirectMessageDefault, ConfigError> {
    match optional_string(table, "default_direct_messages")? {
        None => Ok(DirectMessageDefault::Allow),
        Some(text) => closed_enum(
            text,
            &[
                ("allow", DirectMessageDefault::Allow),
                ("contacts", DirectMessageDefault::Contacts),
                ("deny", DirectMessageDefault::Deny),
            ],
        ),
    }
}

struct Paths {
    invite_verification_key_file: Option<PathBuf>,
    access_token_key_file: Option<PathBuf>,
    account_service_hpke_private_key_file: Option<PathBuf>,
    opaque_server_setup_file: Option<PathBuf>,
    opaque_fake_credential_key_file: Option<PathBuf>,
}

fn parse_paths(table: &Table, resolver: &PathResolver, sink: &mut IssueSink) -> Option<Paths> {
    let mut path = |field: &'static str| {
        sink.field(
            SchemaKey::new(TABLE, field),
            optional_path(table, field, resolver),
        )
    };
    let invite_verification_key_file = path("invite_verification_key_file");
    let access_token_key_file = path("access_token_key_file");
    let account_service_hpke_private_key_file = path("account_service_hpke_private_key_file");
    let opaque_server_setup_file = path("opaque_server_setup_file");
    let opaque_fake_credential_key_file = path("opaque_fake_credential_key_file");
    Some(Paths {
        invite_verification_key_file: invite_verification_key_file?,
        access_token_key_file: access_token_key_file?,
        account_service_hpke_private_key_file: account_service_hpke_private_key_file?,
        opaque_server_setup_file: opaque_server_setup_file?,
        opaque_fake_credential_key_file: opaque_fake_credential_key_file?,
    })
}

struct Numbers {
    max_contacts: u64,
    max_reserved_nicknames: u64,
    auth_transaction_seconds: u64,
    create_transaction_seconds: u64,
    credential_change_transaction_seconds: u64,
}

fn parse_numbers(table: &Table, sink: &mut IssueSink) -> Option<Numbers> {
    let mut fixed = |field: &'static str, bound: crate::scalar::Bound| {
        sink.field(
            SchemaKey::new(TABLE, field),
            optional_unsigned(table, field).and_then(|value| bound.fixed(value)),
        )
    };
    let max_reserved_nicknames = fixed("max_reserved_nicknames", MAX_RESERVED_NICKNAMES);
    let auth_transaction_seconds = fixed("auth_transaction_seconds", AUTH_TRANSACTION_SECONDS);
    let create_transaction_seconds =
        fixed("create_transaction_seconds", CREATE_TRANSACTION_SECONDS);
    let credential_change_transaction_seconds = fixed(
        "credential_change_transaction_seconds",
        CREDENTIAL_CHANGE_TRANSACTION_SECONDS,
    );
    let max_contacts = sink.field(
        SchemaKey::new(TABLE, "max_contacts"),
        optional_unsigned(table, "max_contacts").and_then(|value| MAX_CONTACTS.resolve(value)),
    );
    Some(Numbers {
        max_contacts: max_contacts?,
        max_reserved_nicknames: max_reserved_nicknames?,
        auth_transaction_seconds: auth_transaction_seconds?,
        create_transaction_seconds: create_transaction_seconds?,
        credential_change_transaction_seconds: credential_change_transaction_seconds?,
    })
}
