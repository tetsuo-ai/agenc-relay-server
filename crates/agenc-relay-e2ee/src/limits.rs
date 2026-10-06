//! The named profile limits (companion Section 16), fixed private-use
//! values, and the closed MLS version and suite sets.
//!
//! Every `MAX_*_OBJECT` value measures the complete encoded `ArcWireObject`
//! including its six-byte envelope. The embedded-value limits named below
//! measure the canonical encoding of that value alone.
//!
//! Section 16 also names limits only an endpoint applies: the MLS ratchet
//! and application replay windows and the update and idle defaults. They are
//! defined here so that clients share one definition; the server holds no
//! ratchet or replay state and enforces none of them. Durations are in
//! seconds.

/// Companion profile version carried in every `profile_version` field.
pub const PROFILE_VERSION: u16 = 1;

/// RFC 9420 protocol version `mls10`.
pub const MLS_VERSION_MLS10: u16 = 1;
/// `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const SUITE_X25519_AES128GCM_SHA256_ED25519: u16 = 0x0001;
/// `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`.
pub const SUITE_X25519_CHACHA20POLY1305_SHA256_ED25519: u16 = 0x0003;
/// The only suites version 1 may enable, in registry order.
pub const ENABLED_SUITES: [u16; 2] = [
    SUITE_X25519_AES128GCM_SHA256_ED25519,
    SUITE_X25519_CHACHA20POLY1305_SHA256_ED25519,
];
/// RFC 9420 `SignatureScheme` value for Ed25519.
pub const SIGNATURE_SCHEME_ED25519: u16 = 0x0807;
/// RFC 9420 `CredentialType` value for `basic`.
pub const CREDENTIAL_TYPE_BASIC: u16 = 1;
/// Private-use GroupContext extension `ARC_MLS_CONTEXT_EXTENSION`.
pub const ARC_MLS_CONTEXT_EXTENSION: u16 = 0xF1C1;
/// Private-use proposal type `IRC_DEVICE_ROSTER_UPDATE_PROPOSAL`.
pub const IRC_DEVICE_ROSTER_UPDATE_PROPOSAL: u16 = 0xF1C2;
/// Private-use GroupInfo extension `IRC_JOIN_AUTH_BUNDLE_EXTENSION`.
pub const IRC_JOIN_AUTH_BUNDLE_EXTENSION: u16 = 0xF1C3;

/// Returns whether a suite is enabled in profile version 1.
#[must_use]
pub const fn suite_is_enabled(suite: u16) -> bool {
    suite == SUITE_X25519_AES128GCM_SHA256_ED25519
        || suite == SUITE_X25519_CHACHA20POLY1305_SHA256_ED25519
}

/// `MAX_APPLICATION_PLAINTEXT`.
pub const MAX_APPLICATION_PLAINTEXT: usize = 32_768;
/// `MAX_PRIVATE_TOPIC_BYTES`.
pub const MAX_PRIVATE_TOPIC_BYTES: usize = 4_096;
/// `MAX_APPLICATION_MLS_OBJECT`.
pub const MAX_APPLICATION_MLS_OBJECT: usize = 65_536;
/// `MAX_KEY_PACKAGE_OBJECT`.
pub const MAX_KEY_PACKAGE_OBJECT: usize = 65_536;
/// `MAX_IDENTITY_OBJECT`.
pub const MAX_IDENTITY_OBJECT: usize = 65_536;
/// `MAX_ROOT_CHAIN_OBJECT`.
pub const MAX_ROOT_CHAIN_OBJECT: usize = 1_048_576;
/// `MAX_ROSTER_OBJECT`.
pub const MAX_ROSTER_OBJECT: usize = 65_536;
/// `MAX_CAPABILITY_OBJECT`.
pub const MAX_CAPABILITY_OBJECT: usize = 65_536;
/// `MAX_CREDENTIAL_BUNDLE`.
pub const MAX_CREDENTIAL_BUNDLE: usize = 8_192;
/// `MAX_POLICY_BYTES`.
pub const MAX_POLICY_BYTES: usize = 32_768;
/// `MAX_POLICY_OBJECT`: a published policy with its six-byte envelope.
pub const MAX_POLICY_OBJECT: usize = 32_774;
/// `MAX_BINDING_OBJECT`.
pub const MAX_BINDING_OBJECT: usize = 262_144;
/// `MAX_BINDING_CHAIN_BYTES`.
pub const MAX_BINDING_CHAIN_BYTES: usize = 1_048_576;
/// `MAX_ARC_MLS_CONTEXT_EXTENSION`.
pub const MAX_ARC_MLS_CONTEXT_EXTENSION: usize = 196_608;
/// `MAX_POLICY_CHAIN_BYTES`.
pub const MAX_POLICY_CHAIN_BYTES: usize = 1_048_576;
/// `MAX_LIVE_OBJECT`.
pub const MAX_LIVE_OBJECT: usize = 262_144;
/// `MAX_COMMIT_APPROVAL_OBJECT`.
pub const MAX_COMMIT_APPROVAL_OBJECT: usize = 65_536;
/// `MAX_COMMIT_ACK_OBJECT`.
pub const MAX_COMMIT_ACK_OBJECT: usize = 65_536;
/// `MAX_REINIT_ACK_OBJECT`.
pub const MAX_REINIT_ACK_OBJECT: usize = 65_536;
/// `MAX_LEAF_MEMBERSHIP_OBJECT`: a leaf-membership proof with its envelope
/// (companion 13.7.3).
pub const MAX_LEAF_MEMBERSHIP_OBJECT: usize = 8_192;
/// `MAX_FINALIZATION_OBJECT`.
pub const MAX_FINALIZATION_OBJECT: usize = 4_190_000;
/// `MAX_ABORT_OBJECT`.
pub const MAX_ABORT_OBJECT: usize = 1_048_576;
/// `MAX_REINIT_OBJECT`.
pub const MAX_REINIT_OBJECT: usize = 4_190_000;
/// `MAX_REINIT_INITIAL_COMMIT_BYTES`.
pub const MAX_REINIT_INITIAL_COMMIT_BYTES: usize = 3_145_728;
/// `MAX_RESERVATION_OBJECT`.
pub const MAX_RESERVATION_OBJECT: usize = 65_536;
/// `MAX_SEQUENCER_RECORD_OBJECT`.
pub const MAX_SEQUENCER_RECORD_OBJECT: usize = 4_194_304;
/// `MAX_CLOSE_OBJECT`.
pub const MAX_CLOSE_OBJECT: usize = 32_768;
/// `MAX_DEVICE_ATTACH_OBJECT`.
pub const MAX_DEVICE_ATTACH_OBJECT: usize = 4_096;
/// `MAX_FEDERATION_CONTROL_OBJECT`.
pub const MAX_FEDERATION_CONTROL_OBJECT: usize = 65_536;
/// `MAX_FEDERATION_STATE_ENTRIES_PER_EDGE`.
pub const MAX_FEDERATION_STATE_ENTRIES_PER_EDGE: u64 = 1_000_000;
/// `MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE`.
pub const MAX_FEDERATION_STATE_SNAPSHOT_BYTES_PER_EDGE: u64 = 536_870_912;
/// `FEDERATION_STATE_SNAPSHOT_TIMEOUT` in seconds.
pub const FEDERATION_STATE_SNAPSHOT_TIMEOUT_SECONDS: u64 = 15 * 60;
/// `MAX_UNACKED_E2EE_EVENTS_PER_EDGE`.
pub const MAX_UNACKED_E2EE_EVENTS_PER_EDGE: u64 = 262_144;
/// `MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE`.
pub const MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE: u64 = 1_073_741_824;
/// `MAX_CROSS_PROFILE_EVENT_PARTS_PER_EDGE`.
pub const MAX_CROSS_PROFILE_EVENT_PARTS_PER_EDGE: u16 = 2_048;
/// `MAX_CROSS_PROFILE_EVENT_BYTES_PER_EDGE`.
pub const MAX_CROSS_PROFILE_EVENT_BYTES_PER_EDGE: u64 = 16_777_216;
/// `ACKED_E2EE_EVENT_REPLAY_TARGET` in seconds.
pub const ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS: u64 = 24 * 60 * 60;
/// `MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE`.
pub const MAX_ACKED_E2EE_EVENT_REPLAY_ROWS_PER_EDGE: u64 = 1_000_000;
/// `MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE`.
pub const MAX_ACKED_E2EE_EVENT_REPLAY_BYTES_PER_EDGE: u64 = 1_073_741_824;
/// `MAX_WELCOME_MAILBOX_OBJECT`.
pub const MAX_WELCOME_MAILBOX_OBJECT: usize = 4_194_304;
/// `MAX_EMBEDDED_MLS_WELCOME_BYTES`.
pub const MAX_EMBEDDED_MLS_WELCOME_BYTES: usize = 4_190_000;
/// `MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES` (includes the three-byte prefix).
pub const MAX_JOIN_TRANSITION_PROOF_BUNDLE_BYTES: usize = 262_147;
/// `MAX_E2EE_SERVER_PREFIX_BYTES`.
pub const MAX_E2EE_SERVER_PREFIX_BYTES: usize = 127;
/// `MAX_SERIALIZED_ACCOUNT_TAG`.
pub const MAX_SERIALIZED_ACCOUNT_TAG: usize = 512;
/// `MAX_CANDIDATE_RECEIPT_TAG`.
pub const MAX_CANDIDATE_RECEIPT_TAG: usize = 462;
/// `MAX_FRAGMENT_RAW`.
pub const MAX_FRAGMENT_RAW: usize = 2_940;
/// `MAX_LIVE_FRAGMENT_COUNT`.
pub const MAX_LIVE_FRAGMENT_COUNT: u32 = 90;
/// `MAX_MAILBOX_FRAGMENT_COUNT`.
pub const MAX_MAILBOX_FRAGMENT_COUNT: u32 = 1_427;
/// `MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER`.
pub const MAX_OPEN_REASSEMBLIES_PER_LOCAL_SENDER: usize = 1;
/// `MAX_OPEN_REMOTE_OBJECTS_PER_SENDER`.
pub const MAX_OPEN_REMOTE_OBJECTS_PER_SENDER: usize = 8;
/// `MAX_OPEN_REMOTE_OBJECTS_PER_CONNECTION`.
pub const MAX_OPEN_REMOTE_OBJECTS_PER_CONNECTION: usize = 32;
/// `MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION`.
pub const MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION: usize = 2_097_152;
/// `MAX_OPEN_REASSEMBLIES_PER_ACCOUNT`.
pub const MAX_OPEN_REASSEMBLIES_PER_ACCOUNT: usize = 16;
/// `MAX_REASSEMBLY_BYTES_PER_ACCOUNT`.
pub const MAX_REASSEMBLY_BYTES_PER_ACCOUNT: usize = 8_388_608;
/// `MAX_OPEN_REASSEMBLIES_PER_ROUTE`.
pub const MAX_OPEN_REASSEMBLIES_PER_ROUTE: usize = 64;
/// `MAX_REASSEMBLY_BYTES_PER_ROUTE`.
pub const MAX_REASSEMBLY_BYTES_PER_ROUTE: usize = 16_777_216;
/// `MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER`.
pub const MAX_OPEN_REASSEMBLIES_PER_FEDERATION_PEER: usize = 256;
/// `MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER`.
pub const MAX_REASSEMBLY_BYTES_PER_FEDERATION_PEER: usize = 67_108_864;
/// `MAX_OPEN_REASSEMBLIES_GLOBAL`.
pub const MAX_OPEN_REASSEMBLIES_GLOBAL: usize = 1_024;
/// `MAX_REASSEMBLY_BYTES_GLOBAL`.
pub const MAX_REASSEMBLY_BYTES_GLOBAL: usize = 268_435_456;
/// `LIVE_REASSEMBLY_TIMEOUT` absolute, in seconds.
pub const LIVE_REASSEMBLY_ABSOLUTE_SECONDS: u64 = 120;
/// `LIVE_REASSEMBLY_TIMEOUT` idle, in seconds.
pub const LIVE_REASSEMBLY_IDLE_SECONDS: u64 = 15;
/// `MAILBOX_REASSEMBLY_TIMEOUT` absolute, in seconds.
pub const MAILBOX_REASSEMBLY_ABSOLUTE_SECONDS: u64 = 600;
/// `MAILBOX_REASSEMBLY_TIMEOUT` idle, in seconds.
pub const MAILBOX_REASSEMBLY_IDLE_SECONDS: u64 = 30;
/// `MIN_ADMITTED_E2EE_INGRESS_RATE` in bytes per second.
pub const MIN_ADMITTED_E2EE_INGRESS_RATE: u64 = 65_536;
/// `MAX_RECIPIENT_E2EE_SENDQ`.
pub const MAX_RECIPIENT_E2EE_SENDQ: usize = 8_388_608;
/// `MAX_BATCH_OBJECTS`.
pub const MAX_BATCH_OBJECTS: usize = 32;
/// `MAX_BATCH_FRAGMENTS`.
pub const MAX_BATCH_FRAGMENTS: usize = 1_427;
/// `MAX_BATCH_DECODED_BYTES`.
pub const MAX_BATCH_DECODED_BYTES: usize = 4_194_304;
/// `RECENT_OBJECT_IDEMPOTENCY_RETENTION` in seconds.
pub const RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS: u64 = 30 * 60;
/// `S2S_IDEMPOTENCY_RETENTION` in seconds.
pub const S2S_IDEMPOTENCY_RETENTION_SECONDS: u64 = 24 * 60 * 60;
/// `MAX_ACTIVE_COMMIT_CANDIDATES`.
pub const MAX_ACTIVE_COMMIT_CANDIDATES: usize = 1;
/// `MAX_FINALITY_PRINCIPALS`.
pub const MAX_FINALITY_PRINCIPALS: usize = 64;
/// `MAX_BINDING_PRINCIPALS`.
pub const MAX_BINDING_PRINCIPALS: usize = 64;
/// `MAX_BINDING_APPROVALS`.
pub const MAX_BINDING_APPROVALS: usize = 256;
/// `MAX_CANDIDATE_ATTEMPTS_PER_EPOCH`.
pub const MAX_CANDIDATE_ATTEMPTS_PER_EPOCH: u32 = 8;
/// `ENROLLMENT_CHALLENGE_TIMEOUT` in seconds.
pub const ENROLLMENT_CHALLENGE_TIMEOUT_SECONDS: u64 = 10 * 60;
/// `RESERVATION_TIMEOUT` in seconds.
pub const RESERVATION_TIMEOUT_SECONDS: u64 = 60;
/// `ATTACH_CHALLENGE_TIMEOUT` in seconds.
pub const ATTACH_CHALLENGE_TIMEOUT_SECONDS: u64 = 60;
/// `MAILBOX_DELIVERY_TOKEN_TIMEOUT` in seconds.
pub const MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS: u64 = 10 * 60;
/// `DIRECTORY_CURSOR_TIMEOUT` in seconds.
pub const DIRECTORY_CURSOR_TIMEOUT_SECONDS: u64 = 10 * 60;
/// `MAX_COMMIT_CLOCK_SKEW` in seconds.
pub const MAX_COMMIT_CLOCK_SKEW_SECONDS: u64 = 10 * 60;
/// `COMMIT_STAGING_TIMEOUT` in seconds.
pub const COMMIT_STAGING_TIMEOUT_SECONDS: u64 = 10 * 60;
/// `JOIN_CONFIRMATION_TIMEOUT` in seconds.
pub const JOIN_CONFIRMATION_TIMEOUT_SECONDS: u64 = 60 * 60;
/// `KEY_PACKAGE_CLAIM_TIMEOUT` in seconds.
pub const KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `MAILBOX_ACK_RETENTION` in seconds.
pub const MAILBOX_ACK_RETENTION_SECONDS: u64 = 30 * 60;
/// `REINIT_STAGING_TIMEOUT` in seconds.
pub const REINIT_STAGING_TIMEOUT_SECONDS: u64 = 60 * 60;
/// `MAX_COMMIT_SUBMISSIONS_PER_LEAF_PER_MINUTE`.
pub const MAX_COMMIT_SUBMISSIONS_PER_LEAF_PER_MINUTE: u32 = 2;
/// `MAX_COMMIT_SUBMISSIONS_PER_CONVERSATION_PER_MINUTE`.
pub const MAX_COMMIT_SUBMISSIONS_PER_CONVERSATION_PER_MINUTE: u32 = 16;
/// `MAX_RATCHET_FORWARD_JUMP`: MLS sender generations a receiver may skip
/// ahead in one message (endpoint only).
pub const MAX_RATCHET_FORWARD_JUMP: u32 = 1_024;
/// `MAX_SKIPPED_KEYS_PER_SENDER`: skipped-generation keys an endpoint
/// retains for one sender.
pub const MAX_SKIPPED_KEYS_PER_SENDER: usize = 1_024;
/// `MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION`: retained skipped-key state of
/// one conversation (endpoint only).
pub const MAX_SKIPPED_KEY_BYTES_PER_CONVERSATION: u64 = 67_108_864;
/// `SKIPPED_KEY_RETENTION` in seconds (endpoint only).
pub const SKIPPED_KEY_RETENTION_SECONDS: u64 = 5 * 60;
/// `MAX_RETAINED_PAST_EPOCHS`: past epochs whose unconsumed receive keys an
/// endpoint keeps (companion 14).
pub const MAX_RETAINED_PAST_EPOCHS: usize = 2;
/// `PAST_EPOCH_RECEIVE_RETENTION` in seconds; zero for a removed leaf
/// (endpoint only).
pub const PAST_EPOCH_RECEIVE_RETENTION_SECONDS: u64 = 5 * 60;
/// `MAX_APPLICATION_SEQUENCE_FORWARD_JUMP`: how far beyond the highest
/// accepted `sender_sequence` an application message may land (companion
/// 14).
pub const MAX_APPLICATION_SEQUENCE_FORWARD_JUMP: u64 = 4_096;
/// `MAX_APPLICATION_SEQUENCE_GAPS`: outstanding application-sequence gaps
/// per leaf (companion 14).
pub const MAX_APPLICATION_SEQUENCE_GAPS: usize = 1_024;
/// `MAX_RECENT_MESSAGE_IDS_PER_LEAF`: recent message IDs an endpoint keeps
/// per leaf for replay detection (companion 14).
pub const MAX_RECENT_MESSAGE_IDS_PER_LEAF: usize = 8_192;
/// `MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION`: the conversation-wide
/// replay-state ceiling, at which new gaps are refused (companion 14).
pub const MAX_REPLAY_GAP_STATE_BYTES_PER_CONVERSATION: u64 = 16_777_216;
/// `MAX_PROPOSALS_PER_COMMIT`.
pub const MAX_PROPOSALS_PER_COMMIT: usize = 512;
/// `MAX_GROUP_LEAVES`.
pub const MAX_GROUP_LEAVES: u32 = 512;
/// `MAX_ACTIVE_DEVICES_PER_ACCOUNT`.
pub const MAX_ACTIVE_DEVICES_PER_ACCOUNT: u16 = 64;
/// `MAX_KEY_PACKAGE_LIFETIME` in seconds.
pub const MAX_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `MAX_CAPABILITY_LIFETIME` in seconds.
pub const MAX_CAPABILITY_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `MIN_KEY_PACKAGE_CLAIM_VALIDITY` in seconds.
pub const MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS: u64 = 60 * 60;
/// `MAX_ROSTER_AGE_AT_ADD` in seconds.
pub const MAX_ROSTER_AGE_AT_ADD_SECONDS: u64 = 24 * 60 * 60;
/// `MAX_ROSTER_LIFETIME` in seconds.
pub const MAX_ROSTER_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `ROSTER_STALE_SEND_GRACE` in seconds.
pub const ROSTER_STALE_SEND_GRACE_SECONDS: u64 = 24 * 60 * 60;
/// `MAX_MAILBOX_BYTES_PER_ACCOUNT`.
pub const MAX_MAILBOX_BYTES_PER_ACCOUNT: u64 = 67_108_864;
/// `MAX_DIRECTORY_BYTES_PER_ACCOUNT`.
pub const MAX_DIRECTORY_BYTES_PER_ACCOUNT: u64 = 8_388_608;
/// `MAX_STORED_BYTES_PER_CONVERSATION`.
pub const MAX_STORED_BYTES_PER_CONVERSATION: u64 = 268_435_456;
/// `WELCOME_RETENTION` in seconds.
pub const WELCOME_RETENTION_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `SEQUENCER_RECORD_RETENTION` in seconds.
pub const SEQUENCER_RECORD_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
/// `MAX_RECOVERY_SUBMISSION_OBJECT`.
pub const MAX_RECOVERY_SUBMISSION_OBJECT: usize = 4_096;
/// `MAX_OPEN_RECOVERY_SUBMISSIONS` per conversation.
pub const MAX_OPEN_RECOVERY_SUBMISSIONS: usize = 8;
/// `MAX_RECOVERY_CHAIN_BYTES`: the complete accepted chain of one
/// conversation, elements included.
pub const MAX_RECOVERY_CHAIN_BYTES: u64 = 268_435_456;
/// `MAX_RECOVERY_SUBMISSION_SECONDS`: an accepted submission whose element
/// has not arrived after this long is discarded.
pub const MAX_RECOVERY_SUBMISSION_SECONDS: u64 = 600;
/// The stored bytes a conversation keeps free of proof-producing transitions
/// so that an explicit finalized close, its route state, the open recovery
/// submissions of Section 13.7.4 and the leaf proofs a close names always fit
/// under `MAX_STORED_BYTES_PER_CONVERSATION` (Section 15: the route stops
/// accepting new proof-producing transitions and Adds before the quota is
/// exhausted).
pub const RECOVERY_HEADROOM_BYTES: u64 = (MAX_FINALIZATION_OBJECT
    + MAX_CLOSE_OBJECT
    + MAX_FEDERATION_CONTROL_OBJECT
    + MAX_OPEN_RECOVERY_SUBMISSIONS * MAX_RECOVERY_SUBMISSION_OBJECT
    + 2 * MAX_LEAF_MEMBERSHIP_OBJECT) as u64;
/// `MAX_WITNESS_RESOLUTION_RECORDS`: the records one edge witness
/// resolution may carry (companion 12.5.1).
pub const MAX_WITNESS_RESOLUTION_RECORDS: u32 = 1_024;
/// `MAX_WITNESS_RESOLUTION_BYTES`: the complete `sequencer_record` objects
/// one resolution set may carry (companion 12.5.1).
pub const MAX_WITNESS_RESOLUTION_BYTES: u64 = 268_435_456;
/// `MAX_WITNESS_RESOLUTION_SECONDS`: how long the edge waits before it
/// repeats an unanswered `EWITNESS REQUEST` (companion 12.5.1).
pub const MAX_WITNESS_RESOLUTION_SECONDS: u64 = 300;
/// `MAX_SEQUENCER_KEY_OVERLAP` in seconds.
pub const MAX_SEQUENCER_KEY_OVERLAP_SECONDS: u64 = 7 * 24 * 60 * 60;
/// `REINIT_RESUMPTION_PSK_RETENTION` in seconds.
pub const REINIT_RESUMPTION_PSK_RETENTION_SECONDS: u64 = 24 * 60 * 60;
/// `MAX_SIGNATURE_VERIFICATIONS_PER_ACCOUNT_PER_MINUTE`.
pub const MAX_SIGNATURE_VERIFICATIONS_PER_ACCOUNT_PER_MINUTE: u32 = 1_024;
/// `DEFAULT_ACTIVE_UPDATE_PERIOD` in seconds: an active device's longest
/// interval between its own UpdatePath Commits (companion 13.6).
pub const DEFAULT_ACTIVE_UPDATE_PERIOD_SECONDS: u64 = 24 * 60 * 60;
/// `DEFAULT_ACTIVE_UPDATE_MESSAGES`: the application messages an active
/// device sends before its next UpdatePath Commit (companion 13.6).
pub const DEFAULT_ACTIVE_UPDATE_MESSAGES: u64 = 10_000;
/// `DEFAULT_IDLE_DEVICE_EVICTION` in seconds: the silence after which a
/// client warns about one of its account's devices; a local reminder, never
/// an automatic removal (companion 13.6).
pub const DEFAULT_IDLE_DEVICE_EVICTION_SECONDS: u64 = 30 * 24 * 60 * 60;
/// Client-added tag data budget in bytes (IRCv3).
pub const MAX_CLIENT_TAG_DATA: usize = 4_094;
/// Server-added tag data budget in bytes (IRCv3).
pub const MAX_SERVER_TAG_DATA: usize = 4_094;
/// Combined tag section budget in bytes (IRCv3).
pub const MAX_COMBINED_TAG_SECTION: usize = 8_191;
/// Bytes of the `ArcWireObject` envelope before `body`.
pub const WIRE_OBJECT_ENVELOPE_BYTES: usize = 6;
/// The largest `ArcWireObject.body` the envelope can carry.
pub const MAX_WIRE_OBJECT_BODY_BYTES: usize = 4_194_298;
/// The Section 11.1 vendor capability value, exact.
pub const CAPABILITY_VALUE: &str = "v1,profile=CzmFweGfd-Vhc0E51lEx-xwfxct6Y6ERnKA7WmFYNSU,seg=2940,obj=262144,parts=90,welcome=4194304";
/// The vendor capability name.
pub const CAPABILITY_NAME: &str = "agenc.ag/e2ee-mls";
