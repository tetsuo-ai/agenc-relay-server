#![forbid(unsafe_code)]

//! Account authentication and credential state machines.
//!
//! All private application messages enter through the fixed account-service
//! HPKE envelope. OPAQUE state, credentials, transaction bindings, and
//! completion receipts remain coordinator-owned and move-only.

mod channel_key;
mod error;
mod invitation;
mod opaque;
mod service;
mod transaction;
mod wire;

pub use channel_key::{
    CHANNEL_KEY_HASH_BYTES, CHANNEL_KEY_ITERATIONS, CHANNEL_KEY_LANES, CHANNEL_KEY_MEMORY_KIB,
    CHANNEL_KEY_SALT_BYTES, derive_channel_key_verifier,
};
pub use error::AuthError;
pub use invitation::{ACCOUNT_CREATION_INVITE_BYTES, AccountCreationInvite};
pub use opaque::{
    OPAQUE_KE1_BYTES, OPAQUE_KE2_BYTES, OPAQUE_KE3_BYTES, OPAQUE_REGISTRATION_RECORD_BYTES,
    OPAQUE_REGISTRATION_REQUEST_BYTES, OPAQUE_REGISTRATION_RESPONSE_BYTES,
    OPAQUE_SERVER_LOGIN_STATE_BYTES, OPAQUE_SERVER_SETUP_BYTES, OpaqueAuthentication, OpaqueKe1,
    OpaqueKe2, OpaqueKe3, OpaqueProfile, OpaqueRegistrationRecord, OpaqueRegistrationRequest,
    OpaqueRegistrationResponse, OpaqueServerLoginState, finish_authentication, finish_registration,
};
pub use service::{
    AUTHENTICATION_TRANSACTION_RECORD_BYTES, AccountAuthenticationState,
    AccountCreationStartParameters, AccountCreationState, AccountCredentialRecord,
    AccountDeletionChallenge, AccountDeletionIntent, AccountFinishOutcome, AccountOperationContext,
    AccountResponseIntent, AccountResponsePlan, AccountStartOutcome, AuthenticationGrant,
    AuthenticationLookup, AuthenticationStartParameters, AuthenticationTransactionRecord,
    CREATION_TRANSACTION_RECORD_BYTES, CREDENTIAL_CHANGE_TRANSACTION_RECORD_BYTES,
    CreateAccountIntent, CreationAdmission, CreationTransactionRecord,
    CreationTransactionRestartMetadata, CredentialChangeStartParameters, CredentialChangeState,
    CredentialChangeTransactionRecord, CredentialChangeTransactionRestartMetadata,
    CredentialReplacementIntent, DestructiveAccountSnapshot, FreshAuthenticationProof,
    SealedAccountFinishOutcome, SealedAccountStart, authentication_completion,
    begin_account_creation, begin_account_deletion, begin_authentication, begin_credential_change,
    finish_account_authentication, finish_account_creation, finish_credential_change,
};
pub use transaction::{
    ACCOUNT_CREATION_TIMEOUT_TICKS, AUTHENTICATION_GRANT_TIMEOUT_SECONDS,
    AUTHENTICATION_GRANT_TIMEOUT_TICKS, AUTHENTICATION_TIMEOUT_TICKS, AccountRouteBinding,
    AccountTransaction, AccountTransactionBinding, CREDENTIAL_CHANGE_TIMEOUT_TICKS,
    DELETION_CONFIRMATION_TIMEOUT_TICKS, FRESH_AUTH_TIMEOUT_TICKS, TransactionClass,
};
pub use wire::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, ACCOUNT_SERVICE_RESPONSE_BYTES, AccountRequestPayload,
    AccountServiceEnvelope, AccountServiceResponse, AccountServiceResponsePayload,
    AuthenticatedAccountRequest, AuthenticationFinish, AuthenticationStart, Completion,
    CreationFinish, CreationStart, CredentialChangeFinish, CredentialChangeStart,
    EncodedAccountRequestPlaintext, EncodedAccountResponsePlaintext, OpenedAccountServiceRequest,
    encode_request_plaintext, encode_response_plaintext, open_and_parse_request,
    open_and_parse_response,
};
