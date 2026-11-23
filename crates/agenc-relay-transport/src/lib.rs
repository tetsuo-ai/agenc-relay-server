#![forbid(unsafe_code)]

//! Shared client TLS transport for AgenC Relay.

mod client_stream;
mod tls_config;

pub use client_stream::{CLOSE_NOTIFY_GRACE, ClientTlsStream, TlsHandshakeError};
pub use tls_config::{
    CLIENT_ALPN, GroupPolicy, MAX_CHAIN_CERTIFICATES, MAX_TLS_DOCUMENT_BYTES,
    TLS_PLAINTEXT_BUFFER_LIMIT_BYTES, TlsConfigError, TrustStore, build_client_config,
    build_pinned_client_config, certificate_spki_sha256, parse_certificates, provider,
    provider_for_group_policy,
};
