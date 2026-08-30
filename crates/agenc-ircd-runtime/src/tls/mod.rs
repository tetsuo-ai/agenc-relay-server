//! TLS 1.3 server configuration and the hand-driven rustls stream (spec 8.1
//! through 8.3, lines 464-526).

pub mod config;
pub mod stream;

pub use config::{
    ADMIN_ALPN, CLIENT_ALPN, CertChain, ClientAuth, FEDERATION_ALPN, MAX_CHAIN_CERTIFICATES,
    MAX_TLS_DOCUMENT_BYTES, PrivateKey, TLS_PLAINTEXT_BUFFER_LIMIT_BYTES,
    TLS_TICKET_LIFETIME_SECONDS, TLS_TICKET_ROTATION_SECONDS, TlsConfigError, TlsEndpointProfile,
    TrustStore, build_client_config, build_server_config, build_server_config_blocking,
    load_certificate_chain, load_trust_store, provider,
};
pub use stream::{
    ACCEPT_TO_TLS_DEADLINE, CLOSE_NOTIFY_GRACE, DEFAULT_HANDSHAKES_IN_PROGRESS, HandshakeLimiter,
    MAX_HANDSHAKES_IN_PROGRESS, TLS_TO_REGISTRATION_DEADLINE, TlsHandshakeError, TlsStream,
    WRITE_STALL_BUDGET,
};
