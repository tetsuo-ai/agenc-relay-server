//! Outbound federation enforces the configured key-exchange group policy.

#![forbid(unsafe_code)]

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use agenc_relay_config::GroupPolicy;
use agenc_relay_runtime::tls::{
    CertChain, ClientTlsStream, FEDERATION_ALPN, PrivateKey, TlsStream, TrustStore,
    build_federation_client_config_with_group_policy, provider,
};
use agenc_relay_testkit::TlsFixture;
use agenc_relay_types::ServerId;
use rustls::crypto::aws_lc_rs::kx_group;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{NamedGroup, RootCertStore, ServerConfig};
use tokio::io::duplex;

#[tokio::test]
async fn federation_client_enforces_required_hybrid_and_allows_preferred_fallback()
-> Result<(), Box<dyn Error>> {
    let coordinator_id = ServerId::from_bytes([10; 16]);
    let coordinator = TlsFixture::mint_federation([1; 32], coordinator_id)?;
    let edge = TlsFixture::mint_federation([2; 32], ServerId::from_bytes([20; 16]))?;
    for policy in [GroupPolicy::HybridPreferred, GroupPolicy::HybridRequired] {
        for hybrid in [false, true] {
            let mut server_provider = provider();
            server_provider.kx_groups = if hybrid {
                vec![kx_group::X25519MLKEM768]
            } else {
                vec![kx_group::X25519]
            };
            let server_provider = Arc::new(server_provider);
            let mut roots = RootCertStore::empty();
            roots.add(CertificateDer::from(edge.ca_certificate_der().to_vec()))?;
            let verifier = WebPkiClientVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(&server_provider),
            )
            .build()?;
            let mut server = ServerConfig::builder_with_provider(server_provider)
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![CertificateDer::from(
                        coordinator.leaf_certificate_der().to_vec(),
                    )],
                    PrivateKeyDer::try_from(coordinator.leaf_private_key_pkcs8_der().to_vec())?,
                )?;
            server.alpn_protocols = vec![FEDERATION_ALPN.to_vec()];
            let client = build_federation_client_config_with_group_policy(
                TrustStore::parse(coordinator.ca_certificate_der())?,
                (
                    CertChain::parse(edge.leaf_certificate_der())?,
                    PrivateKey::parse(edge.leaf_private_key_pkcs8_der())?,
                ),
                *coordinator.leaf_spki_sha256(),
                coordinator_id,
                policy,
            )?;
            let (server_io, client_io) = duplex(1 << 16);
            let (server_result, client_result) = tokio::join!(
                TlsStream::handshake(
                    server_io,
                    Arc::new(server),
                    FEDERATION_ALPN,
                    Duration::from_secs(5),
                ),
                ClientTlsStream::handshake(
                    client_io,
                    client,
                    ServerName::try_from("core.example".to_owned())?,
                    FEDERATION_ALPN,
                ),
            );
            let should_connect = hybrid || policy == GroupPolicy::HybridPreferred;
            assert_eq!(
                server_result.is_ok(),
                should_connect,
                "{policy:?}, hybrid={hybrid}"
            );
            assert_eq!(
                client_result.is_ok(),
                should_connect,
                "{policy:?}, hybrid={hybrid}"
            );
            if should_connect {
                let server = server_result?;
                assert_eq!(
                    server.negotiated_group(),
                    Some(if hybrid {
                        NamedGroup::X25519MLKEM768
                    } else {
                        NamedGroup::X25519
                    }),
                );
                assert!(server.peer_certificates().is_some());
            }
        }
    }
    Ok(())
}
