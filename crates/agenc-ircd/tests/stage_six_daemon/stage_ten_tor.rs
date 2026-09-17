//! Native Tor client against the production daemon in an isolated Tor v3 network.
#![forbid(unsafe_code)]

use super::*;

use agenc_ircd_config::{OnboardingDescriptor, OnionAddress, OnionEndpoint, SocksEndpoint};
use agenc_ircd_runtime::tor_client::{
    TorClientOwner, TorClientProfile, TorClientTls, TorIsolationContext,
};
use agenc_ircd_testkit::ScriptedEntropy;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const CANARY: &[u8] = b"PING :agenc-stage-ten-private-plaintext-canary\r\n";

fn wait_for_network(path: &Path) -> TestResult<(OnionAddress, SocketAddr)> {
    let deadline = Instant::now() + Duration::from_secs(360);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(failure("isolated Tor network did not become ready"));
        }
        thread::sleep(Duration::from_millis(100));
    }
    let mut contents = String::new();
    fs::File::open(path)?
        .take(513)
        .read_to_string(&mut contents)?;
    if contents.len() > 512 {
        return Err(failure("Tor network descriptor exceeds its test bound"));
    }
    let lines = contents.lines().collect::<Vec<_>>();
    let [onion, proxy] = lines.as_slice() else {
        return Err(failure("Tor network descriptor has unexpected fields"));
    };
    let proxy: SocketAddr = proxy.parse()?;
    if !proxy.ip().is_loopback() || proxy.port() == 0 {
        return Err(failure("Tor qualification requires a loopback proxy"));
    }
    Ok((OnionAddress::parse(onion)?, proxy))
}

async fn receive_pong(
    connection: &mut agenc_ircd_runtime::tor_client::TorConnection,
) -> TestResult {
    let mut response = Vec::new();
    for _ in 0..4096 {
        let mut byte = [0_u8; 1];
        connection.read_exact(&mut byte).await?;
        response.push(byte[0]);
        if response.ends_with(b"\r\n") {
            if response.ends_with(b" PONG :agenc-stage-ten-private-plaintext-canary\r\n") {
                return Ok(());
            }
            response.clear();
        }
    }
    Err(failure("Tor session did not return its encrypted PONG"))
}

async fn exercise_contexts(
    fixture: &LiveFixture,
    onion: OnionAddress,
    proxy: SocketAddr,
) -> TestResult {
    let descriptor = OnboardingDescriptor {
        network_id: fixture.network_id,
        server_name: DnsName::parse(DNS_NAME)?,
        dns: None,
        onion: Some(OnionEndpoint {
            address: onion,
            port: 5858,
            tls_spki_sha256: *fixture.tls.leaf_spki_sha256(),
        }),
        recovery_epoch: RecoveryEpoch::from_bytes([9; 16]),
        account_service_hpke_key_id: [10; 32],
        account_service_hpke_public_key: [11; 32],
        sequencer_key_set: Some(agenc_ircd_config::SequencerKeySetFacts {
            generation: 12,
            hash: [13; 32],
        }),
    };
    let first = TorIsolationContext::network(fixture.network_id);
    let second = TorIsolationContext::account(
        fixture.network_id,
        AccountId::from_random(AccountRandomId::from_bytes([2; 16])),
    );
    // Public test credentials make control-event comparisons reproducible.
    let mut entropy = ScriptedEntropy::new([b'a'; 64].into_iter().chain([b'b'; 64]).collect())?;
    let owner = TorClientOwner::new(
        SocksEndpoint::Loopback(proxy),
        vec![first, second],
        Duration::from_secs(30),
        &mut entropy,
    )?;
    let tls = TorClientTls::new(TrustStore::parse(fixture.tls.ca_certificate_der())?);
    let mut connections = Vec::new();
    for context in [first, second, first] {
        let mut connection = owner
            .connect(context, TorClientProfile::Onion, &descriptor, &tls)
            .await?;
        connection.write_all(CANARY).await?;
        connection.flush().await?;
        tokio::time::timeout(Duration::from_secs(15), receive_pong(&mut connection)).await??;
        connections.push(connection);
    }
    println!("three native Tor v3 sessions returned encrypted PONGs across two isolation contexts");
    Ok(())
}

#[test]
#[ignore = "requires the isolated Stage 10 Tor network controller"]
fn native_tor_v3_sessions_preserve_context_isolation() -> TestResult {
    let coordination = PathBuf::from(
        std::env::var_os("AGENC_STAGE10_TOR_COORDINATION")
            .ok_or_else(|| failure("Tor qualification controller is absent"))?,
    );
    let fixture = LiveFixture::create()?;
    let mut daemon = DaemonProcess::start(&fixture.config_path)?;
    let mut admin = AdminClient::connect(&fixture)?;
    fs::write(
        coordination.join("daemon-port"),
        fixture.public_address.port().to_string(),
    )?;
    let (onion, proxy) = wait_for_network(&coordination.join("network-ready"))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(exercise_contexts(&fixture, onion, proxy))?;
    fs::write(coordination.join("sessions-complete"), b"3\n")?;
    admin.confirm_process("DIE :Tor qualification complete")?;
    assert!(daemon.wait()?.success());
    Ok(())
}
