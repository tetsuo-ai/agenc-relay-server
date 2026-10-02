//! AUD-01 (SDK program): an encrypted network provisioned through the `arcd`
//! commands an operator runs, where every other suite in this binary writes
//! its node state through library initializers. `arcd init` creates the
//! coordinator and the edge, `arcd print-onboarding` carries the
//! coordinator's public pins to the edge's initialization, and the TLS,
//! federation and E2EE settings are the edits an operator makes to the
//! generated configuration. AUD-03: an edge's own descriptor pins the
//! coordinator epoch it advertises. AUD-02: `arcd sequencer-credentials
//! create` publishes the sequencer credentials every node names, so no
//! node's database, keys or credentials document comes from a library
//! initializer or a testkit builder; the TLS certificates come from the
//! test CA, as an operator's come from its CA.
#![forbid(unsafe_code)]

use super::*;

/// The `[e2ee]` block `arcd init` writes before the profile is enabled.
const DISABLED_E2EE_BLOCK: &str = "[e2ee]\n# Disabled until the sequencer credentials are published; false is core-only.\nenabled = false\n";
/// The public listener `arcd init` writes for the `public` profile.
const DISABLED_PUBLIC_LISTENER: &str = "enabled = false\npurpose = \"client_tls\"\nbind = \"203.0.113.1:6697\"\nmax_connections = 50000";
/// The sequencer credential interval the library fixtures use.
const SEQUENCER_INTERVAL: (u64, u64) = (0, 4_000_000_000);

/// Runs one `arcd` command and returns its standard output, failing with
/// its standard error when the command exits unsuccessfully.
fn arcd(arguments: &[&std::ffi::OsStr]) -> TestResult<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
        .args(arguments)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Err(failure(format!(
            "arcd {:?} exited with {}: {}",
            arguments.first(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// The memory, storage, shutdown and rate settings every Stage 08 fixture
/// node runs (`apply_common_overrides`), applied to a generated
/// configuration whose identity and admin lines `init` already wrote.
fn apply_fixture_sizes(config: &mut String) -> TestResult {
    replace_once(
        config,
        "memory_budget_bytes = 6442450944",
        &format!("memory_budget_bytes = {STAGE_EIGHT_MEMORY_BUDGET_BYTES}"),
    )?;
    replace_once(
        config,
        "quiesce_seconds = 5\ndrain_seconds = 20\nflush_seconds = 10\nstop_seconds = 5",
        "quiesce_seconds = 2\ndrain_seconds = 4\nflush_seconds = 4\nstop_seconds = 8",
    )?;
    replace_once(
        config,
        "database_max_bytes = 85899345920\nbackup_max_bytes = 107374182400",
        &format!(
            "database_max_bytes = {DATABASE_MAX_BYTES}\nbackup_max_bytes = {BACKUP_MAX_BYTES}"
        ),
    )?;
    replace_once(
        config,
        "disk_reserve_bytes = 1073741824\ndisk_reserve_percent = 5",
        &format!("disk_reserve_bytes = {DISK_RESERVE_BYTES}\ndisk_reserve_percent = 1"),
    )?;
    replace_once(
        config,
        "integrity_checkpoint_manifests = 100000",
        "integrity_checkpoint_manifests = 10000",
    )?;
    replace_once(
        config,
        "\n[privacy]",
        "\n[limits.rate.preauth_command]\nrefill_tokens = 10\nrefill_seconds = 1\nburst = 50\n\n[limits.rate.registered_command]\nrefill_tokens = 40\nrefill_seconds = 1\nburst = 200\n\n[privacy]",
    )
}

/// The value of the one `<name>=` line of a receipt or descriptor.
fn line_value<'a>(text: &'a str, name: &str) -> TestResult<&'a str> {
    let mut values = text.lines().filter_map(|line| line.strip_prefix(name));
    match (values.next(), values.next()) {
        (Some(value), None) => Ok(value),
        _ => Err(failure(format!(
            "expected exactly one {name} line in {text:?}"
        ))),
    }
}

/// One node directory laid out as `arcd init` requires: a private root, a
/// configuration directory, a mode-0750 runtime directory and a separate
/// mode-0700 operator directory; `init` creates the data directory.
struct CliNode {
    root: TestRoot,
    name: &'static str,
    dns_name: String,
    role: NodeRole,
    config_path: PathBuf,
    data_dir: PathBuf,
    runtime_dir: PathBuf,
    tls_dir: PathBuf,
    server_id: ServerId,
    /// The `recovery-epoch` of the init receipt: the node's own database
    /// epoch, which its federation hello carries and a peer record pins.
    own_epoch: String,
    operator_id: OperatorId,
    public_address: SocketAddr,
    client_tls: TlsFixture,
    federation_tls: TlsFixture,
}

/// Where a new node's network identity comes from.
enum CliInit<'a> {
    /// A new network.
    Coordinator,
    /// An edge importing the coordinator's descriptor and identity.
    Edge {
        descriptor: &'a str,
        coordinator_server_id: ServerId,
    },
}

impl CliNode {
    /// Runs `arcd init` for one node and enables its public listener on a
    /// reserved loopback address, which `print-onboarding` requires.
    fn init(name: &'static str, seed: u8, mode: &CliInit<'_>) -> TestResult<Self> {
        let root = TestRoot::create()?;
        let etc = root.path().join("etc");
        let tls_dir = etc.join("tls");
        let runtime_dir = root.path().join("run");
        let operator_dir = root.path().join("operator");
        create_directory(&etc, 0o700)?;
        create_directory(&tls_dir, 0o700)?;
        create_directory(&runtime_dir, 0o750)?;
        create_directory(&operator_dir, 0o700)?;
        let config_path = etc.join("config.toml");
        let data_dir = root.path().join("data");
        let dns_name = format!("{name}.client");
        let mut arguments: Vec<std::ffi::OsString> = vec![
            "init".into(),
            "--config".into(),
            config_path.clone().into(),
            "--profile".into(),
            "public".into(),
            "--data-dir".into(),
            data_dir.clone().into(),
            "--runtime-dir".into(),
            runtime_dir.clone().into(),
            "--operator-signing-key-file".into(),
            operator_dir.join("operator-signing.key").into(),
            "--server-name".into(),
            name.into(),
            "--display-name".into(),
            "StageEight".into(),
            "--dns-name".into(),
            dns_name.clone().into(),
        ];
        let role = match mode {
            CliInit::Coordinator => NodeRole::Coordinator,
            CliInit::Edge {
                descriptor,
                coordinator_server_id,
            } => {
                let descriptor_path = root.path().join("coordinator-connect.txt");
                write_private(&descriptor_path, descriptor.as_bytes())?;
                arguments.extend([
                    "--coordinator-descriptor".into(),
                    descriptor_path.into(),
                    "--coordinator-server-id".into(),
                    coordinator_server_id.to_base64url().into(),
                ]);
                NodeRole::Edge
            }
        };
        let arguments: Vec<&std::ffi::OsStr> = arguments.iter().map(AsRef::as_ref).collect();
        let receipt = arcd(&arguments)?;
        let server_id = ServerId::parse(line_value(&receipt, "server-id=")?)?;
        let own_epoch = RecoveryEpoch::parse(line_value(&receipt, "recovery-epoch=")?)?;
        let operator_id = OperatorId::parse(line_value(&receipt, "operator-id=")?)?;
        let public_address = reserve_loopback_address()?;
        let client_tls = TlsFixture::mint([seed; 32], &dns_name)?;
        let federation_tls = TlsFixture::mint_federation([seed.wrapping_add(1); 32], server_id)?;
        let node = Self {
            root,
            name,
            dns_name,
            role,
            config_path,
            data_dir,
            runtime_dir,
            tls_dir,
            server_id,
            own_epoch: own_epoch.to_base64url(),
            operator_id,
            public_address,
            client_tls,
            federation_tls,
        };
        node.edit(|config| {
            replace_once(
                config,
                DISABLED_PUBLIC_LISTENER,
                &format!(
                    "enabled = true\npurpose = \"client_tls\"\nbind = \"{}\"\nmax_connections = 32",
                    node.public_address
                ),
            )?;
            apply_fixture_sizes(config)
        })?;
        node.write_tls()?;
        Ok(node)
    }

    /// Applies one operator edit to the generated configuration.
    fn edit(&self, change: impl FnOnce(&mut String) -> TestResult) -> TestResult {
        let mut config = fs::read_to_string(&self.config_path)?;
        change(&mut config)?;
        fs::write(&self.config_path, config)?;
        Ok(())
    }

    /// Enrolls the client and federation certificates at the paths the
    /// generated configuration names.
    fn write_tls(&self) -> TestResult {
        write_private(
            &self.tls_dir.join("server.crt"),
            self.client_tls.leaf_certificate_der(),
        )?;
        write_private(
            &self.tls_dir.join("server.key"),
            self.client_tls.leaf_private_key_pkcs8_der(),
        )?;
        write_private(
            &self.tls_dir.join("federation.crt"),
            self.federation_tls.leaf_certificate_der(),
        )?;
        write_private(
            &self.tls_dir.join("federation.key"),
            self.federation_tls.leaf_private_key_pkcs8_der(),
        )
    }

    fn print_onboarding(&self) -> TestResult<String> {
        arcd(&[
            "print-onboarding".as_ref(),
            "--config".as_ref(),
            self.config_path.as_os_str(),
        ])
    }

    /// The standard error of a `print-onboarding` that must be refused.
    fn print_onboarding_refusal(&self) -> TestResult<String> {
        let output = Command::new(env!("CARGO_BIN_EXE_arcd"))
            .arg("print-onboarding")
            .arg("--config")
            .arg(&self.config_path)
            .stdin(Stdio::null())
            .output()?;
        if output.status.success() || !output.stdout.is_empty() {
            return Err(failure(format!(
                "print-onboarding was not refused for {}",
                self.name
            )));
        }
        Ok(String::from_utf8(output.stderr)?)
    }

    /// AUD-02: runs `arcd sequencer-credentials create` on the coordinator
    /// with the sequencer key `init` wrote, and returns the public document
    /// with the key-set hash the command printed. The document must equal,
    /// byte for byte, the one the testkit builds for the same key.
    fn create_sequencer_credentials(&self, descriptor: &str) -> TestResult<(Vec<u8>, String)> {
        let key_file = self.data_dir.join("keys/sequencer.key");
        let output = self.root.path().join("sequencer-credentials.bin");
        let printed = arcd(&[
            "sequencer-credentials".as_ref(),
            "create".as_ref(),
            "--config".as_ref(),
            self.config_path.as_os_str(),
            "--sequencer-key-file".as_ref(),
            key_file.as_os_str(),
            "--not-before".as_ref(),
            SEQUENCER_INTERVAL.0.to_string().as_ref(),
            "--not-after".as_ref(),
            SEQUENCER_INTERVAL.1.to_string().as_ref(),
            "--output".as_ref(),
            output.as_os_str(),
        ])?;
        if line_value(&printed, "sequencer-key-set-generation=")? != "0" {
            return Err(failure(format!("unexpected key set: {printed:?}")));
        }
        let key_set_hash = line_value(&printed, "sequencer-key-set-hash=")?.to_owned();
        let document = fs::read(&output)?;
        let seed: [u8; 32] = fs::read(&key_file)?
            .as_slice()
            .try_into()
            .map_err(|_| failure("sequencer key is not 32 bytes"))?;
        let network_id = NetworkId::parse(line_value(descriptor, "network-id=")?)?;
        let expected = builders::sequencer_credentials_document(
            *network_id.as_bytes(),
            &Ed25519SecretKey::from_bytes(seed),
            SEQUENCER_INTERVAL,
        )?;
        if document != expected {
            return Err(failure(
                "the arcd credentials document differs from the testkit document",
            ));
        }
        Ok((document, key_set_hash))
    }

    /// The public half of the federation signing key `init` generated, the
    /// value a peer record pins.
    fn federation_signing_public_key(&self) -> TestResult<[u8; 32]> {
        let seed: [u8; 32] = fs::read(self.data_dir.join("keys/federation-signing.key"))?
            .as_slice()
            .try_into()
            .map_err(|_| failure("federation signing key is not 32 bytes"))?;
        Ok(*Ed25519SecretKey::from_bytes(seed).public_key().as_bytes())
    }

    /// The `[[federation.peer]]` record another node keeps for this one.
    fn peer_entry(&self, recovery_epoch: &str, endpoints: &str) -> TestResult<String> {
        Ok(format!(
            "[[federation.peer]]\nserver_id = \"{}\"\nserver_name = \"{}\"\nrole = \"{}\"\nrecovery_epoch = \"{recovery_epoch}\"\nendpoints = [{endpoints}]\ncertificate_spki_sha256 = \"{}\"\nsigning_public_key = \"{}\"\nenabled = true\n\n",
            self.server_id.to_base64url(),
            self.name,
            self.role.as_str(),
            encode_base64url_32(self.federation_tls.leaf_spki_sha256()),
            encode_base64url_32(&self.federation_signing_public_key()?),
        ))
    }

    /// Enables federation with `peers` behind the private CA bundle of
    /// their federation CAs. The coordinator serves the federation listener;
    /// an edge keeps the entry disabled and dials with its certificate.
    fn enable_federation(
        &self,
        peers: &[&Self],
        peer_entries: &str,
        listener: Option<SocketAddr>,
    ) -> TestResult {
        let mut bundle = String::new();
        for peer in peers {
            bundle.push_str(&pem_certificate(peer.federation_tls.ca_certificate_der()));
        }
        let ca_path = self.tls_dir.join("federation-ca.pem");
        write_private(&ca_path, bundle.as_bytes())?;
        let (enabled, bind) = listener.map_or((false, "127.0.0.1:1".to_owned()), |address| {
            (true, address.to_string())
        });
        let listener = format!(
            "[[listeners.endpoint]]\nname = \"federation\"\nenabled = {enabled}\npurpose = \"federation\"\nbind = \"{bind}\"\nmax_connections = 64\ntls_certificate_file = \"{}\"\ntls_private_key_file = \"{}\"\nclient_ca_file = \"{}\"\n\n",
            protected_path_text(&self.tls_dir.join("federation.crt"))?,
            protected_path_text(&self.tls_dir.join("federation.key"))?,
            protected_path_text(&ca_path)?,
        );
        self.edit(|config| {
            replace_once(
                config,
                "enabled = false\nsigning_private_key_file",
                &format!(
                    "enabled = true\nprivate_ca_file = \"{}\"\nsigning_private_key_file",
                    protected_path_text(&ca_path)?
                ),
            )?;
            replace_once(
                config,
                "connect_timeout_seconds = 10\n\n",
                &format!("connect_timeout_seconds = 10\n\n{peer_entries}"),
            )?;
            replace_once(
                config,
                "[[listeners.endpoint]]\nname = \"admin-local\"",
                &format!("{listener}[[listeners.endpoint]]\nname = \"admin-local\""),
            )
        })
    }

    /// Installs the public credentials document and enables the encrypted
    /// profile; the coordinator also names the sequencer key `init` wrote.
    fn enable_e2ee(&self, credentials: &[u8]) -> TestResult {
        let credentials_path = self.data_dir.join("keys/sequencer-credentials.bin");
        write_private(&credentials_path, credentials)?;
        let mut enabled = format!(
            "[e2ee]\nenabled = true\nsequencer_credentials_file = \"{}\"\n",
            protected_path_text(&credentials_path)?
        );
        if self.role == NodeRole::Coordinator {
            enabled.push_str(&format!(
                "sequencer_private_key_file = \"{}\"\n",
                protected_path_text(&self.data_dir.join("keys/sequencer.key"))?
            ));
        }
        self.edit(|config| replace_once(config, DISABLED_E2EE_BLOCK, &enabled))
    }

    /// Hands the node to the shared daemon fixture helpers.
    fn into_fixture(self) -> NodeFixture {
        NodeFixture {
            config_path: self.config_path,
            log_dir: self.data_dir.join("logs"),
            public_address: self.public_address,
            dns_name: self.dns_name,
            client_tls: self.client_tls,
            seed: 0,
            server_id: self.server_id,
            admin_socket: self.runtime_dir.join("admin.sock"),
            data_dir: self.data_dir,
            operator_id: self.operator_id,
            federation_listener: None,
            _root: self.root,
        }
    }
}

/// A coordinator and its edges after provisioning, before any start.
struct CliNetwork {
    coordinator: NodeFixture,
    edges: Vec<NodeFixture>,
    /// The `recovery-epoch` of the coordinator's onboarding descriptor.
    coordinator_epoch: String,
    /// Each edge's `arcd print-onboarding` descriptor, printed once its
    /// coordinator record is enabled.
    edge_descriptors: Vec<String>,
}

/// Provisions a coordinator and one edge per name with `arcd init` and
/// `arcd print-onboarding`, then makes the operator's federation and E2EE
/// edits. `arcd sequencer-credentials create` writes the public credentials
/// document from the sequencer key `init` wrote on the coordinator.
fn provision_cli_network(edge_names: &[&'static str]) -> TestResult<CliNetwork> {
    let coordinator = CliNode::init("core.test", 120, &CliInit::Coordinator)?;
    let descriptor = coordinator.print_onboarding()?;
    let coordinator_epoch = line_value(&descriptor, "recovery-epoch=")?.to_owned();
    // AUD-03: a coordinator's descriptor pins its own database epoch.
    if coordinator_epoch != coordinator.own_epoch {
        return Err(failure("the coordinator descriptor left its own epoch"));
    }
    let mut edges = Vec::new();
    for (index, name) in edge_names.iter().enumerate() {
        let seed = u8::try_from(index)?
            .checked_mul(2)
            .and_then(|offset| offset.checked_add(140))
            .ok_or_else(|| failure("too many edges"))?;
        edges.push(CliNode::init(
            name,
            seed,
            &CliInit::Edge {
                descriptor: &descriptor,
                coordinator_server_id: coordinator.server_id,
            },
        )?);
    }
    for edge in &edges {
        // An edge with no enabled coordinator record advertises no
        // coordinator epoch, so it gets no descriptor.
        let refused = edge.print_onboarding_refusal()?;
        if !refused.contains("configuration validation failed") {
            return Err(failure(format!("unexpected refusal: {refused}")));
        }
    }
    let (credentials, key_set_hash) = coordinator.create_sequencer_credentials(&descriptor)?;
    let federation_address = reserve_loopback_address()?;
    let coordinator_entry =
        coordinator.peer_entry(&coordinator_epoch, &format!("\"tcp:{federation_address}\""))?;
    let mut edge_entries = String::new();
    let mut edge_descriptors = Vec::new();
    for edge in &edges {
        edge.enable_federation(&[&coordinator], &coordinator_entry, None)?;
        edge.enable_e2ee(&credentials)?;
        // The coordinator's record pins the edge's own epoch, which its
        // init receipt printed; the edge's descriptor pins the coordinator's.
        edge_entries.push_str(&edge.peer_entry(&edge.own_epoch, "")?);
        let edge_descriptor = edge.print_onboarding()?;
        if line_value(&edge_descriptor, "recovery-epoch=")? != coordinator_epoch
            || edge.own_epoch == coordinator_epoch
        {
            return Err(failure(format!(
                "{} descriptor does not pin its coordinator's epoch",
                edge.name
            )));
        }
        // AUD-02: the descriptor's E2EE lines name the key set the command
        // published.
        if line_value(&edge_descriptor, "sequencer-key-set-generation=")? != "0"
            || line_value(&edge_descriptor, "sequencer-key-set-hash=")? != key_set_hash
        {
            return Err(failure(format!(
                "{} descriptor does not name the published key set",
                edge.name
            )));
        }
        edge_descriptors.push(edge_descriptor);
    }
    let edge_nodes: Vec<&CliNode> = edges.iter().collect();
    coordinator.enable_federation(&edge_nodes, &edge_entries, Some(federation_address))?;
    coordinator.enable_e2ee(&credentials)?;
    Ok(CliNetwork {
        coordinator: coordinator.into_fixture(),
        edges: edges.into_iter().map(CliNode::into_fixture).collect(),
        coordinator_epoch,
        edge_descriptors,
    })
}

/// A daemon whose standard error is kept beside its node, so a refused
/// startup reports the daemon's own line.
struct CliDaemon {
    process: DaemonProcess,
    stderr: PathBuf,
}

impl CliDaemon {
    fn start(fixture: &NodeFixture) -> TestResult<Self> {
        let stderr = fixture.data_dir.with_file_name("stderr.log");
        Ok(Self {
            process: DaemonProcess::start_logged(&fixture.config_path, None, Some(&stderr))?,
            stderr,
        })
    }

    /// Waits for one more established coordinator link than `before`, and
    /// fails at once with the daemon's standard error if it exits first.
    fn wait_for_link(&mut self, fixture: &NodeFixture, before: usize) -> TestResult {
        let deadline = Instant::now() + NETWORK_WAIT;
        while links_established(fixture) <= before {
            let child = self
                .process
                .child
                .as_mut()
                .ok_or_else(|| failure("daemon was already joined"))?;
            if let Some(status) = child.try_wait()? {
                self.process.child = None;
                return Err(failure(format!(
                    "{} exited with {status} before linking: {}",
                    fixture.dns_name,
                    fs::read_to_string(&self.stderr).unwrap_or_default()
                )));
            }
            if Instant::now() >= deadline {
                return Err(failure(format!(
                    "{} never established its coordinator link",
                    fixture.dns_name
                )));
            }
            thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    }
}

/// The complete `CAP LS 302` advertisement of one node.
fn advertised_capabilities(fixture: &NodeFixture) -> TestResult<Vec<String>> {
    let mut client = ArcClient::connect(fixture)?;
    client.send("CAP LS 302")?;
    client.read_until(|line| line.contains(" CAP * LS ") && !line.contains(" CAP * LS * :"))
}

/// AUD-01: an edge initialized by `arcd init --coordinator-descriptor`
/// starts, links to its coordinator, advertises the encrypted profile and
/// registers a client; after a SIGKILL it restarts and links again.
/// AUD-03: the edge's own descriptor pins the epoch its CAP advertises.
#[test]
fn a_cli_initialized_edge_serves_links_and_advertises_e2ee() -> TestResult {
    let network = provision_cli_network(&["edge-a.test"])?;
    let edge = network
        .edges
        .first()
        .ok_or_else(|| failure("the network has no edge"))?;
    let edge_descriptor = network
        .edge_descriptors
        .first()
        .ok_or_else(|| failure("the edge has no descriptor"))?;
    let mut coordinator = CliDaemon::start(&network.coordinator)?;
    let mut daemon = CliDaemon::start(edge)?;
    daemon.wait_for_link(edge, 0)?;
    let advertised = advertised_capabilities(edge)?;
    assert_contains(&advertised, "agenc.ag/e2ee-mls=v1,profile=")?;
    assert_contains(
        &advertised,
        &format!(
            "agenc.ag/recovery=v1.{}",
            line_value(edge_descriptor, "recovery-epoch=")?
        ),
    )?;
    assert_contains(
        &advertised,
        &format!("agenc.ag/recovery=v1.{}", network.coordinator_epoch),
    )?;
    let mut client = register_when_available(edge, "CliGuest")?;
    client.send("QUIT :done")?;

    let before = links_established(edge);
    daemon.process.kill()?;
    let mut restarted = CliDaemon::start(edge)?;
    restarted.wait_for_link(edge, before)?;
    let mut client = register_when_available(edge, "CliAgain")?;
    client.send("QUIT :done")?;
    assert!(restarted.process.stop()?.success());
    assert!(coordinator.process.stop()?.success());
    Ok(())
}

/// AUD-02: a coordinator and two edges provisioned only through `arcd`
/// (`init`, `print-onboarding` and `sequencer-credentials create`) plus the
/// operator's TLS, federation and E2EE edits: both edges link, advertise the
/// encrypted profile and the coordinator's recovery epoch, and register a
/// client.
#[test]
fn a_network_provisioned_only_with_arcd_links_and_advertises_e2ee() -> TestResult {
    let network = provision_cli_network(&["edge-a.test", "edge-b.test"])?;
    let mut coordinator = CliDaemon::start(&network.coordinator)?;
    let mut daemons = Vec::new();
    for edge in &network.edges {
        daemons.push(CliDaemon::start(edge)?);
    }
    for (edge, daemon) in network.edges.iter().zip(daemons.iter_mut()) {
        daemon.wait_for_link(edge, 0)?;
        let advertised = advertised_capabilities(edge)?;
        assert_contains(&advertised, "agenc.ag/e2ee-mls=v1,profile=")?;
        assert_contains(
            &advertised,
            &format!("agenc.ag/recovery=v1.{}", network.coordinator_epoch),
        )?;
        let mut client = register_when_available(edge, "CliMember")?;
        client.send("QUIT :done")?;
    }
    for daemon in &mut daemons {
        assert!(daemon.process.stop()?.success());
    }
    assert!(coordinator.process.stop()?.success());
    Ok(())
}
