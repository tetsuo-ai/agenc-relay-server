# AgenC Relay operator guide

The daemon executable is `arcd`. Initialize a fresh schema-generation-5
database using the paths below. Earlier development profiles and stored
formats are rejected; this private project has no deployment migration.

## Install the service account and directories

Install the records from `deploy/sysusers.d` and `deploy/tmpfiles.d` before initialization. The daemon runs as `arcd`. The sysusers record also creates `arcd-sockets`, the group used only to reach the runtime sockets. Tmpfiles creates the empty daemon-owned data layout and the root-owned `/var/lib/arcd-operator` directory. Initialization accepts those empty directories, preserves their ownership, and refuses any nonempty, replaced, or symlinked target. Keep `/var/lib/arcd`, its key directory, its state directory, its trust directory, and its backup directory at mode 0700. Secret files use mode 0600.

Install `deploy/systemd/arcd.service` under `/etc/systemd/system`. Install the host package that provides `/usr/bin/setfacl`. Choose the matching address-family file from `deploy/systemd/profiles` and install it as the service drop-in described in `deploy/README.md`. The daemon opens configured listeners directly; systemd socket activation is not supported. Review the executable and configuration paths before enabling the service. Run the deployment checker from the source tree:

```sh
python3 scripts/check-deploy.py check
```

## Initialize a coordinator

Create a new stopped coordinator with one of the three listener templates:

```sh
sudo arcd init \
  --config /etc/arcd/config.toml \
  --profile public \
  --data-dir /var/lib/arcd \
  --runtime-dir /run/arcd \
  --operator-signing-key-file /var/lib/arcd-operator/operator-signing.key \
  --server-name chat.example \
  --display-name Example \
  --dns-name chat.example
```

The `public`, `onion`, and `dual` profiles write a complete configuration with every listener disabled. Run initialization as root after applying the tmpfiles record. Root initialization refuses a missing data directory instead of creating root-owned state that the service cannot use. It installs daemon files with the ownership of the precreated data directories, keeps the operator signing key in the separate root-owned operator directory, and writes the configuration last. The command never replaces an existing operator key or durable identity. Save the printed operator signing-key path with the other protected operator credentials; do not copy it into `/var/lib/arcd`, the configuration directory, or the runtime directory.

Initialization prints a Tor fragment, the service-unit reminder, and certificate enrollment instructions. It does not install them. It does not contact a certificate authority or bind a public socket.

Before them it prints the new node's `network-id=`, `server-id=`, `recovery-epoch=`, `operator-id=` and `operator-signing-key-file=` lines. The `recovery-epoch` is the node's own database epoch, which its federation hello carries: a peer's `[[federation.peer]]` record for this node pins it together with the `server-id`. Keep the printed lines. For an edge the receipt is the only `arcd` output that prints its own epoch, because the edge's `print-onboarding` prints its coordinator's; a later `storage restore` prints the new epoch it declares. An earlier `arcd init` printed no `recovery-epoch=` line: before upgrading such an edge, record its own epoch from that earlier `arcd print-onboarding`, or initialize the edge again.

## Enroll certificates and enable listeners

Place each certificate and private key at the path shown in the generated configuration. Check the certificate identity and the configured DNS name or onion pin. Set `enabled = true` only for listeners whose bind address, certificate, and transport purpose have been reviewed.

For public `client_tls` or `client_wss` listeners, `tls_ocsp_staple_file`
names a protected file containing the leaf certificate's DER OCSP response
(1..65,536 bytes). Setting `[tls] require_ocsp_staple = true` requires that
file for every enabled public listener. Provision a current response, refresh
it before expiry, and use `REHASH` to activate it. The daemon transports the
response as opaque bytes; the setting does not verify revocation status or
freshness. Onion, federation and admin listeners reject this field.

For an onion listener, install `deploy/tor/arcd.torrc.snippet` after checking the hidden-service and Unix-socket paths. Tor creates the onion identity. Copy the resulting onion address and the certificate SPKI hash into the paired configuration fields.

Add the Tor service account to `arcd-sockets`, then restart Tor so its process receives the new supplementary group. Keep `/var/lib/tor/arcd` owned by the Tor service account and inaccessible to `arcd` and `arcd-sockets`. The shared group applies only to `/run/arcd` and the sockets below it.

Initialization puts its effective UID in both the local listener's `allowed_uids` and the generated operator's `local_uids`. Root initialization therefore selects UID 0. Add each approved local administrator login to the same group and start a new login session. Put each administrator's exact numeric UID in both admission lists, and keep the shared group GID out of `allowed_gids`. The group grants directory traversal and socket connection. Administrative access still requires UID admission and the configured Ed25519 operator proof.

At each daemon start, the service gives `arcd-sockets` traverse access to the mode-0750 runtime directory and installs a default read-write ACL for new mode-0660 sockets. Verify the resulting modes and named ACL entries with the commands in `deploy/README.md` before enabling the onion listener or local administration.

## Check the stopped configuration

Run the full stopped-node check before the first start and after changing keys, paths, listener identity, or storage settings:

```sh
arcd check-config --config /etc/arcd/config.toml
```

The command parses the complete document, opens every configured secret under the protected-file rules, reconstructs the authenticated database through a read-only handle, checks the database identity, and prints the observed host controls. It does not create the writer lock, repair the database, replace the rollback guard, or remove stale temporary files. Exit status 2 means at least one required control was observed absent. An unreadable control is reported as unknown instead of present.

A storage refusal names its closed cause after the fixed text `filesystem policy rejected storage:`; the same label appears as `error=filesystem_<cause>` on the daemon's log events. The cause is diagnostic only: it never changes whether an operation was refused, committed, or left indeterminate, and it never carries a path, an errno string, or content.

A client reads the same bare failure (`904`, or `FAIL ... UNAVAILABLE`) whichever check refused its login or account request. The daemon records the check as `event=account_request_refused severity=warning reason=<check>`. The reasons are a closed set: `request_unreadable`, `wrong_phase`, `exchange_in_progress`, `no_live_exchange`, `connection_attempt_limit`, `rate_limit`, `forward_unavailable` (an edge could not forward the request to the account authority), `authority_refused`, `principal_mismatch` and `carrier_busy`. The event never names a login, an account, a session or a connection.

| Cause | Meaning | Action |
| --- | --- | --- |
| `missing_state` | a required entry (rollback guard, database, lock, directory, plan) is absent | do not create or regenerate it by hand; restore from a verified backup into a new directory, or run the stopped construction command that owns it |
| `permission_rejected` | ownership, mode, or an access check refused the entry | fix the owner and mode to the documented values (directories 0700, secrets 0600, owned by the service account or root); never widen the checks |
| `insufficient_capacity` | the free-space reserve, quota, or configured ceiling is exhausted | free space or raise the ceiling within its table range after a fresh free-space check; an uncertain write that hit this cause still requires the normal stop and reopen |
| `unqualified` | the filesystem, mount, target, or measured tuple is not the qualified one | move the state to a qualified ext4 mount or re-run the storage qualification on this host |
| `io_failure` | the kernel reported an input/output error | treat the device as failing; preserve evidence and restore elsewhere |
| `unsafe_path` | the path, name, link count, type, or filesystem boundary is unsafe | remove the symlink, foreign file, or cross-filesystem layout; the daemon never follows or replaces it |
| `unknown` | an operating-system error outside the classified set | read the kernel and service-manager logs; the daemon keeps no raw error text |

Run the stopped-node commands either as the service account or as root. As the service account (for example through `runuser -u arcd -- arcd check-config --config /etc/arcd/config.toml`) the command trusts the account's own files. As root, name the service account explicitly so its material is trusted without weakening any other file check:

```sh
arcd check-config --config /etc/arcd/config.toml --service-user arcd
arcd print-onboarding --config /etc/arcd/config.toml --service-user arcd
arcd account-invite create --descriptor /etc/arcd/onboarding.txt --signing-key-file /var/lib/arcd-operator/invite-signing.key --expires-in 86400 --service-user arcd
```

`--service-user` names a local account from `/etc/passwd`; it is refused for an unknown name and for any caller other than root or that account. It never changes the daemon's refusal to start as root, and the host-control report still names the invoking identity. Root keeps its own operator-owned invitation signing key; the option only lets root read the service-owned keys, trust manifests, and directories that the daemon itself would read.

The packaged tmpfiles and service records keep `/run/arcd` at mode 0750 while the daemon is stopped. This allows the same Host-depth path checks to run before the first start and between service runs.

The process cannot observe every service-manager restriction from inside its own namespace. Check the installed unit separately with `systemd-analyze security` and the deployment checker. `check-config` does not prove swap encryption, backup handling, certificate issuance, firewall rules, or Tor routing.

## Storage and federation baseline

This ARC baseline uses schema generation 5 and exact ARC profile negotiation.
Initialize fresh private development state. Earlier schema generations are
rejected, and no stopped migration command is provided. Preserve older state
separately; never remove authenticated records to bypass an admission failure.

Use matching ARC profile hashes on coordinator, edge, and client builds.
Encrypted origin floors, witnessed checkpoints, and durable barrier records
are part of the current schema from initialization onward. Restore and recovery
must preserve their authenticated relationships.

Optional WSS and plaintext history settings are described in
[Stage 09 operations](stage-09-operations.md).

## Enable the encrypted profile

The encrypted profile rides on the federation link between the coordinator and its edges, and only edges offer it to clients. Enable federation on every node first. Each `[[federation.peer]]` record pins its peer exactly:

- `server_id` and `recovery_epoch` are the `server-id=` and `recovery-epoch=` lines the peer's `arcd init` printed; a later `storage restore` of that peer prints its new epoch.
- `certificate_spki_sha256` is the SHA-256 hash of the subject public key info of the peer's federation certificate.
- `signing_public_key` is the Ed25519 public key of the raw 32-byte seed the peer's `init` wrote to `keys/federation-signing.key`. No `arcd` command prints it.
- On an edge, the coordinator record's `endpoints` lists the coordinator's federation listener. A coordinator's edge records keep `endpoints = []`, because each edge dials its coordinator.

Every node then names the same public sequencer credentials document, and the coordinator also holds the sequencer key `init` wrote. Create the document of a new network once, on the coordinator, after its configuration passes `check-config`:

```sh
arcd sequencer-credentials create \
  --config /etc/arcd/config.toml \
  --sequencer-key-file /var/lib/arcd/keys/sequencer.key \
  --not-before 1791000000 \
  --not-after 1822536000 \
  --output /etc/arcd/sequencer-credentials.bin \
  --service-user arcd
```

The command takes the network ID from the configuration and reads the key under the protected-file rules. It writes set generation zero with one credential at key generation zero, valid from `--not-before` through `--not-after`, both canonical decimal Unix seconds and both inclusive. The coordinator signs a record only under a credential whose interval covers that record's validation time, so start the interval no later than the network's first start and end it after the key's planned lifetime. Before publishing, the command verifies the document with the parser and key-set check startup runs. It creates the output as a new file with mode 0644 whatever the umask, so the service account can read a document root created. It refuses an existing path instead of replacing it, printing `initialization target already exists`, the offline commands' message for any existing target. It also refuses an output below a group- or world-writable directory or a symbolic link, which the protected-file rules would keep every node from reading. It prints the document's `sequencer-key-set-generation=` and `sequencer-key-set-hash=` lines. The document holds no private material. `--service-user` has the meaning described above.

Install the same bytes on every node under the protected-file rules: a single-link regular file owned by root or the service account, with neither the file nor any ancestor directory group- or world-writable. `init` already wrote each node's `coordinator_server_id`. On the coordinator, set:

```toml
[e2ee]
enabled = true
sequencer_private_key_file = "/var/lib/arcd/keys/sequencer.key"
sequencer_credentials_file = "/etc/arcd/sequencer-credentials.bin"
```

On each edge, set `enabled = true` and the same `sequencer_credentials_file`, without a sequencer key. Restart every node, because the credentials file is restart-only. Then `print-onboarding` on each node prints the four E2EE lines, with the generation and hash the command printed. The command creates only a new network's first document; later rotation and retirement documents are provisioned as described in [Rotate the sequencer credential](#rotate-the-sequencer-credential).

## Upgrade to a new encrypted profile

A release whose encrypted profile hash differs from the running one is a
coordinated upgrade. This release's hash differs from release candidate 3's,
because the ReInit target revision changed two companion object layouts. CAP
and ECAP accept only the exact profile version and hash, so there is no
mixed-version operation of the encrypted profile.

- Stop the coordinator and every edge that has the encrypted profile enabled,
  install the new release on all of them, and start the coordinator before
  its edges.
- A federation link whose ends run different hashes fails its ECAP
  negotiation and closes, and the edge's redials fail the same way until both
  ends match. An upgraded end that reads the other end's OFFER answers it with
  `ERROR :ARC-MLS profile mismatch` before it closes, and each end logs
  `federation_link_closed`. While its coordinator link is closed, an edge
  serves only what architecture Section 20.10 allows and refuses new
  registrations and global commands with `FAIL <command> NETWORK_UNAVAILABLE`.
  Edges that run the coordinator's hash are unaffected.
- An upgraded node advertises the new profile value to every client. A
  client of the previous hash finds that value unequal to its own and does
  not enable the encrypted profile: its encrypted conversations stay blocked
  until the client is upgraded and never fall back to plaintext (companion
  Section 11.1). Plaintext channels keep working.
- This release does not migrate ReInit state stored under the previous
  profile; the coordinator starts with it and keeps each such conversation
  closed. A conversation whose latest sequencer record is a ReInit
  activation or abort of the previous profile is retired, together with a
  successor bound for it, and so is a conversation that took ordinary
  records after its ReInit Commit was finalized: a retired conversation
  accepts no Commit, application message, ReInit attempt or close. A ReInit
  attempt left open under the previous profile can neither complete nor be
  aborted, and a ReInit Commit finalized under the previous profile admits
  no attempt of this release. A conversation that was closed stays closed.
  Plaintext stays refused on all of these routes, and this release offers
  no way to bind such a channel to a new group.
- Databases written by development builds of this profile from before its
  ReInit enforcement are not supported: a coordinator refuses to start on
  one that holds a ReInit activation its build stored without installing
  the successor, or with a target this release does not admit. Start such a
  test network again from new databases. Release candidate 3's databases
  are upgraded as described above.
- Do not start release candidate 3 on a database that this release has run
  on. The storage format is unchanged (schema generation 5), so nothing
  refuses it, but the database then holds encrypted state of this profile
  that release candidate 3 does not read as this release does. Going back
  to release candidate 3 means restoring a backup taken before the upgrade
  into a new directory with the stopped `storage restore` command, which
  declares a new recovery epoch.
- After the upgrade, run `print-onboarding` on every node that has the
  encrypted profile enabled, distribute the new descriptor, and create new
  account invitations from it. A client refuses a descriptor whose
  `e2ee-profile-sha256` differs from its build, so descriptors and
  invitations printed before the upgrade no longer import. Clients take the
  new descriptor through the explicit confirmation of a changed pin that
  architecture Sections 6.3 and 9.3 require. A node with the encrypted
  profile disabled prints the same descriptor as before.
- Recovery epochs, keys, the base federation profile and the storage format
  (schema generation 5) do not change.

## Print onboarding data and account invitations

After enabling at least one reviewed client endpoint, print the canonical connection descriptor:

```sh
arcd print-onboarding --config /etc/arcd/config.toml
```

The command reconstructs the database through the same read-only inspection path while it reads the authenticated recovery epoch. A running writer causes the read-only database open to fail.

The descriptor pins the recovery epoch the node advertises in `agenc.ag/recovery`. A coordinator advertises its own database epoch. An edge advertises its coordinator's, the `recovery_epoch` of its enabled coordinator `[[federation.peer]]` record, so its descriptor pins that value and not the edge's own database epoch; an edge without an enabled coordinator record cannot serve and is refused with `configuration validation failed`. When the coordinator's recovery epoch changes, update the edge's record, restart the edge and distribute its new descriptor: clients treat the change as an identity transition that needs their explicit confirmation.

Create a time-limited account invitation with a separate offline Ed25519 invitation key:

```sh
arcd account-invite create \
  --descriptor ./connect.txt \
  --signing-key-file ./account-invite-signing.key \
  --expires-in 86400
```

Send the exact three-line output through the trusted invitation channel. Do not place the invitation signing key in the daemon configuration.

## Reload and administration

Use the local Unix admin socket for routine operation. Each operator still proves its configured signing key after the operating-system peer check. Remote administration uses its separate pinned mutual-TLS listener. Client IRC connections have no administrative authority.

`REHASH` validates a complete replacement configuration before activation. Identity, storage-key, listener-purpose, wire-limit, OPAQUE, E2EE, HPKE, and onion-identity changes require a stopped restart or their named transition procedure. A rejected reload leaves the active configuration unchanged.

To export stopped login-index rotation events together with ordinary admin
events, sign `AUDIT EXPORT <from> <to> maintenance-v1` on the authenticated admin
connection. The [maintenance export profile](admin-audit-maintenance-v1.md)
defines the exact batch, record labels, historical verification, and limits.
The operator needs the `audit` permission.

## Size the pre-authentication command budget

Every line a connection sends before its registration completes is charged to
that connection's `[limits.rate.preauth_command]` bucket. The generated
configuration names no rate table, so the Appendix C.6 default applies: one
token per second with a burst of 24. The hard row is ten tokens per second with
a burst of 50; a configuration with a faster rate or a larger burst fails
validation. A line beyond the available credit is answered with
`263 * <command> :Please wait a while and try again.` and is not processed; the
connection stays open, and the 30-second registration limit still applies.

The default is sized for account clients. An `ACCTCREATE` request sends 16
`DATA` lines and its `END` with no reply between them, and network delay can
deliver them at once, so a burst below 17 can refuse the end of an account
request however the client paces it. The credit beyond that run lets a client
that paces its lines to the bucket finish account creation, or a login before
registration, followed by registration within the 30-second limit at round
trips of up to 3 seconds, as `tor-exit` and `onion` connections can have.
Lowering the rate or the burst below the default can therefore make account
creation and pre-registration login fail on slow routes; raising them up to
the hard row admits more unauthenticated lines per connection before
registration. Rates are reloadable: lowering one clamps each connection's
current credit to the new burst, and raising one adds no immediate credit.

## Qualify storage growth on a host

`arcd storage qualify` measures the production storage engine on the
filesystem that will hold the state directory. Give it two new directories on
that filesystem and paths for the unsigned report, the raw log, and a JSON
summary. It writes the report only when the largest observed growth stays at
or below the qualification ceiling; the raw log and summary are kept in every
case. The command may fallocate a temporary ballast file in the scratch
directory to reach the reserve boundary and removes it before exiting. Run it
before a release on each target and filesystem tuple you intend to claim, not
on a live node.

## Inspect a signed release decision

A binary reports its compiled profiles with `arcd conformance --json`
and leaves `qualified_claims` empty. Completed qualification is a detached
directory signed by the release key, and the binary never bundles that key.
To see which claims a decision grants the binary you deployed, pass the
decision directory and the public key you obtained through a trusted channel:

```sh
arcd conformance --json \
  --release-decision /path/to/decision \
  --trusted-public-key /etc/arcd/trusted-release-public.pem
```

The command verifies the signature with that key only, then compares the
decision's source commit, target, and artifact digest with the running
executable. Claims appear only when all three match. A verified decision for
another build leaves the claims empty and names the reason. A failed
signature, an unreadable file, or a malformed decision is an error, and the
binary treats a key found beside the decision as untrusted.

## Rotate and recover keys

Assign one purpose to each key. Record its generation, creation time, activation time, retirement time, and recovery procedure.

- Rotate TLS certificates only when the configured identity and pin rules still pass.
- Add new backup and audit public keys to their trust manifests before activating the matching private keys. Retain old verification keys for every surviving signed artifact. Keep an audit verification key permanently after it signs a permanent checkpoint.
- Do not regenerate the OPAQUE setup or fake-credential key in place. A compromise disables the affected authentication path until a reviewed migration and client re-registration procedure exists.
- Change the account-service HPKE key with a hard-cut onboarding transition. Distribute the pending descriptor, quiesce account operations, restart the coordinator and edges with the new pair, invalidate old transactions, verify activation, then erase the old private key.
- Use the storage rekey procedure for the storage master and rollback guard. Use the login-index transition for its key. Do not replace those files directly.
- Treat a new onion identity as a new endpoint and distribute an explicit onboarding update.

Store encrypted key backups separately from state backups. Audit access to those backups and rehearse restoration at least every six months.

## Understand backup signing-key validity windows

Each `[[key]]` row of the backup trust manifest carries `not_before` and `not_after`. Restore accepts a backup only when the creation time written in the backup header lies in the interval of the retained key that signed it. That creation time is a claim made by the same private key: the interval constrains which claims a retained key may vouch for, and nothing in the current backup format proves that the backup existed during the interval. A holder of a compromised private key can sign a header that claims an earlier time, and such a backup verifies as long as the key's row is still in the manifest and the claimed time lies in its interval. The format consults no external clock, receipt, or timestamp authority; treat the interval as retention policy for verification, not as evidence of when a backup was made.

The controls that hold independently of the claimed time are:

- The trust manifest itself. It is an offline-authorized, mode-0600 protected file; a key whose row has been removed verifies nothing, whatever a header claims. This is the only way to stop a key from vouching for backups.
- The current rollback guard. The stopped `storage restore` command compares the backup's embedded source boundary against the readable current guard where one exists, so a backup cannot silently move the state behind the boundary the guard records.
- Backup custody. Restore only from artifacts whose origin and storage you control; a signature and an interval do not substitute for custody.
- Retained old keys and disaster-recovery generation pins. Keep every verification key that a surviving legitimate backup still needs, and pin the schema and storage key generations you expect a restored state to carry.

Distinguish two states of a key row. A historically retained key is one whose private half was retired and destroyed in a controlled rotation; keep its row, with its original interval, until no surviving backup signed by it is needed, so old legitimate backups still restore. A disabled key is one whose private half was lost, exposed, or otherwise compromised; remove its row immediately, because a retained interval would still accept backdated backups from whoever holds it. Backups it signed can no longer be restored from that manifest, so re-create current backups under a fresh key before removing the row when a controlled window allows. Do not extend an interval to accept a backup whose claimed time falls outside it; investigate why the claim and the rotation record disagree instead.

Do not narrow an interval to a single second to compensate: `created_at` is the signed claim, and a key holder chooses it. If a deployment requires proof of when a backup was made, that is a separate, versioned design with an external timestamp or receipt authority, not a change to how the current format is parsed.

## Rotate the sequencer credential

The coordinator holds the active sequencer key at
`e2ee.sequencer_private_key_file`, an optional successor key at
`e2ee.sequencer_successor_private_key_file`, and an optional retired key at
`e2ee.sequencer_retired_private_key_file`. Every node reads the same public
credentials file. Rotate in this order:

1. Provision the successor credential out of band: a fresh key, key
   generation plus one, an interval whose `not_before` lies inside the active
   interval, and the active key's continuity signature.
2. Publish a credentials file with set generation plus one holding the
   active credential first and the successor second. Install it on every
   edge and, together with the successor private key, on the coordinator.
3. Restart the coordinator and the edges; a changed credentials file is
   restart-only and never reloads in place.
4. Monitor the migration telemetry: set generation, pinned-route and
   unfinished-record counts per credential, the overlap deadline, and the
   blocked-route count. Groups migrate when their controllers finalize a
   context transition to the successor.
5. Retire the old credential with a successor-only credentials file. Before
   the overlap deadline the coordinator refuses that file while any normal
   route still pins the old credential; at or after the deadline it accepts
   the file and blocks those routes. Move the old key to the retired path
   whenever a normal route or an unfinished receipt still needs it.
6. Destroy the old key only after the coordinator has recorded its release
   fact: the credential is out of the accepted set, no normal route pins it,
   and no unfinished receipt names it.
7. If routes are blocked because the retired key is unavailable, restore it
   from custody to the retired path and restart; the unfinished receipts then
   complete under their original credential.

Steady state:

```toml
[e2ee]
sequencer_private_key_file = "/etc/arcd/keys/sequencer-active.key"
sequencer_credentials_file = "/etc/arcd/sequencer-credentials.bin"
```

Overlap:

```toml
[e2ee]
sequencer_private_key_file = "/etc/arcd/keys/sequencer-active.key"
sequencer_successor_private_key_file = "/etc/arcd/keys/sequencer-successor.key"
sequencer_credentials_file = "/etc/arcd/sequencer-credentials.bin"
```

Retirement with a retained signer:

```toml
[e2ee]
sequencer_private_key_file = "/etc/arcd/keys/sequencer-successor.key"
sequencer_retired_private_key_file = "/etc/arcd/keys/sequencer-active.key"
sequencer_credentials_file = "/etc/arcd/sequencer-credentials.bin"
```

Startup refuses, without installing any signer: a key whose public key
matches no credential the node knows; a public key reused under a different
credential ID; a credentials file whose set or key generation rolls back; a
retired key for a credential outside the verified history; a file with more
than two credentials, a generation gap, or two successors; a successor-only
file before the overlap deadline while a normal route still pins the old
credential; a missing active or successor key; the same key bytes at two
paths or shared with another purpose; a failed protected-file check; and a
REHASH that changes any sequencer path or the credentials file. A missing
retired key that a route still needs does not stop the node: the affected
routes are blocked and an audit event names the count.

No workflow signs an old receipt with a replacement key, silently updates
every conversation's pin on reload, or keeps accepting new records for a
group pinned to a retired credential. Public credentials are retained
permanently for historical verification; only the private key is destroyed.

## Respond to an incident

For suspected key compromise, rollback, equivocation, database corruption, or secret exposure, quiesce the affected listeners. Preserve encrypted audit evidence and fence the affected incarnation or key. Send a client-visible security notice after verifying the facts.

Do not disable certificate checks, delete tombstones, reuse an incarnation, force an MLS epoch, or accept partial storage. Restore into a new directory with the stopped `storage restore` command and review the changed recovery epoch before activation.
