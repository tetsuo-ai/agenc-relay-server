# AgenC IRC operator guide

## Install the service account and directories

Install the records from `deploy/sysusers.d` and `deploy/tmpfiles.d` before initialization. The daemon runs as `agenc-ircd`. The sysusers record also creates `agenc-ircd-sockets`, the group used only to reach the runtime sockets. Tmpfiles creates the empty daemon-owned data layout and the root-owned `/var/lib/agenc-ircd-operator` directory. Initialization accepts those empty directories, preserves their ownership, and refuses any nonempty, replaced, or symlinked target. Keep `/var/lib/agenc-ircd`, its key directory, its state directory, its trust directory, and its backup directory at mode 0700. Secret files use mode 0600.

Install `deploy/systemd/agenc-ircd.service` under `/etc/systemd/system`. Install the host package that provides `/usr/bin/setfacl`. Choose the matching address-family file from `deploy/systemd/profiles` and install it as the service drop-in described in `deploy/README.md`. The daemon opens configured listeners directly; systemd socket activation is not supported. Review the executable and configuration paths before enabling the service. Run the deployment checker from the source tree:

```sh
python3 scripts/check-deploy.py check
```

## Initialize a coordinator

Create a new stopped coordinator with one of the three listener templates:

```sh
sudo agenc-ircd init \
  --config /etc/agenc-ircd/config.toml \
  --profile public \
  --data-dir /var/lib/agenc-ircd \
  --runtime-dir /run/agenc-ircd \
  --operator-signing-key-file /var/lib/agenc-ircd-operator/operator-signing.key \
  --server-name chat.example \
  --display-name Example \
  --dns-name chat.example
```

The `public`, `onion`, and `dual` profiles write a complete configuration with every listener disabled. Run initialization as root after applying the tmpfiles record. Root initialization refuses a missing data directory instead of creating root-owned state that the service cannot use. It installs daemon files with the ownership of the precreated data directories, keeps the operator signing key in the separate root-owned operator directory, and writes the configuration last. The command never replaces an existing operator key or durable identity. Save the printed operator signing-key path with the other protected operator credentials; do not copy it into `/var/lib/agenc-ircd`, the configuration directory, or the runtime directory.

Initialization prints a Tor fragment, the service-unit reminder, and certificate enrollment instructions. It does not install them. It does not contact a certificate authority or bind a public socket.

## Enroll certificates and enable listeners

Place each certificate and private key at the path shown in the generated configuration. Check the certificate identity and the configured DNS name or onion pin. Set `enabled = true` only for listeners whose bind address, certificate, and transport purpose have been reviewed.

For public `client_tls` or `client_wss` listeners, `tls_ocsp_staple_file`
names a protected file containing the leaf certificate's DER OCSP response
(1..65,536 bytes). Setting `[tls] require_ocsp_staple = true` requires that
file for every enabled public listener. Provision a current response, refresh
it before expiry, and use `REHASH` to activate it. The daemon transports the
response as opaque bytes; the setting does not verify revocation status or
freshness. Onion, federation and admin listeners reject this field.

For an onion listener, install `deploy/tor/agenc-ircd.torrc.snippet` after checking the hidden-service and Unix-socket paths. Tor creates the onion identity. Copy the resulting onion address and the certificate SPKI hash into the paired configuration fields.

Add the Tor service account to `agenc-ircd-sockets`, then restart Tor so its process receives the new supplementary group. Keep `/var/lib/tor/agenc-ircd` owned by the Tor service account and inaccessible to `agenc-ircd` and `agenc-ircd-sockets`. The shared group applies only to `/run/agenc-ircd` and the sockets below it.

Initialization puts its effective UID in both the local listener's `allowed_uids` and the generated operator's `local_uids`. Root initialization therefore selects UID 0. Add each approved local administrator login to the same group and start a new login session. Put each administrator's exact numeric UID in both admission lists, and keep the shared group GID out of `allowed_gids`. The group grants directory traversal and socket connection. Administrative access still requires UID admission and the configured Ed25519 operator proof.

At each daemon start, the service gives `agenc-ircd-sockets` traverse access to the mode-0750 runtime directory and installs a default read-write ACL for new mode-0660 sockets. Verify the resulting modes and named ACL entries with the commands in `deploy/README.md` before enabling the onion listener or local administration.

## Check the stopped configuration

Run the full stopped-node check before the first start and after changing keys, paths, listener identity, or storage settings:

```sh
agenc-ircd check-config --config /etc/agenc-ircd/config.toml
```

The command parses the complete document, opens every configured secret under the protected-file rules, reconstructs the authenticated database through a read-only handle, checks the database identity, and prints the observed host controls. It does not create the writer lock, repair the database, replace the rollback guard, or remove stale temporary files. Exit status 2 means at least one required control was observed absent. An unreadable control is reported as unknown instead of present.

A storage refusal names its closed cause after the fixed text `filesystem policy rejected storage:`; the same label appears as `error=filesystem_<cause>` on the daemon's log events. The cause is diagnostic only: it never changes whether an operation was refused, committed, or left indeterminate, and it never carries a path, an errno string, or content.

| Cause | Meaning | Action |
| --- | --- | --- |
| `missing_state` | a required entry (rollback guard, database, lock, directory, plan) is absent | do not create or regenerate it by hand; restore from a verified backup into a new directory, or run the stopped construction command that owns it |
| `permission_rejected` | ownership, mode, or an access check refused the entry | fix the owner and mode to the documented values (directories 0700, secrets 0600, owned by the service account or root); never widen the checks |
| `insufficient_capacity` | the free-space reserve, quota, or configured ceiling is exhausted | free space or raise the ceiling within its table range after a fresh free-space check; an uncertain write that hit this cause still requires the normal stop and reopen |
| `unqualified` | the filesystem, mount, target, or measured tuple is not the qualified one | move the state to a qualified ext4 mount or re-run the storage qualification on this host |
| `io_failure` | the kernel reported an input/output error | treat the device as failing; preserve evidence and restore elsewhere |
| `unsafe_path` | the path, name, link count, type, or filesystem boundary is unsafe | remove the symlink, foreign file, or cross-filesystem layout; the daemon never follows or replaces it |
| `unknown` | an operating-system error outside the classified set | read the kernel and service-manager logs; the daemon keeps no raw error text |

Run the stopped-node commands either as the service account or as root. As the service account (for example through `runuser -u agenc-ircd -- agenc-ircd check-config --config /etc/agenc-ircd/config.toml`) the command trusts the account's own files. As root, name the service account explicitly so its material is trusted without weakening any other file check:

```sh
agenc-ircd check-config --config /etc/agenc-ircd/config.toml --service-user agenc-ircd
agenc-ircd print-onboarding --config /etc/agenc-ircd/config.toml --service-user agenc-ircd
agenc-ircd account-invite create --descriptor /etc/agenc-ircd/onboarding.txt --signing-key-file /var/lib/agenc-ircd-operator/invite-signing.key --expires-in 86400 --service-user agenc-ircd
```

`--service-user` names a local account from `/etc/passwd`; it is refused for an unknown name and for any caller other than root or that account. It never changes the daemon's refusal to start as root, and the host-control report still names the invoking identity. Root keeps its own operator-owned invitation signing key; the option only lets root read the service-owned keys, trust manifests, and directories that the daemon itself would read.

The packaged tmpfiles and service records keep `/run/agenc-ircd` at mode 0750 while the daemon is stopped. This allows the same Host-depth path checks to run before the first start and between service runs.

The process cannot observe every service-manager restriction from inside its own namespace. Check the installed unit separately with `systemd-analyze security` and the deployment checker. `check-config` does not prove swap encryption, backup handling, certificate issuance, firewall rules, or Tor routing.

## Upgrade to schema generation 2

Stage 09 requires schema generation 2 in every feature combination. Stop the
daemon and migrate existing generation-1 state before starting the new binary.
The base federation profile also changes, so coordinate the upgrade across
coordinator and edge nodes. Follow the migration, backup, resume, and rollback
steps in [Stage 09 operations](stage-09-operations.md). That guide also covers
the independently optional WSS listener and plaintext history service.

## Upgrade encrypted federation state

The review changes add a durable operation-sequence floor for each companion
origin. The floor is written with a committed request result and survives
replay-result expiry. It uses a new typed record under E2EE state table 23,
record kind 9. Earlier binaries do not understand this record; keep a stopped-node
backup from before upgrading if a rollback to an earlier binary is required.

An origin created by an earlier build has no floor until this build commits a
request for it. After restart, retained replay history without a matching
floor causes the daemon to refuse that generation's `EORIGIN ADD` or `UPDATE`.
Reconnect the affected client with a fresh origin or establish a new
authenticated origin generation before continuing. Earlier retained results
cannot prove the latest sequence because their retention periods differ.

If all legacy replay history has expired, the daemon cannot distinguish a
previously used generation from one that never committed a request. Replace
legacy origins with uncertain history during upgrade, even if their
declarations are accepted. Deleted sequence history cannot be reconstructed.

Edge checkpoints now use the typed `WitnessedCursor` delivery-row arm (tag 4)
under the existing `delivery/v1/` key. It records that the cursor committed
with the latest record-chain witness heads. Earlier binaries reject this arm
as well as the new origin-floor record. Keep the pre-upgrade backup until the
upgrade is accepted.

An older or missing edge checkpoint automatically requests fresh base and
companion snapshots. An unfinished legacy barrier without a durable coordinator
identity fence stops startup and leaves its sealed state intact. Applied
legacy receipts with missing required retention evidence also fail closed.
Completing a pending barrier with the earlier binary can delete its immutable
parts, so that action alone does not produce a compatible checkpoint. Recovery
requires the stopped-daemon restore procedure with a backup free of these
incompatible barrier states. Do not delete barrier rows to bypass the check.

The outbound federation connection now enforces `tls.group_policy`. A node
configured with `hybrid_required` refuses a coordinator offering only
classical key exchange. Check both peers' TLS configuration before restarting
an edge with that policy.

## Print onboarding data and account invitations

After enabling at least one reviewed client endpoint, print the canonical connection descriptor:

```sh
agenc-ircd print-onboarding --config /etc/agenc-ircd/config.toml
```

The command reconstructs the database through the same read-only inspection path while it reads the authenticated recovery epoch. A running writer causes the read-only database open to fail.

Create a time-limited account invitation with a separate offline Ed25519 invitation key:

```sh
agenc-ircd account-invite create \
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

## Qualify storage growth on a host

`agenc-ircd storage qualify` measures the production storage engine on the
filesystem that will hold the state directory. Give it two new directories on
that filesystem and paths for the unsigned report, the raw log, and a JSON
summary. It writes the report only when the largest observed growth stays at
or below the qualification ceiling; the raw log and summary are kept in every
case. The command may fallocate a temporary ballast file in the scratch
directory to reach the reserve boundary and removes it before exiting. Run it
before a release on each target and filesystem tuple you intend to claim, not
on a live node.

## Inspect a signed release decision

A binary reports its compiled profiles with `agenc-ircd conformance --json`
and leaves `qualified_claims` empty. Completed qualification is a detached
directory signed by the release key, and the binary never bundles that key.
To see which claims a decision grants the binary you deployed, pass the
decision directory and the public key you obtained through a trusted channel:

```sh
agenc-ircd conformance --json \
  --release-decision /path/to/decision \
  --trusted-public-key /etc/agenc-ircd/trusted-release-public.pem
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
sequencer_private_key_file = "/etc/agenc-ircd/keys/sequencer-active.key"
sequencer_credentials_file = "/etc/agenc-ircd/sequencer-credentials.bin"
```

Overlap:

```toml
[e2ee]
sequencer_private_key_file = "/etc/agenc-ircd/keys/sequencer-active.key"
sequencer_successor_private_key_file = "/etc/agenc-ircd/keys/sequencer-successor.key"
sequencer_credentials_file = "/etc/agenc-ircd/sequencer-credentials.bin"
```

Retirement with a retained signer:

```toml
[e2ee]
sequencer_private_key_file = "/etc/agenc-ircd/keys/sequencer-successor.key"
sequencer_retired_private_key_file = "/etc/agenc-ircd/keys/sequencer-active.key"
sequencer_credentials_file = "/etc/agenc-ircd/sequencer-credentials.bin"
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
