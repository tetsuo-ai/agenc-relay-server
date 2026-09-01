# AgenC IRC operator guide

## Install the service account and directories

Install the records from `deploy/sysusers.d` and `deploy/tmpfiles.d` with the host's normal systemd tools. The daemon runs as `agenc-ircd`. Keep `/var/lib/agenc-ircd`, its key directory, its state directory, its trust directory, and its backup directory at mode 0700. Secret files use mode 0600.

Install `deploy/systemd/agenc-ircd.service` under `/etc/systemd/system`. Choose the matching address-family file from `deploy/systemd/profiles` and install it as the service drop-in described in `deploy/README.md`. The daemon opens configured listeners directly; systemd socket activation is not supported. Review the executable and configuration paths before enabling the service. Run the deployment checker from the source tree:

```sh
python3 scripts/check-deploy.py check
```

## Initialize a coordinator

Create a new stopped coordinator with one of the three listener templates:

```sh
agenc-ircd init \
  --config /etc/agenc-ircd/config.toml \
  --profile public \
  --data-dir /var/lib/agenc-ircd \
  --runtime-dir /run/agenc-ircd \
  --server-name chat.example \
  --display-name Example \
  --dns-name chat.example
```

The `public`, `onion`, and `dual` profiles write a complete configuration with every listener disabled. Initialization creates independent key files, trust manifests, and an authenticated database. The command refuses existing targets and writes the configuration last. Save the printed operator signing-key path in protected operator storage.

Initialization prints a Tor fragment, the service-unit reminder, and certificate enrollment instructions. It does not install them. It does not contact a certificate authority or bind a public socket.

## Enroll certificates and enable listeners

Place each certificate and private key at the path shown in the generated configuration. Check the certificate identity and the configured DNS name or onion pin. Set `enabled = true` only for listeners whose bind address, certificate, and transport purpose have been reviewed.

For an onion listener, install `deploy/tor/agenc-ircd.torrc.snippet` after checking the hidden-service and Unix-socket paths. Tor creates the onion identity. Copy the resulting onion address and the certificate SPKI hash into the paired configuration fields.

## Check the stopped configuration

Run the full stopped-node check before the first start and after changing keys, paths, listener identity, or storage settings:

```sh
agenc-ircd check-config --config /etc/agenc-ircd/config.toml
```

The command parses the complete document, opens every configured secret under the protected-file rules, reconstructs the authenticated database through a read-only handle, checks the database identity, and prints the observed host controls. It does not create the writer lock, repair the database, replace the rollback guard, or remove stale temporary files. Exit status 2 means at least one required control was observed absent. An unreadable control is reported as unknown instead of present.

The process cannot observe every service-manager restriction from inside its own namespace. Check the installed unit separately with `systemd-analyze security` and the deployment checker. `check-config` does not prove swap encryption, backup handling, certificate issuance, firewall rules, or Tor routing.

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

## Rotate and recover keys

Assign one purpose to each key. Record its generation, creation time, activation time, retirement time, and recovery procedure.

- Rotate TLS certificates only when the configured identity and pin rules still pass.
- Add new backup and audit public keys to their trust manifests before activating the matching private keys. Retain old verification keys for every surviving signed artifact. Keep an audit verification key permanently after it signs a permanent checkpoint.
- Do not regenerate the OPAQUE setup or fake-credential key in place. A compromise disables the affected authentication path until a reviewed migration and client re-registration procedure exists.
- Change the account-service HPKE key with a hard-cut onboarding transition. Distribute the pending descriptor, quiesce account operations, restart the coordinator and edges with the new pair, invalidate old transactions, verify activation, then erase the old private key.
- Use the storage rekey procedure for the storage master and rollback guard. Use the login-index transition for its key. Do not replace those files directly.
- Treat a new onion identity as a new endpoint and distribute an explicit onboarding update.

Store encrypted key backups separately from state backups. Audit access to those backups and rehearse restoration at least every six months.

## Respond to an incident

For suspected key compromise, rollback, equivocation, database corruption, or secret exposure, quiesce the affected listeners. Preserve encrypted audit evidence and fence the affected incarnation or key. Send a client-visible security notice after verifying the facts.

Do not disable certificate checks, delete tombstones, reuse an incarnation, force an MLS epoch, or accept partial storage. Restore into a new directory with the stopped `storage restore` command and review the changed recovery epoch before activation.
