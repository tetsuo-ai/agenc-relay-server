# Deployment files

Install `systemd/arcd.service` under `/etc/systemd/system`, review every path, then run `systemctl daemon-reload`. The daemon opens its configured listeners itself. The package does not support systemd socket activation.

Choose one file from `systemd/profiles` and install it as `/etc/systemd/system/arcd.service.d/20-address-families.conf`. The direct and dual profiles allow Unix, IPv4, and IPv6 sockets. The onion local-admin profile allows only Unix sockets. Use the onion remote-admin profile only when an enabled remote administration listener requires IP sockets.

The service account, socket-access group, and directory records live under `sysusers.d` and `tmpfiles.d`. Apply both records before running `arcd init`. Tmpfiles creates the empty daemon-owned data layout, the persistent runtime directory, and the root-owned `/var/lib/arcd-operator` directory. Root initialization refuses a missing data directory; this prevents it from creating state that the service account cannot use. Run initialization as root so it can install daemon-owned state and the separate operator credential in one no-replace workflow. Install the host package that provides `/usr/bin/setfacl` before starting the service. The service can write only its state, backup, log, and runtime paths. Its key and trust directories are read-only inside the service mount namespace. The operator authority and Tor hidden-service directory are inaccessible from that namespace.

Add the Tor service account and each approved local administrator login to `arcd-sockets`. Start a new login session for an administrator after changing group membership, and restart Tor after adding its service account. The daemon service applies an access ACL to `/run/arcd` and a default ACL to new sockets each time it starts. Members can traverse the mode-0750 directory and connect to mode-0660 sockets. They cannot create or remove files in the directory.

Keep local administration tied to exact numeric UIDs in `allowed_uids`. Do not add the shared `arcd-sockets` GID to `allowed_gids`, because the Tor account also belongs to that group. Group membership permits a Unix-socket connection; the UID allowlist and operator signing proof grant administrative authority.

The service preserves `/run/arcd` when stopped. This lets `arcd check-config --config /etc/arcd/config.toml` validate the configured Unix-socket parents without starting the daemon. The stopped directory contains no live socket after shutdown.

The Tor snippet creates a version 3 onion service and forwards virtual port 6697 to the Unix socket at `/run/arcd/onion.sock`. Install the snippet in Tor's configuration only after checking the `HiddenServiceDir` ownership and the runtime socket path. The Tor key directory stays owned by the Tor service account and does not receive the socket-access ACL. Replace the account name below with the Tor service account used by the host, then verify the owner, mode, and daemon denial:

```sh
tor_service_account=debian-tor
test "$(stat -c '%U' /var/lib/tor/arcd)" = "$tor_service_account"
test "$(stat -c '%a' /var/lib/tor/arcd)" = 700
runuser -u arcd -- test ! -r /var/lib/tor/arcd
runuser -u arcd -- test ! -w /var/lib/tor/arcd
```

After starting both services, verify the modes and ACLs:

```sh
stat -c '%a %n' /run/arcd /run/arcd/onion.sock /run/arcd/admin.sock
getfacl -cp /run/arcd /run/arcd/onion.sock /run/arcd/admin.sock
```

The expected modes are 750 for the directory and 660 for each socket. The directory must contain `group:arcd-sockets:r-x` and `default:group:arcd-sockets:rw-`. Each socket must contain `group:arcd-sockets:rw-`.

Run this before installing the files:

```sh
python3 scripts/check-deploy.py check
```

After installation, verify the service and selected drop-in with `systemd-analyze verify arcd.service`. Review `systemd-analyze security arcd.service` on the target host.
