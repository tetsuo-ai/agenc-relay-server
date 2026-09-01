# Deployment files

Install `systemd/agenc-ircd.service` under `/etc/systemd/system`, review every path, then run `systemctl daemon-reload`. The daemon opens its configured listeners itself. The package does not support systemd socket activation.

Choose one file from `systemd/profiles` and install it as `/etc/systemd/system/agenc-ircd.service.d/20-address-families.conf`. The direct and dual profiles allow Unix, IPv4, and IPv6 sockets. The onion local-admin profile allows only Unix sockets. Use the onion remote-admin profile only when an enabled remote administration listener requires IP sockets.

The service account, socket-access group, and directory records live under `sysusers.d` and `tmpfiles.d`. Install the host package that provides `/usr/bin/setfacl` before starting the service. The service can write only its state, backup, log, and runtime paths. Its key and trust directories are read-only inside the service mount namespace. The Tor hidden-service directory is inaccessible from that namespace.

Add the Tor service account and each approved local administrator login to `agenc-ircd-sockets`. Start a new login session for an administrator after changing group membership, and restart Tor after adding its service account. The daemon service applies an access ACL to `/run/agenc-ircd` and a default ACL to new sockets each time it starts. Members can traverse the mode-0750 directory and connect to mode-0660 sockets. They cannot create or remove files in the directory.

Keep local administration tied to exact numeric UIDs in `allowed_uids`. Do not add the shared `agenc-ircd-sockets` GID to `allowed_gids`, because the Tor account also belongs to that group. Group membership permits a Unix-socket connection; the UID allowlist and operator signing proof grant administrative authority.

The Tor snippet creates a version 3 onion service and forwards virtual port 6697 to the Unix socket at `/run/agenc-ircd/onion.sock`. Install the snippet in Tor's configuration only after checking the `HiddenServiceDir` ownership and the runtime socket path. The Tor key directory stays owned by the Tor service account and does not receive the socket-access ACL. Replace the account name below with the Tor service account used by the host, then verify the owner, mode, and daemon denial:

```sh
tor_service_account=debian-tor
test "$(stat -c '%U' /var/lib/tor/agenc-ircd)" = "$tor_service_account"
test "$(stat -c '%a' /var/lib/tor/agenc-ircd)" = 700
runuser -u agenc-ircd -- test ! -r /var/lib/tor/agenc-ircd
runuser -u agenc-ircd -- test ! -w /var/lib/tor/agenc-ircd
```

After starting both services, verify the modes and ACLs:

```sh
stat -c '%a %n' /run/agenc-ircd /run/agenc-ircd/onion.sock /run/agenc-ircd/admin.sock
getfacl -cp /run/agenc-ircd /run/agenc-ircd/onion.sock /run/agenc-ircd/admin.sock
```

The expected modes are 750 for the directory and 660 for each socket. The directory must contain `group:agenc-ircd-sockets:r-x` and `default:group:agenc-ircd-sockets:rw-`. Each socket must contain `group:agenc-ircd-sockets:rw-`.

Run this before installing the files:

```sh
python3 scripts/check-deploy.py check
```

After installation, verify the service and selected drop-in with `systemd-analyze verify agenc-ircd.service`. Review `systemd-analyze security agenc-ircd.service` on the target host.
