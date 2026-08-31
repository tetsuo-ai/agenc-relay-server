# Deployment files

Install `systemd/agenc-ircd.service` under `/etc/systemd/system`, review every path, then run `systemctl daemon-reload`. The daemon opens its configured listeners itself. The package does not support systemd socket activation.

Choose one file from `systemd/profiles` and install it as `/etc/systemd/system/agenc-ircd.service.d/20-address-families.conf`. The direct and dual profiles allow Unix, IPv4, and IPv6 sockets. The onion local-admin profile allows only Unix sockets. Use the onion remote-admin profile only when an enabled remote administration listener requires IP sockets.

The service account and directory records live under `sysusers.d` and `tmpfiles.d`. The service can write only its state, backup, log, and runtime paths. Its key and trust directories are read-only inside the service mount namespace.

The Tor snippet creates a version 3 onion service and forwards virtual port 6697 to the Unix socket at `/run/agenc-ircd/onion.sock`. Install the snippet in Tor's configuration only after checking the `HiddenServiceDir` ownership and the runtime socket path.

Run this before installing the files:

```sh
python3 scripts/check-deploy.py check
```

After installation, verify the service and selected drop-in with `systemd-analyze verify agenc-ircd.service`. Review `systemd-analyze security agenc-ircd.service` on the target host.
