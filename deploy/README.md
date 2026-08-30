# Deployment files

The `systemd` directory contains the service and TLS socket units. Install both files under `/etc/systemd/system`, review every path, then run `systemctl daemon-reload`. The service account and directory records live under `sysusers.d` and `tmpfiles.d`.

The socket unit binds TCP port 6697 before the daemon starts. The service unit gives the daemon write access only to its state, backup, and runtime paths. Edit the socket unit when the configured public listener uses a different address or port.

The Tor snippet creates a version 3 onion service and forwards virtual port 6697 to the Unix socket at `/run/agenc-ircd/onion.sock`. Install the snippet in Tor's configuration only after checking the `HiddenServiceDir` ownership and the runtime socket path.

Run this before installing the files:

```sh
python3 scripts/check-deploy.py check
```
