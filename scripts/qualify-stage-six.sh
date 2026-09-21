#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for tool in systemd-analyze tor; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "stage-six qualification: missing $tool" >&2
        exit 1
    fi
done

python3 scripts/check-deploy.py check

qualification_root="$(mktemp -d)"
trap 'find "$qualification_root" -depth -delete' EXIT
mkdir -p \
    "$qualification_root/usr/bin" \
    "$qualification_root/etc/systemd/system/arcd.service.d"
install -m 0755 /bin/true "$qualification_root/usr/bin/arcd"
install -m 0755 /bin/true "$qualification_root/usr/bin/setfacl"
install -m 0644 \
    deploy/systemd/arcd.service \
    "$qualification_root/etc/systemd/system/arcd.service"
for target in sysinit basic multi-user network-online; do
    printf '%s\n' \
        "[Unit]" \
        "Description=Stage 06 qualification target" \
        >"$qualification_root/etc/systemd/system/$target.target"
done

for profile in deploy/systemd/profiles/*.conf; do
    install -m 0644 \
        "$profile" \
        "$qualification_root/etc/systemd/system/arcd.service.d/20-address-families.conf"
    systemd-analyze --root="$qualification_root" verify arcd.service
done

tor_root="$qualification_root/tor"
mkdir -m 0700 -p "$tor_root/data" "$tor_root/onion"
torrc="$tor_root/torrc"
printf '%s\n' \
    "DataDirectory $tor_root/data" \
    "ClientOnly 1" \
    "DisableNetwork 1" \
    "SocksPort 0" \
    "DNSPort 0" \
    "SafeSocks 1" \
    "TestSocks 1" \
    "HiddenServiceDir $tor_root/onion" \
    "HiddenServiceVersion 3" \
    "HiddenServicePort 6697 unix:$tor_root/onion.sock" \
    >"$torrc"
chmod 0600 "$torrc"
tor --verify-config -f "$torrc"

if rg -n --hidden --glob '!target/**' --glob '!fuzz/target/**' \
    'LISTEN_FDS|LISTEN_PID|SOCKS_PROXY|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|resolve_addr|lookup_host' \
    crates deploy; then
    echo "stage-six qualification: forbidden socket, proxy, or DNS path found" >&2
    exit 1
fi

echo "stage-six controlled host and Tor qualification: ok"
