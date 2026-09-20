# warpper

Warpper is a DNS filter daemon for Linux. It is capable of blocking domains via a local DNS
resolver and enforces at the IP layer with nftables.

## What it does

- Runs a DNS resolver on `127.0.0.1:15353` (UDP + TCP)
- Redirects system DNS through it via an nftables `output` chain
- Checks each query against SQLite-backed rules
- Blocks by answering `0.0.0.0` / `::`, and forwards everything else upstream
- Optionally, it can drop traffic to blocked IPs at the nftables layer by enabling the firewall option (see below)
- Updates from public blocklists on a daily timer

## Requirements

- nftables v1.1.5+
- Python 3.11+

## Install

**Arch (AUR):**

    yay -S warpper
    sudo systemctl enable --now warpperd

**pip:**

    pip install warpper
    sudo warpperd

## Quick start

    sudo warpperctl status
    sudo warpperctl firewall enable        # intercept all system DNS

    dig @127.0.0.1 -p 15353 example.com +short     # real IP
    sudo warpperctl block example.com
    dig @127.0.0.1 -p 15353 example.com +short     # 0.0.0.0
    sudo warpperctl unblock example.com

If you don't want to enable the firewall layer and use the default nft table, point systemd-resolved
at the daemon instead:

    sudo resolvectl dns <iface> 127.0.0.1:15353

## CLI

    warpperctl block <domain>              # block an exact domain
    warpperctl block '*.doubleclick.net'   # wildcard
    warpperctl block '.example.com'        # subtree (implies wildcard)
    warpperctl block 're:^track\d+\.'      # regex
    warpperctl block reddit.com --time 9-5 --days weekdays
    warpperctl unblock <domain>            # remove all rules matching
    warpperctl whitelist <domain>          # permanent allow

    warpperctl check <domain>              # what would happen?
    warpperctl list                        # all active rules
    warpperctl logs --tail 20              # recent queries
    warpperctl logs --action block --since 1h # self explanatory
    warpperctl status                      # daemon summary

    warpperctl categories list|enable|disable <name>
    warpperctl firewall enable|disable|status
    warpperctl flush-cache
    warpperctl update                      # refresh the blocklists
    warpperctl reload                      # re-read rules from DB

Rule types are inferred: `*.foo` is wildcard, `.foo` means "foo and
everything under it," `re:` prefix for regex, exact match otherwise.

## Configuration

`/etc/warpper/warpper.conf`. Created on first start if missing. This is the default:

    [general]
    sinkhole_ip = 0.0.0.0
    upstream_dns = 1.1.1.1,8.8.8.8
    enable_firewall = false
    db_path = /var/lib/warpper/warpper.db
    log_level = info

    [proxy]
    listen_host = 127.0.0.1
    listen_port = 15353
    ca_cert_path = /var/lib/warpper/certs
    cache_size = 4096
    cache_max_ttl = 300

    [firewall]
    nft_family = inet
    nft_table = warpper
    block_set = blocked_ips

After editing: `sudo systemctl restart warpperd`. Delete the file to
reset to defaults.

## Blocklists

To enable the daily updater:

    sudo systemctl enable --now warpperd-update.timer

Comes with categories: `ads`, `malware`, `trackers`, `social`. Updates are
transactional, a mid-update failure rolls back, so you don't end up
with a half-populated list.

    sudo warpperctl update
    sudo warpperctl categories list
    sudo warpperctl categories disable ads

## Troubleshooting

**All websites slow or broken after enabling the firewall.**
Usually the daemon looping its own upstream queries. Check for stray
nftables tables:

    sudo nft list tables

Anything other than `inet warpper` redirecting port 53 needs to be removed to avoid conflicts.

**Block doesn't take effect in a browser.**
Browsers cache DNS for 60+ seconds and keep HTTP/2 connections open.
New tab picks up the block immediately while existing ones need the
connection dropped. Enable IP-level blocking for global DNS filtering:

    sudo warpperctl firewall enable

**Port 53 already in use.**
Usually `systemd-resolved` on `127.0.0.53:53`. Move the daemon to a
higher port (default 15353) or just disable the stub:

    sudo mkdir -p /etc/systemd/resolved.conf.d
    echo -e '[Resolve]\nDNSStubListener=no' | \
        sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
    sudo systemctl restart systemd-resolved

**"daemon not running".**

    sudo systemctl status warpperd
    sudo journalctl -u warpperd -n 30

**Blocked domain still loads.**
DNS-based blocking only catches clients that use your resolver.
Enable the firewall redirect to intercept clients with hardcoded
resolvers or DoH:

    sudo warpperctl firewall enable

Also check the domain isn't whitelisted: `sudo warpperctl list`.

## File locations

    /etc/warpper/warpper.conf              config
    /var/lib/warpper/warpper.db            SQLite: rules, logs
    /var/lib/warpper/certs/                CA for the future proxy layer
    /run/warpper/warpperd.sock             IPC socket, root-owned
    /usr/lib/systemd/system/warpperd*.service
    /usr/bin/warpperd
    /usr/bin/warpperctl

## Uninstall

    sudo systemctl disable --now warpperd warpperd-update.timer
    sudo pacman -R warpper

`/etc/warpper/` and `/var/lib/warpper/` are left alone, your rules
and logs survive. Delete them manually for a clean slate:

    sudo rm -rf /etc/warpper /var/lib/warpper

## License

GNU AGPLv3. See LICENSE.
