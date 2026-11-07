# Wirelight – PCAP analysis dashboard

Upload a `.pcap` / `.pcapng` file, see summary stats, and filter packets with plain English.

## Run
```bash
docker compose up --build
# open http://localhost:8080
```
Stop with `docker compose down`. Or without Compose:
```bash
docker build -t wirelight .
docker run --rm -p 8080:8080 wirelight
```
The image is built locally from `python:3.12-alpine` (the only thing pulled from the internet); nothing is pulled from a registry under the name `wirelight`.

## Plain-English queries
| Query | Meaning |
|---|---|
| `dns queries for example.com` | DNS packets mentioning example.com |
| `tcp syn to port 443` | SYN packets with destination port 443 |
| `http from 10.0.0.5` | HTTP sent by that host (CIDR like `10.0.0.0/24` works) |
| `between 10.0.0.5 and 8.8.8.8` | traffic in either direction |
| `larger than 1000 bytes`, `smaller than 1 kb` | size filters |
| `tcp resets`, `syn-ack`, `fin` | TCP flags |
| `not tls`, `except dns` | exclusions |
| `ssh`, `rdp`, `smb`, … | well-known service ports |
| `"password"` or `containing admin` | search payload text, info, addresses |
| `first 20 …`, `last 50 …` | limit results |

Terms are combined with AND. The chips under the search box show exactly how your query was interpreted. Click a protocol, host, or packet to drill down.

## Remote live capture (over SSH)
1. **Remote capture** tab → **Generate key** (ed25519). Copy the shown `echo '…' >> ~/.ssh/authorized_keys` command and run it on the server as the SSH user.
2. Enter user/host/port → **Verify host key**, compare the fingerprint with the server's, then **Trust this host**. Connections use strict host-key checking against that list.
3. **Load interfaces**, pick one, optionally add a capture filter (BPF, e.g. `host 10.0.0.5`), and **Start capture**. `tcpdump` runs remotely and streams the pcap back over SSH; the dashboard updates every 2 s and all natural-language filters work on the live data. Your own SSH port is excluded automatically.

Remote requirements: Linux with `tcpdump`, and either an SSH user that is root, **or** passwordless sudo for tcpdump (tick the box), e.g. in `/etc/sudoers.d/wirelight`:
`youruser ALL=(root) NOPASSWD: /usr/bin/tcpdump`, **or** `setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`.
Captures stop after the time limit (default 300 s, max 3600), at 100,000 packets, on Stop, or when the session expires.

## Security design
- Container: Alpine, non-root UID 10001, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, noexec tmpfs, CPU/memory/PID limits, published on 127.0.0.1 only. Only `openssh-client` is added; pip is removed.
- Keys live only in the `wirelight-data` volume (`/data/keys`, dir 0700, files 0600). No API returns a private key; nothing is logged (HTTP logging is disabled, SSH `LogLevel=ERROR`, error text is truncated). Key generation happens in a throwaway tmpfs dir that is deleted immediately. Keys are unencrypted (needed for unattended capture) so protect the Docker volume/host. Delete a key from the UI (or `docker compose down -v` to wipe everything).
- SSH: argv lists only (no local shell), `BatchMode`, key-only auth, `StrictHostKeyChecking=yes` with a private known_hosts, no agent/port forwarding. Remote arguments are allow-listed and shell-quoted; the remote command is fixed to `ls /sys/class/net` or `tcpdump -w -`.
- Control API is protected against CSRF and DNS rebinding: Host allow-list (`ALLOWED_HOSTS`, default localhost), Origin check, and a required custom header. Add your hostname to `ALLOWED_HOSTS` if you reach it by another name, and put TLS + auth in front before exposing it beyond localhost.
- Uploads/captures are held in memory only; size, packet, session (4) and live-capture (2) caps; 30-minute expiry; strict CSP; UI renders text with `textContent`; the query parser never builds code or regexes from input.
- Python standard library only.

## Layout
`app/pcap.py` parser · `app/nlq.py` query engine · `app/ssh.py` keys + remote capture · `app/server.py` API · `app/static/` UI.
