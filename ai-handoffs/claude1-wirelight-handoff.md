# Wirelight: project handoff

Last updated: 2026-11-06. Use this file to continue the project in a new chat. Attach it together with `wirelight-pcap-dashboard.zip` (the full source) and say what you want to change.

## What it is
A local web dashboard for analysing packet captures, run in Docker (Alpine).
- Upload a `.pcap` / `.pcapng` file, or capture live from a remote Linux host over SSH.
- Summary cards, a packets-over-time chart, a protocol breakdown and top talkers.
- Search and filter packets in plain English.
- Click a packet for a detail drawer with a hex dump.

**Status:** everything above works. The user ran it in Docker and confirmed live capture and the data display after the fixes below. The development sandbox had no Docker and no ssh binaries, so SSH key generation and host-key scanning were never run in the sandbox. The live pipeline was tested with stubbed `ssh` and a fake `tcpdump`.

## Layout
```
Dockerfile, docker-compose.yml, .dockerignore, README.md
app/
  server.py      HTTP server and JSON API (stdlib ThreadingHTTPServer), sessions, security headers
  pcap.py        pcap/pcapng reader, incremental Stream reader, packet dissector, hexdump
  nlq.py         plain-English query parser -> (predicate, chips, limit)
  ssh.py         SSH key management, host-key trust, remote tcpdump streaming
  static/        index.html, app.css, app.js (no inline script or style, CSP-safe)
```
Python standard library only. No frameworks and no build step.

## Run
`docker compose up --build`, then open http://localhost:8080. Compose publishes on `127.0.0.1:8080` only.

## Packet model (`pcap.dissect`)
Each packet is a dict: `n, ts, len, src, dst, sport, dport, tr` (transport), `proto` (app-level label), `flags` (TCP letters FSRPAU), `info`, `txt` (lowercased printable payload, first 512 bytes).
- **Link types handled:** Ethernet (1, with VLAN), Linux cooked v1 (113), Linux cooked v2 (276), raw IP (12, 14, 101, 228, 229), null/loopback (0). Anything else gets `Unsupported link type N` in Info.
- **Network and transport:** IPv4, IPv6 (extension headers skipped), ARP, TCP, UDP, ICMP, ICMPv6.
- **App detection:** DNS (UDP port 53 or 5353), HTTP (request or response line), TLS (record header only, no SNI).
- **Memory:** raw bytes are kept per packet, truncated to 1600 (`SNAP`). The cap is 100,000 packets (`MAXPKT`).

## Natural-language queries (`nlq.py`)
Rule-based and sequential, using regexes on a lowercased copy of the query. User input never becomes code or regex. Terms combine with AND.
- **Supported:**
  - Protocols and `not X`.
  - `from/to/between IP` (IPv4 and CIDR) and ports (`port N`, `from port`, `to port`).
  - Service names (ssh, rdp, smb, and so on).
  - Size filters (`larger than N bytes/kb`).
  - TCP flags (syn, syn-ack, rst, fin).
  - `first/last N`.
  - Quoted text, and leftover words as keyword search over payload, info and addresses.
- **Output:** the server returns "chips" describing how the query was interpreted, and the UI shows them.
- **Not supported yet:** IPv6 addresses (quoted text works), time ranges, OR across different filter types.

## API (all `/api/*` need header `X-Requested-With: wirelight`)
| Method and path | Purpose |
|---|---|
| POST `/api/upload` | raw body, returns `{id, stats}` |
| GET `/api/packets?id&q&offset&limit` | filtered page, returns `{total, filters, rows}` |
| GET `/api/packet?id&n` | one packet plus hex dump |
| GET `/api/keys` | list keys (name, public key, fingerprint) |
| POST `/api/keys`, `/api/keys/delete` | generate or delete a key |
| POST `/api/ssh/hostkey` | ssh-keyscan, returns fingerprints and a pending token |
| POST `/api/ssh/trust`, `/api/ssh/forget` | add or remove a known_hosts entry |
| POST `/api/ssh/interfaces` | `ls /sys/class/net` on the remote host |
| POST `/api/live/start`, `/api/live/stop` | start or stop a capture |
| GET `/api/live/status?id` | `{running, error, stats}`, polled every 2 s by the UI |

Sessions are in memory only: max 4, 30-minute TTL, 192-bit random ids, and at most 2 live captures.

## Remote live capture
1. Generate an ed25519 key. The UI shows an `echo '<pubkey>' >> ~/.ssh/authorized_keys` command to run on the server.
2. Verify the host key (fingerprint shown), then trust it. The UI also does this automatically when a connect fails on an unknown host.
3. Load the remote interfaces, then start. The server runs `ssh ... sh -c WRAP sh [sudo -n] tcpdump -i IFACE -U -n -s 0 -w - '(FILTER) and not port SSHPORT'`.
4. `_pump` in `ssh.py` reads the stdout stream through `pcap.Stream`, dissects the packets and appends them to the session. The UI polls for updates.
5. A capture ends on Stop, at the time limit (default 300 s, max 3600 s), at 100,000 packets, or if the remote process ends early. An early end sets `error` to `capture ended early (exit N): <stderr tail>`.

**Remote wrapper (`ssh.WRAP`):**
```
exec 3<&0; "$@" </dev/null 3<&- & p=$!; { cat <&3; kill $p; } >/dev/null 2>&1 & w=$!; exec 3<&-; wait $p; r=$?; kill $w 2>/dev/null; exit $r
```
It keeps the SSH stdin open and kills tcpdump when that stdin closes, so no orphan tcpdump is left on a quiet interface. It exits with tcpdump's status as soon as tcpdump exits.

## Security design
- **Container:**
  - Alpine, `openssh-client-default` only, pip removed.
  - UID/GID 10001.
  - Read-only root filesystem.
  - `cap_drop: ALL`, `no-new-privileges`.
  - noexec tmpfs on `/tmp`.
  - Memory, PID and CPU limits.
  - Code is root-owned and read-only.
- **Keys and trust:**
  - Keys live in the named volume `wirelight-data` at `/data/keys` (dir 0700, files 0600). `/data/known_hosts` is in the same volume.
  - No API returns a private key, and nothing is logged.
  - Keys have no passphrase, which is needed for unattended capture, so protect the volume.
  - Key generation uses a throwaway tmpfs directory that is deleted immediately.
- **SSH:**
  - Argv lists only, never a local shell.
  - `BatchMode`, key-only auth, `StrictHostKeyChecking=yes` against the private known_hosts.
  - No agent or port forwarding.
  - Remote arguments are allow-listed by regex and `shlex.quote`d.
  - The remote command is fixed to either `ls /sys/class/net` or `tcpdump -w -`.
- **API:**
  - Host header allow-list (`ALLOWED_HOSTS`, default `localhost,127.0.0.1,[::1]`).
  - Origin check.
  - Required custom header (CSRF and DNS rebinding protection).
  - Strict CSP and `nosniff`.
  - The UI uses `textContent` only.
- **Environment variables:** `MAX_UPLOAD_MB` (default 64), `ALLOWED_HOSTS`, `DATA_DIR` (default `/data`).

## Bugs already fixed (do not reintroduce)
1. **Compose image pull error:** a compose file with both `build:` and `image: wirelight:latest` tried to pull from a registry. Use `build:` only.
2. **Typing blocked in inputs:** a `document.onkeydown = e => cond && ...` handler returns `false` for other keys, which cancels the keypress. Use `addEventListener` and never return a value.
3. **Capture ended after 1 s:**
   - `ssh` was started with stdin closed (`DEVNULL`). Now it uses `PIPE` and stays open.
   - A POSIX shell redirects a background job's stdin to `/dev/null`, so `cat <&0` inside `&` sees EOF at once. Fix: save stdin on fd 3 first (see `WRAP`).
4. **Blank Source/Destination/Info:** `tcpdump -i any` on current libpcap writes link type 276 (Linux cooked v2), which was unhandled. It is now handled.
5. **Lost errors on early exit:** `p.poll()` straight after EOF can return `None`. Now it does `p.wait(timeout=3)` first and reads stderr non-blockingly.

## Testing approach used (no Docker or ssh in the sandbox)
- Synthetic pcaps built with `struct` for each link type.
- Live pipeline tested by monkeypatching `ssh.cmd` to run `['sh','-c', remote]` with a fake `tcpdump` script on `ssh.ENV['PATH']`.
- The wrapper was tested with both `dash` and `bash`, with stdin open and closed, and checked for orphan processes.

## Known limitations and ideas
- No TLS SNI, HTTP header parsing, TCP stream reassembly or follow-stream view.
- No pcap export or download of a live capture.
- No saved connection profiles. Only keys and trusted hosts persist.
- No IPv6 in plain-English queries and no time-range queries.
- The table is paged (100 rows) and polled. There is no virtual scrolling or live push.
- The server is `http.server`, which is fine for local use. Put TLS and authentication in front before exposing it beyond localhost.
- Some ideas: conversation view, per-packet protocol tree, export filtered packets to pcap, a "capture to file on remote, then fetch" mode, an optional passphrase for keys.

## Conventions for further work
- Keep it stdlib-only and Alpine-friendly.
- Keep the JS in external files (CSP forbids inline).
- Validate every input that reaches `ssh`, and always pass local commands as lists.
- Run the container with the hardening flags in `docker-compose.yml`.
