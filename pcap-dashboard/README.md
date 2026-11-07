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

## Ask AI about your capture (LM Studio)

Wirelight loads and analyzes your PCAP locally to populate the packet dashboard. **It does not contact LM Studio automatically**, either when uploading a capture or during live capture. Type a question into **Ask AI** to discuss that capture, including follow-up questions, or explicitly choose **Generate AI report** for a structured assessment. The optional report has categories for normal activity, suspicious/anomalous behavior, possible attacks and possible vulnerabilities, with evidence, confidence, limitations and next steps. Export the report as JSON or Markdown. If LM Studio is unavailable, the regular packet dashboard continues working.

1. Run LM Studio on a machine reachable by the **Docker container** (not necessarily by the browser). In LM Studio load an instruction-following model, start its OpenAI-compatible local server and note its exposed listening address and model identifier.
2. Configure the connection via a `.env` file next to `docker-compose.yml`:
   ```dotenv
   LM_STUDIO_HOST=host.docker.internal
   LM_STUDIO_PORT=1234
   LM_STUDIO_MODEL=your-loaded-model-identifier
   LM_STUDIO_SCHEME=http
   LM_STUDIO_TIMEOUT=240
   AI_ENABLED=true
   # LM_STUDIO_API_KEY=optional-bearer-token
   ```
   Then run `docker compose up --build`. On Linux Docker Engine, `host.docker.internal` is mapped to the Docker host gateway. If LM Studio is on a **different host**, specify its DNS hostname or IP. On Windows/macOS Docker Desktop, `host.docker.internal` resolves to the host. LM Studio must listen on an address accessible from Docker; binding only to `127.0.0.1` on the host may not suffice. Secure the connection and restrict LM Studio network access with host firewall or private networking. Set `LM_STUDIO_SCHEME=https` when using an HTTPS-terminating proxy with a trusted CA. The port is a number between 1 and 65535.
3. Open the dashboard; the AI panel displays the server-side configured endpoint, model and timeout. Upload a PCAP or start live capture. Ask a question such as **"Are there signs of scanning?"** or **"What traffic involves 10.0.0.5?"**. Follow up in the same chat, or click **Generate AI report** to create a formal assessment. The server's API key, if configured, is never returned to the browser.

**Timeout troubleshooting:** The older version used a hardcoded 35-second timeout; a large LM Studio model could receive the request but not respond before the dashboard displayed a misleading "Cannot reach LM Studio" error. The default is now 240 seconds (set `LM_STUDIO_TIMEOUT` between 10 and 900). If you still get HTTP 504, check the LM Studio server output for model loading / tokens per second and raise the timeout or use a smaller model. Connection errors and malformed model responses now return more specific HTTP 502 errors. Changes to `.env` require recreating the container with `docker compose up -d --build --force-recreate`.

**Privacy & trust boundary:** When you explicitly ask a question or generate a report, the LM Studio request contains aggregate counts, IP addresses, destination ports, timestamps, protocol labels, TCP flags totals and scan indicators. Questions also send your question text and up to six prior chat messages for conversational context. It **never sends full PCAP bytes, raw payloads, HTTP URLs or DNS query names**. Network IPs and timing can still be sensitive. Do not point the endpoint at a third-party service without authorization. The host/port is operator-configured through environment variables rather than arbitrary user-submitted URLs, limiting SSRF. Responses are size-bounded and added to the DOM using `textContent` (never interpreted as HTML); malformed responses produce a visible error. Questions and answers for follow-up context are kept only in the current in-memory session, with a bounded history. AI findings are **hypotheses**, not confirmed vulnerabilities or incident conclusions. The app does not do signature matching, CVE scans, TLS decryption or TCP stream reconstruction. The AI report is stored only in the existing ephemeral in-memory capture session and is exported locally in the browser. No AI dependencies are installed in Alpine.

**API:** `GET /api/ai/config` returns safe display configuration; `POST /api/ai/ask` accepts JSON `{"id":"<session-id>","question":"..."}` and returns `{"answer":"...","packet_count":123}`; `GET /api/ai/chat?id=...` returns the in-session conversation; `POST /api/ai/analyze` returns a structured report only if invoked; `GET /api/ai/report?id=...` returns the last report. All use the existing `X-Requested-With: wirelight` protection. Only one AI request per capture can be in flight. The model request times out after `LM_STUDIO_TIMEOUT` seconds (default 240) and its response is limited to 64 KiB. The model endpoint is fixed at `/v1/chat/completions`.

For a hackathon demo, a smaller local instruction-tuned model that reliably generates JSON is recommended. Models that wrap JSON in markdown fences are supported. If your LM Studio model has a different ID than the configured one, set `LM_STUDIO_MODEL` to that ID or any accepted alias. To disable AI, set `AI_ENABLED=false`.
