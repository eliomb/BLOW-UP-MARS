# Wirelight – PCAP analysis dashboard

Upload a `.pcap` / `.pcapng` file, see complete-capture summary stats, and filter packets with a simple search field, protocol/port selectors or optional plain-English queries.

## Run
```bash
docker compose up --build
# open http://localhost:8080 (or http://<your-Docker-host-LAN-IP>:8080 if enabled)
```
Stop with `docker compose down`. Or without Compose:
```bash
docker build -t wirelight .
docker run --rm -p 8080:8080 -v wirelight-data:/data wirelight
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

The search field accepts ordinary IP addresses, ports (`443`), `src:IP`, `dst:IP`, quoted text, and the legacy plain-English queries above. Use the separate protocol and port filters, type to filter automatically (450 ms debounce), or Clear to reset. Terms are combined with AND; the chips show how a plain-English query was interpreted. Only 100 results render at once, so the page stays responsive even with large captures. Click a protocol, host, or packet to drill down.

## Remote live capture (over SSH)
1. **Remote capture** tab → **Generate key** (ed25519). Copy the shown `echo '…' >> ~/.ssh/authorized_keys` command and run it on the server as the SSH user.
2. Enter user/host/port → **Verify host key**, compare the fingerprint with the server's, then **Trust this host**. Connections use strict host-key checking against that list.
3. **Load interfaces**, pick one, optionally add a capture filter (BPF, e.g. `host 10.0.0.5`), and **Start capture**. `tcpdump` runs remotely and streams the pcap back over SSH; the dashboard updates every 2 s and all natural-language filters work on the live data. Your own SSH port is excluded automatically.

Remote requirements: Linux with `tcpdump`, and either an SSH user that is root, **or** passwordless sudo for tcpdump (tick the box), e.g. in `/etc/sudoers.d/wirelight`:
`youruser ALL=(root) NOPASSWD: /usr/bin/tcpdump`, **or** `setcap cap_net_raw,cap_net_admin=eip $(which tcpdump)`.
Captures stop after the time limit (default 300 s, max 3600), after reaching the configured raw download byte budget (`MAX_REMOTE_CAPTURE_MB`, default 128 MB), on Stop, or when the session expires. There is no longer a 100,000-packet cutoff.

## Security design
- Container: Alpine, non-root UID 10001, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, noexec tmpfs, CPU/memory/PID limits. Port binding is controlled by `WIRELIGHT_BIND_IP` (default 127.0.0.1; this configured LAN package sets `0.0.0.0`). Only `openssh-client` is added; pip is removed.
- Keys live only in the `wirelight-data` volume (`/data/keys`, dir 0700, files 0600). No API returns a private key; nothing is logged (HTTP logging is disabled, SSH `LogLevel=ERROR`, error text is truncated). Key generation happens in a throwaway tmpfs dir that is deleted immediately. Keys are unencrypted (needed for unattended capture) so protect the Docker volume/host. Delete a key from the UI (or `docker compose down -v` to wipe everything).
- SSH: argv lists only (no local shell), `BatchMode`, key-only auth, `StrictHostKeyChecking=yes` with a private known_hosts, no agent/port forwarding. Remote arguments are allow-listed and shell-quoted; the remote command is fixed to `ls /sys/class/net` or `tcpdump -w -`.
- The Host allowlist (`ALLOWED_HOSTS`) has been removed by request. An Origin check and `X-Requested-With: wirelight` requirement remain for API requests, but **neither replaces authentication nor guarantees protection against DNS rebinding**. LAN users can reach the AI and SSH-control endpoints: **restrict access with your firewall**, and add TLS + authentication before exposing it beyond a trusted local network.
- Uploads/captures are indexed in temporary SQLite files under `/data/captures`, not held entirely in memory. Session limit (4), concurrent live-capture limit (2), upload/download byte limits and per-capture disk budgets apply. Sessions expire after 30 minutes of inactivity; indexes are cleaned up when sessions are evicted and on service restart. Saved network maps and SSH keys are stored separately and never deleted by this cleanup. Captured packet data is sensitive and remains in plaintext on disk while sessions are active. Use volume encryption and protect the Docker host. Strict CSP and text rendering protect the UI; all database queries are parameterized.
- Python standard library only.

## Layout
`app/pcap.py` parser · `app/nlq.py` query engine · `app/ssh.py` keys + remote capture · `app/server.py` API · `app/static/` UI.

## Ask AI about your capture (Mistral cloud or local LM Studio)

**PCAP loading and live packet capture never invoke an AI model on their own.** The dashboard is completely functional with AI disabled. After loading a capture, ask a question in the chat, ask follow-ups, or explicitly choose **Generate AI report**. Optional reports include normal activity, suspicious/anomalous behavior, potential attacks and possible vulnerabilities, evidence, limitations and next steps; export as JSON or Markdown. Conclusions are hypotheses, not confirmed incidents.

### Mistral AI hosted (default)

**Important: Hosted access is not guaranteed free.** Mistral's current [Usage and limits docs](https://docs.mistral.ai/admin/billing-usage/usage-limits) state that **Free mode does not include API access** and enabling API keys requires billing activation/pay-as-you-go. Older articles about an Experiment API free tier may be out of date. Check your own Mistral Studio account's API eligibility, pricing and billing settings before using the hosted provider. For a truly no-API-fee option, see **Local LM Studio** below.

1. Check your Mistral Studio API access; generate a key under **API Keys** if your account permits it: https://console.mistral.ai/ . Do **not** put the key in webpage JavaScript or send it to anyone.
2. Copy `.env.example` to `.env` next to `docker-compose.yml`, and set:

   ```dotenv
   AI_ENABLED=true
   AI_PROVIDER=mistral
   MISTRAL_API_KEY=your-own-private-key
   MISTRAL_MODEL=ministral-8b-latest
   MISTRAL_TIMEOUT=120
   ```

   The selected `ministral-8b-latest` is a lightweight starting model, **not a promise of free access**. You can change `MISTRAL_MODEL` to one available to your account in Mistral Studio; e.g. `mistral-small-latest` (which may have higher charges). Hosted traffic goes to Mistral's fixed HTTPS endpoint `https://api.mistral.ai/v1/chat/completions` and the key stays in the backend. Model availability and rate limits depend on your plan.
3. Start/recreate Wirelight: `docker compose up -d --build --force-recreate`. The AI panel identifies the active provider, model, and whether an API key is configured. If the key is missing, the chat and report controls are disabled with an explanation. If the backend reports HTTP **401/403**, check key and billing; HTTP **429** means quota or rate limit (or that your account has no allowance for that model); HTTP **400/404/422** may mean the model is unavailable to your account.

### Local LM Studio (no cloud API charges)

1. Install or keep LM Studio and download a small **Mistral-family instruct model** that your computer can run quickly (for example, a quantized Ministral model compatible with LM Studio). Start its OpenAI-compatible server.
2. In `.env` switch provider and configure the actual model ID/host:

   ```dotenv
   AI_ENABLED=true
   AI_PROVIDER=lmstudio
   LM_STUDIO_HOST=host.docker.internal
   LM_STUDIO_PORT=1234
   LM_STUDIO_SCHEME=http
   LM_STUDIO_MODEL=your-loaded-model-identifier
   LM_STUDIO_TIMEOUT=240
   ```

3. Recreate the container: `docker compose up -d --force-recreate`. On Linux Docker Engine, `host.docker.internal` maps to the host gateway; when connecting to a separate machine, enter its IP or DNS name. The server must listen on an address accessible to the container. Configure firewall and access controls accordingly. This option has no Mistral-hosted API usage charges, but generation speed still depends on your hardware.

**Privacy and evidence:** AI only runs after you click **Ask AI** or **Generate AI report**. Unlike the earlier metadata-only version, both actions automatically send correlated traffic evidence (source/destination flow counts, SYN/RST/ACK behavior, tentative traffic-pattern observations, infrastructure clues, traffic spikes, common DNS query names and HTTP status summaries) **plus representative decoded packet samples containing readable plaintext payload excerpts**. Even an ordinary chat question can therefore transmit HTTP requests, DNS names, tokens, credentials or other sensitive captured content to the configured provider. This is deliberately enabled for investigative testing and is not suitable for confidential captures unless you are authorized to send them to that provider. The raw PCAP file itself is not uploaded to the model. The sample budget is configurable below; the AI does **not** view every full packet, and a token limit prevents dumping arbitrary PCAPs into one request. Selected packets add extra header detail and up to 1,600 characters of readable data. For wholly private investigation use `AI_PROVIDER=lmstudio` when ready, and secure the LAN endpoint.

### AI evidence depth / speed

Set these in `.env` and recreate the container. Defaults aim for representative network-traffic coverage without overwhelming smaller models:

```env
AI_CONTEXT_CHARS=55000
AI_PACKET_SAMPLES=72
AI_PAYLOAD_CHARS=400
```

`AI_CONTEXT_CHARS` limits the JSON evidence sent in each request (12,000–150,000 characters). `AI_PACKET_SAMPLES` limits packet examples (8–160), chosen from packet-pattern observations, question-specific hosts, TCP flag patterns, protocols and across the capture timeline. `AI_PAYLOAD_CHARS` limits each sampled packet's readable payload excerpt (0–1,600). **On large captures, AI behavioral summaries use a bounded capture-wide metadata sample; complete-capture totals are supplied separately.** Larger settings can improve coverage, but can also increase latency, token charges and model confusion; more text isn't automatically more accurate. For a lightweight hosted 8B model, first test the defaults against known attack PCAPs before raising limits. Every uploaded packet is indexed, but detailed AI evidence is sampled, and individual uploaded frames keep at most the first **1,600 bytes** for inspection; a larger AI context setting cannot recover missing payload bytes. No stream reassembly, automated TLS decryption, or host-level intrusion verification is provided.


**Neutral analysis and infrastructure context:** Report generation and chat now begin with ordinary network behavior and infrastructure relationships instead of assuming an incident. High packet counts, SYN bursts, TCP resets, authentication errors, and scanner-like patterns remain observable facts, but are **not automatically called attacks**. Packet-level heuristics are leads to interpret in context, not verified security findings. A proxy often appears as the source of backend connections, and a Docker gateway can resemble another host; neither identity is provable from a private IP alone.

If you know your topology, you can supply accurate roles through `.env` (also passed into Docker by `docker-compose.yml`):

```dotenv
AI_DOCKER_NETWORKS=172.17.0.0/16,172.18.0.0/16
AI_REVERSE_PROXY_IPS=10.0.12.15
AI_NETWORK_NOTES=10.0.12.15 is Traefik; it sends traffic to application containers on the listed Docker networks
```

Replace these **examples** with your real subnets/proxy IPs. `AI_DOCKER_NETWORKS` means *addresses within a container network*, **not** that every IP is necessarily a container. `AI_REVERSE_PROXY_IPS` designates known reverse proxies. `AI_NETWORK_NOTES` is optional topology context (up to 1,000 characters); don't put passwords or API keys here. For unknown networks, Wirelight only offers *low-confidence* clues such as a 172.17/16 address or a Docker-style `02:42` source MAC. Unencrypted `Forwarded`, `X-Forwarded-For`, `X-Real-IP` and `Via` HTTP request headers can indicate a proxy hop; multi-hop web traffic can also offer a weaker topology clue. Clients can forge forwarding headers, and TLS/split headers remain invisible without decryption or reassembly. The model should describe these as clues rather than certified identities.

**Security and implementation:** API keys stay in `.env` and the backend container, never in API responses or frontend JavaScript; `.env` is excluded from the Docker build context and ignored by Git. Cloud requests have a fixed HTTPS endpoint (TLS certificate verified, redirects refused) and do not use ambient HTTP proxies. Request and response sizes are bounded. Model Markdown is rendered using an allowlisted, sanitized DOM builder (not unsanitized HTML). Session chat and AI reports are kept in memory only and expire with the capture session. AI endpoints have `X-Requested-With: wirelight` protection; only one AI request per capture runs at a time. Response timeout defaults to 120 seconds in cloud mode, 240 locally, configurable up to 900 seconds. The app uses only Python standard-library HTTP clients, no Mistral SDK dependency.

**API:** `GET /api/ai/config` returns safe display settings (never API keys); `POST /api/ai/ask` with `{"id":"<session-id>","question":"..."}` returns an answer, packet count and evidence sample counts; `GET /api/ai/chat?id=...` returns in-session chat; `POST /api/ai/analyze` generates the optional report; `GET /api/ai/report?id=...` retrieves it. `AI_ENABLED=false` disables all model requests. Tests are runnable offline with `python -m unittest discover -s tests -v`.

### AI chat Markdown formatting

Mistral and LM Studio chat replies are rendered as Markdown in the browser (headings,
numbered/bulleted lists, **bold**, inline and fenced code, links and tables). The
Markdown parser is bundled locally, and its output is reconstructed using a
restricted HTML element allowlist to avoid executing model-generated HTML.
No CDN or internet connection is needed to load the formatter.

If upgrading an existing Wirelight installation, **keep your existing `.env`**
and replace the application files. The example configuration does not include
credentials. Rebuild with `docker compose up -d --build --force-recreate`.


## Packet inspection, large uploads and remote export

- **Uploads:** `.pcap` and `.pcapng` are parsed incrementally and written to a disk-backed SQLite index (`/data/captures`, in the existing Docker volume). Default maximum upload is `MAX_UPLOAD_MB=256`; storage cap per capture index is `MAX_CAPTURE_STORE_MB=768` MiB. To accept larger uploads, adjust both settings and ensure enough free disk space. **All packets are indexed**, including those after 100,000; the UI displays only one page of 100 packets. Search uses indexed SQL filters where possible. Uploads retain up to 1,600 bytes per packet for detail inspection; remote capture stores complete frame bytes for PCAP download until its configured byte budget. Temporary indexes expire with sessions and are deleted on app restart; saved network maps/SSH data are untouched.
- **Packet detail:** Click a row to view Ethernet/IP/TCP/UDP/ICMP headers, a readable ASCII payload excerpt, and hex+ASCII bytes. Uploaded packets store the first 1,600 captured bytes for browsing; this is not full Wireshark stream reconstruction or decryption.
- **Ask AI about a packet:** Open its detail drawer and click **Use packet in AI question**. Nothing is sent to the model until you click **Ask AI**. The selected packet's decoded headers, up to 1,600 characters of readable payload and a short hex prefix are included **in addition to** the automatic representative packet samples. **Cloud users:** both automatically sampled and manually attached text can contain passwords, tokens, or private network content; removing an attachment does not disable automatic payload samples. Set `AI_PAYLOAD_CHARS=0` to disable automatic payload excerpts (names/URIs may still appear in parsed metadata).
- **Remote capture download:** **Download remote PCAP** exports a classic `.pcap` file containing complete captured frames. You can download while capture is in progress (snapshot) or after it finishes. A remote capture is capped at `MAX_REMOTE_CAPTURE_MB=128` MiB to bound container RAM usage; captured frames within that limit are not truncated.
- **SSH:** Hostname and username are remembered in your browser's localStorage (not in server files). This does not store a password or private key.
- **Report JSON:** When using hosted Mistral, the report generator requests JSON mode. It also tolerates unescaped line breaks inside model strings. If a model still outputs unusable JSON, the page shows an explicitly labeled unstructured fallback instead of a 400/502 error.
- **Operational note:** Large captures are indexed on the disk-backed Docker volume, not held entirely in application RAM. Downloading remote PCAP snapshots can still consume browser RAM (remote captures are limited by `MAX_REMOTE_CAPTURE_MB`). Restrict access through Docker/firewall, especially since the app has no login or HTTP Host allowlist.

## Persistent Network Mapping (manual Nmap scans)

Wirelight now has a **Network maps** button in its header. You can save a named
RFC1918 IPv4 subnet, trigger an Nmap scan when you choose, inspect open ports and
service hints, and manually label hosts (LXC container, Docker host/container,
reverse proxy, router, etc.). The data and operator labels are saved to
`/data/network-maps.json` in the existing persistent `wirelight-data` Docker
volume. `docker compose down` and rebuilds preserve this volume; **do not run
`docker compose down -v`** unless you intend to delete the maps and SSH keys.

1. Open **Network maps**, enter a name and CIDR such as `10.0.1.0/24`, and
   click **Save map**. This creates the inventory without starting a scan.
2. Click **Scan / Rescan** to run Nmap and replace only that map's latest
   observed scan results. No scanning happens automatically, including when you
   upload a PCAP. Network scans run asynchronously and the status is polled.
3. Use **Save label** on individual discovered hosts, or **Add a known host** to
   enter an IP and role that Nmap couldn't reach. Labels survive rescans.
4. Open a PCAP, then check one or more inventories (maximum four) in **Network
   inventory context for AI**. Both **Ask AI** and **Generate AI report** use
   only the maps you've explicitly checked. Uncheck them for PCAP-only analysis.

The Docker image includes Alpine's `nmap`, `nmap-nselibs` and `nmap-scripts`
packages. Both NSE data packages are needed for `-sV` service detection. The
Docker build verifies that `nse_main.lua` and `script.db` exist and tests script
loading. If an earlier image reports **could not locate nse_main.lua**, rebuild
with `docker compose up -d --build --force-recreate`. Your maps remain in the
persistent volume; **do not** use `docker compose down -v`.

Choose one of two **manual** scan modes before clicking **Scan / Rescan**:

- **Quick (default):** unprivileged `-sT -sV --version-light --top-ports 40`,
  normal host discovery, up to 8 minutes. Optionally enable **Skip host discovery
  (-Pn)** for computers that don't reply to discovery probes.
- **Aggressive:** automatically enables `-Pn` (every address is probed, even if
  the host blocks ping), unprivileged TCP connect scanning over approximately
  1,050 ports including 135/139/445 (RPC/SMB), 3389 (RDP), and 5985/5986
  (WinRM). It uses stronger service detection and *safe* Nmap NSE discovery
  scripts (`smb-os-discovery` and `rdp-ntlm-info`) to collect Windows-related
  clues, if the services respond. Timeout up to **30 minutes**, per-host
  deadline 90 seconds, max one scan at a time; CPU/network load is bounded.
  It does **not** scan every one of 65,535 TCP ports or attempt login/exploit.

With `-Pn`, Nmap assumes addresses are up. Wirelight excludes assumed-up hosts
that show no TCP or link-layer response, so offline/filtered IPs aren't saved as
positive discoveries. A fully firewalled host may still be missed. Some service
clues suggest Windows, but are **not proof** of the host OS. Raw-socket OS
fingerprinting (`-O` / full Nmap `-A`) isn't enabled because the container runs
unprivileged with Linux capabilities dropped.

To limit resource use and unintended scans: **one active scan at a time**,
**at most 256 addresses per scan**, private IPv4 RFC1918 targets only, and up
to 25 saved maps. A failed or timed-out scan leaves the previous successful
result and operator labels untouched. Only scan networks you own or are
permitted to test. Nmap sends real packets to the target network; it may be
visible to monitoring/IDS systems and may not work through restrictive firewalls.

**Crucial scope limitation:** Nmap runs *inside the Wirelight Docker container*.
It discovers reachable addresses from that network vantage point, so it may not
reach Docker bridges inside a separate LXC guest without routing/firewall
changes. A missing host is **not** evidence of an absent container or service.
Nmap cannot reliably identify Docker/LXC/reverse-proxy roles from open ports;
manual labels and map notes are supplied by you and identified as such to the
AI. Nmap results may also be older than the capture being inspected.

**Security:** The Wirelight UI does not provide user authentication. Anybody
who can access its LAN-exposed API can create/delete saved maps and trigger
bounded scans. Restrict port 8080 to trusted clients with your firewall or
reverse-proxy authentication, especially when remote captures and AI API
credentials are configured. No Nmap arguments are built with a shell; subnets
are validated before invoking Nmap. Nmap inventory names, service banners, and
notes are passed to the AI only when you select the map and are treated as
untrusted data.

### Performance and AI on large captures

Packet search uses a disk-backed SQLite index with only a single page returned per request. The dashboard summary counts **every imported packet**. There is **no packet-count truncation**; maximum file size and per-session disk usage are still bounded. Expect storage overhead for metadata and indexes above the original PCAP file size. A very large substring search can still take longer than an indexed host/port/protocol query.

AI reports and chat do not send or read millions of packet contents into a single prompt. For large captures they use a bounded, **capture-wide sample (up to approximately 25,000 decoded packets)** plus full-capture summary counts and additional recent/host-matched examples. The AI receives `context_scope` describing the sample and must not treat sampled behavior as a proven full-capture count. You can explicitly attach any packet number, including after 100,000, to an AI question. Evidence in unsampled packets may still be missed; use filters to narrow investigations.

**Storage:** Capture indexes are temporary and stored under `/data/captures`. Saved network inventories and SSH keys continue to persist in `/data` in their own paths. Never use `docker compose down -v` unless you want to remove those permanent records. If the upload fails due to disk limits, raise `MAX_CAPTURE_STORE_MB` or `MAX_UPLOAD_MB` and make sure the Docker volume has sufficient capacity.
