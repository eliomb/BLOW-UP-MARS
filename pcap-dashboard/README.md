# Wirelight – PCAP analysis dashboard

Upload a `.pcap` / `.pcapng` file, see summary stats, and filter packets with plain English.

## Run
```bash
docker compose up --build
# open http://localhost:8080 (or http://<your-Docker-host-LAN-IP>:8080 if enabled)
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
- Container: Alpine, non-root UID 10001, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, noexec tmpfs, CPU/memory/PID limits. Port binding is controlled by `WIRELIGHT_BIND_IP` (default 127.0.0.1; this configured LAN package sets `0.0.0.0`). Only `openssh-client` is added; pip is removed.
- Keys live only in the `wirelight-data` volume (`/data/keys`, dir 0700, files 0600). No API returns a private key; nothing is logged (HTTP logging is disabled, SSH `LogLevel=ERROR`, error text is truncated). Key generation happens in a throwaway tmpfs dir that is deleted immediately. Keys are unencrypted (needed for unattended capture) so protect the Docker volume/host. Delete a key from the UI (or `docker compose down -v` to wipe everything).
- SSH: argv lists only (no local shell), `BatchMode`, key-only auth, `StrictHostKeyChecking=yes` with a private known_hosts, no agent/port forwarding. Remote arguments are allow-listed and shell-quoted; the remote command is fixed to `ls /sys/class/net` or `tcpdump -w -`.
- The Host allowlist (`ALLOWED_HOSTS`) has been removed by request. An Origin check and `X-Requested-With: wirelight` requirement remain for API requests, but **neither replaces authentication nor guarantees protection against DNS rebinding**. LAN users can reach the AI and SSH-control endpoints: **restrict access with your firewall**, and add TLS + authentication before exposing it beyond a trusted local network.
- Uploads/captures are held in memory only; size, packet, session (4) and live-capture (2) caps; 30-minute expiry; strict CSP; UI renders text with `textContent`; the query parser never builds code or regexes from input.
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

**Privacy:** Wirelight sends data to the selected provider **only after a user asks a question or generates a report**. It sends aggregated traffic metadata: IP addresses, port numbers, protocol totals, counts, timestamps, scan indicators, and (for chat) the question plus up to six recent conversation messages. It **does not** send full PCAP bytes, packet payloads, HTTP URIs, DNS names or raw packet rows. **Cloud Mistral is a third party:** the transmitted IP addresses, timing, and questions may still be confidential. Mistral's [data-use policy](https://help.mistral.ai/en/articles/347617-do-you-use-my-user-data-to-train-your-artificial-intelligence-models) says Free mode requests may be used for training; review privacy settings and only upload authorized metadata. Use the local option for sensitive captures.

**Security and implementation:** API keys stay in `.env` and the backend container, never in API responses or frontend JavaScript; `.env` is excluded from the Docker build context and ignored by Git. Cloud requests have a fixed HTTPS endpoint (TLS certificate verified, redirects refused) and do not use ambient HTTP proxies. Request and response sizes are bounded. Model output is rendered with `textContent` (not HTML). Session chat and AI reports are kept in memory only and expire with the capture session. AI endpoints have `X-Requested-With: wirelight` protection; only one AI request per capture runs at a time. Response timeout defaults to 120 seconds in cloud mode, 240 locally, configurable up to 900 seconds. The app uses only Python standard-library HTTP clients, no Mistral SDK dependency.

**API:** `GET /api/ai/config` returns safe display settings (never API keys); `POST /api/ai/ask` with `{"id":"<session-id>","question":"..."}` returns `{"answer":"...","packet_count":123}`; `GET /api/ai/chat?id=...` returns in-session chat; `POST /api/ai/analyze` generates the optional report; `GET /api/ai/report?id=...` retrieves it. `AI_ENABLED=false` disables all model requests. Tests are runnable offline with `python -m unittest discover -s tests -v`.
