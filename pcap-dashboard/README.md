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

## Security design
- Alpine base image, runs in a container with no extra packages installed.
- Python standard library only: no third-party packages, no shell, no database, no `eval`.
- Uploads are parsed in memory, never saved; size-capped (`MAX_UPLOAD_MB`), 100k-packet cap, 4 sessions, 30-minute expiry, random 192-bit session IDs.
- Strict CSP (no inline script/style, no external resources), `nosniff`, no-store, and all UI text rendered with `textContent` (no HTML injection).
- Query parser is rule-based; user input never becomes code or regex.

## Notes
- Meant for local/analyst use. To expose it beyond localhost, put it behind a TLS reverse proxy with authentication.
- Dissects Ethernet/VLAN, Linux cooked, raw IP, IPv4/IPv6, TCP, UDP, ICMP, ARP, plus DNS/HTTP/TLS detection. Natural-language IP matching is IPv4 (IPv6 works via quoted text).
- Layout: `app/pcap.py` (parser), `app/nlq.py` (query engine), `app/server.py` (API), `app/static/` (UI).
