"""Conservative infrastructure hints for AI context.

Addresses and ports do not prove that a host is a Docker container or reverse
proxy. Explicit operator topology takes precedence over weak L2/L7 hints.
All labels are annotated with their provenance and uncertainty.
"""
import collections
import ipaddress
import os
import re

# Common *defaults*, not a definition of Docker's address space. Docker can use
# arbitrary subnets, and these RFC1918 ranges can be ordinary LANs as well.
COMMON_DOCKER_BRIDGE = ipaddress.ip_network('172.17.0.0/16')
HTTP_METHODS = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 3000, 5000, 9000}
PROXY_HEADERS = ('forwarded', 'x-forwarded-for', 'x-forwarded-host',
                 'x-forwarded-proto', 'x-real-ip', 'via')


def settings():
    """Load only operator-provided topology; reject invalid or oversized inputs."""
    network_str = os.environ.get('AI_DOCKER_NETWORKS', '').strip()
    proxy_str = os.environ.get('AI_REVERSE_PROXY_IPS', '').strip()
    notes = os.environ.get('AI_NETWORK_NOTES', '').strip()
    if len(network_str) > 1500 or len(proxy_str) > 1500 or len(notes) > 1000:
        raise ValueError('Infrastructure settings are too long')
    networks, proxies = [], []
    for x in filter(None, (s.strip() for s in network_str.split(','))):
        try:
            n = ipaddress.ip_network(x, strict=False)
        except ValueError:
            raise ValueError('AI_DOCKER_NETWORKS must contain comma-separated CIDRs') from None
        if n not in networks: networks.append(n)
    for x in filter(None, (s.strip() for s in proxy_str.split(','))):
        try: ip = ipaddress.ip_address(x)
        except ValueError: raise ValueError('AI_REVERSE_PROXY_IPS must contain IP addresses') from None
        if ip not in proxies: proxies.append(ip)
    if len(networks) > 24 or len(proxies) > 30:
        raise ValueError('Too many configured Docker networks or proxy IPs')
    return networks, set(proxies), notes


def _http_forwarding_headers(raw, link):
    """Find plaintext HTTP request headers, not arbitrary strings in other traffic.

    Packet-local only: split HTTP headers and TLS traffic cannot be inferred.
    Values are never trusted as the actual original source IP.
    """
    if not raw: return []
    # Skip packet framing using the common packet dissector, including VLANs,
    # raw IP links, and Linux cooked headers.
    import pcap
    decoded = pcap.packet_layers(raw[:4096], link)
    payload = decoded.get('payload_text', '')
    if not payload.startswith(HTTP_METHODS) or '\n' not in payload:
        return []
    # packet_layers() renders CR and LF as separate newlines. A normal HTTP
    # CRLF separator therefore appears as two newlines, and CRLFCRLF as four.
    # Do not mistake the first CRLF for the end of the header section.
    text = payload[:1800]
    if '\n\n\n\n' in text:
        header_text = text.split('\n\n\n\n', 1)[0].replace('\n\n', '\n')
    else:
        header_text = text.split('\n\n', 1)[0]
    lines = header_text.splitlines()[1:]
    found = set()
    for line in lines:
        if not line.strip(): break
        m = re.match(r'^([A-Za-z][A-Za-z0-9-]{0,50}):\s*', line)
        if m and m.group(1).lower() in PROXY_HEADERS:
            found.add(m.group(1).lower())
    return sorted(found)


def summarize(packets, frames):
    networks, known_proxies, notes = settings()
    src_counts = collections.Counter()
    dst_counts = collections.Counter()
    ethernet_macs = collections.defaultdict(collections.Counter)
    forwarding = collections.defaultdict(lambda: {'requests': 0, 'header_counts': collections.Counter(), 'upstreams': collections.Counter(), 'packet_numbers': []})
    web_clients = collections.defaultdict(set)
    web_upstreams = collections.defaultdict(set)
    # The row count is already limited by the PCAP dashboard. Avoid a per-packet
    # full L7 decode unless it contains the start of an HTTP request.
    for i, p in enumerate(packets):
        src, dst = p.get('src', ''), p.get('dst', '')
        if src: src_counts[src] += 1
        if dst: dst_counts[dst] += 1
        frame = frames[i] if i < len(frames) else b''
        if p.get('link', 1) == 1 and len(frame) >= 14 and src:
            mac = frame[6:12].hex(':')
            ethernet_macs[src][mac] += 1
        if p.get('tr') == 'TCP' and src and dst and src != dst and int(p.get('dport') or 0) in WEB_PORTS:
            web_clients[dst].add(src)
            web_upstreams[src].add(dst)
        if p.get('proto') != 'HTTP' or not src or not frame:
            continue
        row = forwarding[src]
        row['requests'] += 1
        # Work is not done for non-HTTP rows (which usually dominate captures).
        headers = _http_forwarding_headers(frame, p.get('link', 1))
        if headers:
            row['upstreams'][dst] += 1
            row['header_counts'].update(headers)
            if len(row['packet_numbers']) < 5:
                row['packet_numbers'].append(p.get('n', i) + 1)

    hosts = []
    # Prioritize active endpoints and observed HTTP forwarding. Never infer
    # "container" from one private IP: even a configured subnet has a host/gateway.
    ranked = (src_counts + dst_counts).most_common(32)
    for host, total in ranked:
        try: addr = ipaddress.ip_address(host)
        except ValueError: continue
        hints = []
        matching = [str(n) for n in networks if addr in n]
        if matching:
            hints.append({'role': 'address_on_operator_configured_docker_network',
                          'basis': 'operator_config', 'confidence': 'high_for_network_membership_not_container_identity',
                          'matching_networks': matching[:4]})
        if addr in known_proxies:
            hints.append({'role': 'operator_designated_reverse_proxy', 'basis': 'operator_config',
                          'confidence': 'operator_asserted_not_verified_from_pcap'})
        macs = ethernet_macs.get(host, {})
        docker_macs = [mac for mac, count in macs.items() if mac.lower().startswith('02:42:')]
        if docker_macs:
            hints.append({'role': 'docker_style_virtual_mac', 'basis': 'observed_ethernet_source_mac',
                          'confidence': 'suggestive_not_proof', 'mac_examples': docker_macs[:3]})
        # Default 172.17/16 is a clue, not an assertion. Other addresses in
        # 172.16/12 are too broadly used to label without another hint.
        if not matching and addr in COMMON_DOCKER_BRIDGE:
            hints.append({'role': 'address_in_common_docker_default_bridge_range',
                          'basis': 'address_range_only', 'confidence': 'low_not_proof'})
        # With TLS, forwarding headers are unavailable. Multi-hop topology is
        # still an extremely weak intermediary clue, not a proxy assertion.
        if len(web_clients[host]) >= 3 and len(web_upstreams[host]) >= 2:
            hints.append({'role': 'possible_web_intermediary_traffic_topology',
                          'basis': 'web_ports_multiple_inbound_clients_and_outbound_peers',
                          'confidence': 'low_can_also_be_an_ordinary_application_server',
                          'distinct_inbound_clients': len(web_clients[host]),
                          'distinct_outbound_web_peers': len(web_upstreams[host])})
        fwd = forwarding.get(host)
        if fwd and fwd['header_counts']:
            hints.append({'role': 'http_proxy_or_forwarder_candidate', 'basis': 'observed_http_forwarding_headers',
                          'confidence': 'suggestive_headers_can_be_client_supplied',
                          'headers': dict(fwd['header_counts'].most_common(6)),
                          'downstream_peers': len(fwd['upstreams']),
                          'packet_numbers': fwd['packet_numbers'][:5]})
        if hints:
            hosts.append({'ip': host, 'observed_packets': total, 'hints': hints})
    # Include explicitly declared proxies even if they are quiet in a capture,
    # but avoid claiming the packet capture independently identified them.
    observed = {h['ip'] for h in hosts}
    for addr in sorted(known_proxies, key=str):
        if str(addr) not in observed and len(hosts) < 48:
            hosts.append({'ip': str(addr), 'observed_packets': 0, 'hints': [
                {'role': 'operator_designated_reverse_proxy', 'basis': 'operator_config',
                 'confidence': 'operator_asserted_not_verified_from_pcap'}]})
    return {
        'operator_declared_docker_networks': [str(n) for n in networks],
        'operator_declared_reverse_proxy_ips': [str(a) for a in sorted(known_proxies, key=str)],
        'operator_network_notes': notes[:1000],
        'host_role_hints': hosts[:48],
        'interpretation': [
            'An RFC1918/private IP address alone cannot establish Docker, a container, proxy, or NAT.',
            'Docker can use any operator-selected subnet; default 172.17/16 is shared with ordinary private networks.',
            'A Docker network member may be a bridge gateway, host, or container; MAC 02:42 is only a clue.',
            'Forwarded HTTP headers suggest a proxy hop but may be injected by clients; encrypted or split headers are not inspected.',
            'Multi-hop web connectivity alone cannot distinguish a reverse proxy from an ordinary application or gateway.',
            'A reverse proxy can hide client IPs or use NAT; a capture on the upstream hop may show only proxy-to-backend traffic.',
            'Operator configuration is topology context, not proof of any security claim.'
        ]
    }
