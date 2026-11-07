"""Rule-based plain-English query parser. No eval, no regex built from user input."""
import re, ipaddress
SVC = {'ssh': 22, 'ftp': 21, 'smtp': 25, 'telnet': 23, 'rdp': 3389, 'smb': 445, 'ntp': 123, 'dhcp': 67, 'mysql': 3306, 'postgres': 5432}
PROTO = {'dns': 'DNS', 'http': 'HTTP', 'tls': 'TLS', 'ssl': 'TLS', 'https': 'TLS', 'tcp': 'TCP', 'udp': 'UDP',
         'icmp': 'ICMP', 'ping': 'ICMP', 'arp': 'ARP', 'icmpv6': 'ICMPv6'}
STOP = set("""show me all find get list give packets packet pkts traffic the a an of with that are is from to and or only any
which have has in on by for between port ports ip address addresses bytes byte than larger bigger smaller greater less more over
under above below containing contains contain including matching mentioning search look looking where what who whose sent
received connections connection requests request responses response data please can you i want see display filter queries query size length""".split())
IP = r'(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)'
PK = '|'.join(sorted(PROTO, key=len, reverse=True))

def _net(s):
    try: return ipaddress.ip_network(s, strict=False)
    except ValueError: return None
def _in(a, n):
    try: return ipaddress.ip_address(a) in n
    except ValueError: return False

def parse(q):
    s, fs, chips, lim = ' ' + q.lower()[:300] + ' ', [], [], None
    def eat(rx):
        nonlocal s
        ms = list(re.finditer(rx, s)); s = re.sub(rx, ' ', s); return ms
    def add(label, fn): chips.append(label); fs.append(fn)
    def txt(t): return lambda p: t in p['txt'] or t in p['info'].lower() or t in p['src'] or t in p['dst']

    for m in eat(r'"([^"]+)"|\'([^\']+)\''):
        t = m[1] or m[2]; add(f'text "{t}"', txt(t))
    for m in eat(r'between\s+' + IP + r'\s+and\s+' + IP):
        a, b = _net(m[1]), _net(m[2])
        if a and b: add(f'{m[1]} ↔ {m[2]}', lambda p, a=a, b=b: (_in(p['src'], a) and _in(p['dst'], b)) or (_in(p['src'], b) and _in(p['dst'], a)))
    for m in eat(r'(?:from|src|source)\s+port\s+(\d+)'): add(f'src port {m[1]}', lambda p, v=int(m[1]): p['sport'] == v)
    for m in eat(r'(?:to|dst|dest|destination)\s+port\s+(\d+)'): add(f'dst port {m[1]}', lambda p, v=int(m[1]): p['dport'] == v)
    for m in eat(r'ports?\s+(\d+)'): add(f'port {m[1]}', lambda p, v=int(m[1]): v in (p['sport'], p['dport']))
    for m in eat(r'(?:from|src|source|sent by)\s+(?:ip\s+|address\s+)?' + IP):
        n = _net(m[1]); n and add(f'src {m[1]}', lambda p, n=n: _in(p['src'], n))
    for m in eat(r'(?:to|dst|dest|destination|towards)\s+(?:ip\s+|address\s+)?' + IP):
        n = _net(m[1]); n and add(f'dst {m[1]}', lambda p, n=n: _in(p['dst'], n))
    for m in eat(r'\b' + IP):
        n = _net(m[1]); n and add(f'host {m[1]}', lambda p, n=n: _in(p['src'], n) or _in(p['dst'], n))
    for m in eat(r'(?:larger|bigger|greater|more|over|above|>)\s*(?:than\s*)?(\d+)\s*(kb|bytes?|b)?\b'):
        v = int(m[1]) * (1024 if m[2] == 'kb' else 1); add(f'size > {v} B', lambda p, v=v: p['len'] > v)
    for m in eat(r'(?:smaller|less|under|below|<)\s*(?:than\s*)?(\d+)\s*(kb|bytes?|b)?\b'):
        v = int(m[1]) * (1024 if m[2] == 'kb' else 1); add(f'size < {v} B', lambda p, v=v: p['len'] < v)
    for m in eat(r'\b(first|last|top)\s+(\d+)'): lim = (m[1], min(int(m[2]), 5000)); chips.append(f'{m[1]} {lim[1]}')
    if eat(r'syn[- ]ack'): add('TCP SYN+ACK', lambda p: 'S' in p['flags'] and 'A' in p['flags'])
    if eat(r'\bsyn\b'): add('TCP SYN', lambda p: 'S' in p['flags'] and 'A' not in p['flags'])
    if eat(r'\b(?:rst|reset|resets)\b'): add('TCP RST', lambda p: 'R' in p['flags'])
    if eat(r'\bfin\b'): add('TCP FIN', lambda p: 'F' in p['flags'])
    for m in eat(r'\b(?:not|no|exclude|excluding|except|without)\s+(' + PK + r')\b'):
        v = PROTO[m[1]]; add(f'not {v}', lambda p, v=v: v not in (p['proto'], p['tr']))
    pv = {PROTO[m[1]] for m in eat(r'\b(' + PK + r')\b')}
    if pv: add('protocol: ' + ' | '.join(sorted(pv)), lambda p: p['proto'] in pv or p['tr'] in pv)
    for m in eat(r'\b(' + '|'.join(SVC) + r')\b'): add(f'{m[1]} (port {SVC[m[1]]})', lambda p, v=SVC[m[1]]: v in (p['sport'], p['dport']))
    for t in re.findall(r'[a-z0-9_\-.:]+', s):
        if t not in STOP and not t.strip('.-:_') == '': add(f'text "{t}"', txt(t))
    return (lambda p: all(f(p) for f in fs)), chips, lim
