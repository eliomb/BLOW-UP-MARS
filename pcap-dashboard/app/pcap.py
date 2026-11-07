"""Dependency-free pcap/pcapng reader and packet dissector."""
import struct, socket
MAXPKT, SNAP = 100000, 1600
FL = [(1, 'F'), (2, 'S'), (4, 'R'), (8, 'P'), (16, 'A'), (32, 'U')]

def read(d):
    if len(d) < 24: raise ValueError("Not a capture file")
    m = d[:4]
    if m == b'\x0a\x0d\x0d\x0a': return _ng(d)
    fm = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\x4d\x3c\xb2\xa1': ('<', 1e9),
          b'\xa1\xb2\xc3\xd4': ('>', 1e6), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}
    if m not in fm: raise ValueError("Unsupported file: expected pcap or pcapng")
    e, res = fm[m]; link = struct.unpack(e + 'I', d[20:24])[0]; o = 24; r = []
    while o + 16 <= len(d) and len(r) < MAXPKT:
        s, f, cl, ol = struct.unpack(e + 'IIII', d[o:o + 16]); o += 16
        if cl > 262144: break
        r.append((s + f / res, ol, link, d[o:o + cl])); o += cl
    return r

def _ng(d):
    r, o, e, ifs = [], 0, '<', []
    while o + 12 <= len(d) and len(r) < MAXPKT:
        if d[o:o + 4] == b'\x0a\x0d\x0d\x0a':
            e = '<' if d[o + 8:o + 12] == b'\x4d\x3c\x2b\x1a' else '>'; ifs = []
        t, n = struct.unpack(e + 'II', d[o:o + 8])
        if n < 12 or o + n > len(d): break
        b = d[o + 8:o + n - 4]
        if t == 1:
            res, p = 1e6, 8
            while p + 4 <= len(b):
                c, l = struct.unpack(e + 'HH', b[p:p + 4])
                if c == 0: break
                if c == 9 and l >= 1:
                    v = b[p + 4]; res = float(2 ** (v & 0x7f) if v & 0x80 else 10 ** v)
                p += 4 + (l + 3) // 4 * 4
            ifs.append((struct.unpack(e + 'H', b[:2])[0], res))
        elif t == 6 and ifs:
            i, th, tl, cl, ol = struct.unpack(e + 'IIIII', b[:20])
            if i < len(ifs): r.append(((th << 32 | tl) / ifs[i][1], ol, ifs[i][0], b[20:20 + cl]))
        o += n
    return r

def _app(p, b):
    p['txt'] = ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:512]).lower()
    if {p['sport'], p['dport']} & {53, 5353} and p['tr'] == 'UDP' and len(b) > 12:
        i, nm = 12, []
        while i < len(b) and 0 < b[i] < 64:
            nm.append(b[i + 1:i + 1 + b[i]].decode('ascii', 'replace')); i += b[i] + 1
        p['proto'] = 'DNS'; p['info'] = ('Response ' if b[2] & 128 else 'Query ') + '.'.join(nm)
    elif b[:4] in (b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE', b'OPTI', b'PATC') or b[:5] == b'HTTP/':
        p['proto'] = 'HTTP'; p['info'] = b.split(b'\r\n')[0][:120].decode('ascii', 'replace')
    elif len(b) > 5 and b[0] in (20, 21, 22, 23) and b[1] == 3 and b[2] <= 4:
        p['proto'] = 'TLS'; p['info'] = 'TLS ' + {20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data'}[b[0]]

def dissect(i, rec):
    ts, ol, link, b = rec
    p = dict(n=i, ts=ts, len=ol, src='', dst='', sport=0, dport=0, tr='Other', proto='Other', flags='', info='', txt='')
    try:
        et = 0
        if link == 1:
            et = struct.unpack('>H', b[12:14])[0]; b = b[14:]
            while et in (0x8100, 0x88a8): et = struct.unpack('>H', b[2:4])[0]; b = b[4:]
        elif link == 113: et = struct.unpack('>H', b[14:16])[0]; b = b[16:]
        elif link == 101: et = 0x800 if b[0] >> 4 == 4 else 0x86dd
        elif link == 0: b = b[4:]; et = 0x800 if b[0] >> 4 == 4 else 0x86dd
        pr = None
        if et == 0x800:
            pr = b[9]; p['src'], p['dst'] = socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20]); b = b[(b[0] & 15) * 4:]
        elif et == 0x86dd:
            pr = b[6]; p['src'], p['dst'] = socket.inet_ntop(socket.AF_INET6, b[8:24]), socket.inet_ntop(socket.AF_INET6, b[24:40]); b = b[40:]
        elif et == 0x806:
            op = struct.unpack('>H', b[6:8])[0]
            p.update(tr='ARP', proto='ARP', src=socket.inet_ntoa(b[14:18]), dst=socket.inet_ntoa(b[24:28]))
            p['info'] = f"Who has {p['dst']}? Tell {p['src']}" if op == 1 else f"{p['src']} is at {b[8:14].hex(':')}"
        if pr in (6, 17):
            p['sport'], p['dport'] = struct.unpack('>HH', b[:4])
            if pr == 6:
                p['tr'] = p['proto'] = 'TCP'; f = b[13]; p['flags'] = ''.join(c for v, c in FL if f & v)
                b = b[(b[12] >> 4) * 4:]; p['info'] = f"{p['sport']} → {p['dport']} [{p['flags']}] len={len(b)}"
            else:
                p['tr'] = p['proto'] = 'UDP'; b = b[8:]; p['info'] = f"{p['sport']} → {p['dport']} len={len(b)}"
            _app(p, b)
        elif pr in (1, 58):
            p['tr'] = p['proto'] = 'ICMP' if pr == 1 else 'ICMPv6'; p['info'] = f"type {b[0]} code {b[1]}"
    except (IndexError, struct.error, ValueError, OSError):
        p['info'] = p['info'] or 'Malformed packet'
    return p

def hexdump(b):
    return '\n'.join(f"{i:04x}  {b[i:i+16].hex(' '):<47}  " + ''.join(chr(x) if 32 <= x < 127 else '.' for x in b[i:i + 16])
                     for i in range(0, len(b), 16))
