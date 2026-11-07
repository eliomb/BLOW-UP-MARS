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
        elif link == 276: et = struct.unpack('>H', b[0:2])[0]; b = b[20:]   # Linux cooked v2 (tcpdump -i any on libpcap >= 1.10)
        elif link in (12, 14, 101, 228, 229): et = 0x800 if b[0] >> 4 == 4 else 0x86dd   # raw IP
        elif link == 0: b = b[4:]; et = 0x800 if b[0] >> 4 == 4 else 0x86dd
        else: p['info'] = f'Unsupported link type {link}'
        pr = None
        if et == 0x800:
            pr = b[9]; p['src'], p['dst'] = socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20]); h = (b[0] & 15) * 4; tl = struct.unpack('>H', b[2:4])[0]; b = b[h:tl] if tl >= h else b[h:]
        elif et == 0x86dd:
            pr = b[6]; p['src'], p['dst'] = socket.inet_ntop(socket.AF_INET6, b[8:24]), socket.inet_ntop(socket.AF_INET6, b[24:40]); b = b[40:]
            while pr in (0, 43, 60): pr = b[0]; b = b[(b[1] + 1) * 8:]   # skip IPv6 extension headers
        elif et == 0x806:
            op = struct.unpack('>H', b[6:8])[0]
            p.update(tr='ARP', proto='ARP', src=socket.inet_ntoa(b[14:18]), dst=socket.inet_ntoa(b[24:28]))
            p['info'] = f"Who has {p['dst']}? Tell {p['src']}" if op == 1 else f"{p['src']} is at {b[8:14].hex(':')}"
        elif et: p['info'] = f'EtherType 0x{et:04x}'
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

FM = {b'\xd4\xc3\xb2\xa1': ('<', 1e6), b'\x4d\x3c\xb2\xa1': ('<', 1e9), b'\xa1\xb2\xc3\xd4': ('>', 1e6), b'\xa1\xb2\x3c\x4d': ('>', 1e9)}

class Stream:
    """Incremental classic-pcap reader for `tcpdump -w -` output."""
    def __init__(s): s.buf, s.e, s.res, s.link = bytearray(), None, 1e6, 1
    def feed(s, d):
        s.buf += d; out = []
        if s.e is None:
            if len(s.buf) < 24: return out
            if bytes(s.buf[:4]) not in FM: raise ValueError('not pcap')
            s.e, s.res = FM[bytes(s.buf[:4])]; s.link = struct.unpack(s.e + 'I', s.buf[20:24])[0]; del s.buf[:24]
        while len(s.buf) >= 16:
            sec, f, cl, ol = struct.unpack(s.e + 'IIII', s.buf[:16])
            if cl > 262144: raise ValueError('bad record')
            if len(s.buf) < 16 + cl: break
            out.append((sec + f / s.res, ol, s.link, bytes(s.buf[16:16 + cl]))); del s.buf[:16 + cl]
        return out

class CaptureReader:
    """Incrementally read classic pcap or pcapng without buffering the whole upload.

    feed() returns bounded individual records. Callers can discard records after MAXPKT,
    but should keep draining the HTTP body so keep-alive connections stay usable.
    """
    def __init__(self):
        self.buf = bytearray()
        self.kind = None
        self.stream = Stream()
        self.endian = '<'
        self.interfaces = []
        self.total = 0

    def feed(self, data):
        if self.total >= MAXPKT:
            return []
        if self.kind == 'pcap':
            result = self.stream.feed(data)
            self.total += len(result)
            return result[:max(0, MAXPKT - (self.total - len(result)))]
        self.buf.extend(data)
        if self.kind is None:
            if len(self.buf) < 4:
                return []
            magic = bytes(self.buf[:4])
            if magic in FM:
                self.kind = 'pcap'
                data = bytes(self.buf)
                self.buf.clear()
                return self.feed(data)
            if magic != b'\x0a\x0d\x0d\x0a':
                raise ValueError('Unsupported file: expected pcap or pcapng')
            self.kind = 'pcapng'
        result = []
        while len(self.buf) >= 12:
            if self.buf[:4] == b'\x0a\x0d\x0d\x0a':
                bom = bytes(self.buf[8:12])
                if bom == b'\x4d\x3c\x2b\x1a': self.endian = '<'
                elif bom == b'\x1a\x2b\x3c\x4d': self.endian = '>'
                else: raise ValueError('Invalid pcapng byte-order magic')
                self.interfaces = []
            e = self.endian
            typ, n = struct.unpack_from(e + 'II', self.buf)
            if n < 12 or n % 4 or n > 16 * 1024 * 1024:
                raise ValueError('Invalid pcapng block length')
            if len(self.buf) < n:
                break
            block = bytes(self.buf[8:n-4])
            if struct.unpack(e + 'I', self.buf[n-4:n])[0] != n:
                raise ValueError('Invalid pcapng block trailer')
            del self.buf[:n]
            if typ == 1 and len(block) >= 8:
                res, pos = 1e6, 8
                while pos + 4 <= len(block):
                    code, size = struct.unpack_from(e + 'HH', block, pos)
                    if code == 0: break
                    if code == 9 and size >= 1 and pos + 5 <= len(block):
                        v = block[pos + 4]
                        res = float(2 ** (v & 127) if v & 128 else 10 ** v)
                    pos += 4 + ((size + 3) & ~3)
                self.interfaces.append((struct.unpack_from(e + 'H', block)[0], res))
            elif typ == 6 and len(block) >= 20:
                iface, high, low, captured, original = struct.unpack_from(e + 'IIIII', block)
                if iface < len(self.interfaces) and captured <= 262144 and captured <= len(block) - 20:
                    link, res = self.interfaces[iface]
                    result.append(((high << 32 | low) / res, original, link, block[20:20+captured]))
                    self.total += 1
                    if self.total >= MAXPKT: break
            elif typ == 3 and len(block) >= 4 and self.interfaces:
                original = struct.unpack_from(e + 'I', block)[0]
                result.append((0.0, original, self.interfaces[0][0], block[4:4+min(original, len(block)-4)]))
                self.total += 1
                if self.total >= MAXPKT: break
        return result


def packet_layers(frame, link=1):
    """A bounded, Wireshark-style textual decode of common packet headers.

    The caller controls how much of `frame` is made available for inspection.
    Unsupported layers are described as raw data rather than guessed at.
    """
    layers = []
    length = len(frame)
    layers.append({'name': 'Frame', 'fields': {'Captured bytes': length}})
    data = frame
    try:
        et = None
        if link == 1 and len(data) >= 14:
            dst, src, et = data[:6].hex(':'), data[6:12].hex(':'), struct.unpack('>H', data[12:14])[0]
            fields = {'Destination MAC': dst, 'Source MAC': src, 'EtherType': f'0x{et:04x}'}
            data = data[14:]
            while et in (0x8100, 0x88a8) and len(data) >= 4:
                tag, et = struct.unpack('>HH', data[:4])
                fields['VLAN ID'] = tag & 0xfff
                fields['EtherType'] = f'0x{et:04x}'
                data = data[4:]
            layers.append({'name': 'Ethernet II', 'fields': fields})
        elif link == 113 and len(data) >= 16:
            et = struct.unpack('>H', data[14:16])[0]
            layers.append({'name': 'Linux cooked capture', 'fields': {'EtherType': f'0x{et:04x}'}})
            data = data[16:]
        elif link == 276 and len(data) >= 20:
            et = struct.unpack('>H', data[:2])[0]
            layers.append({'name': 'Linux cooked capture v2', 'fields': {'EtherType': f'0x{et:04x}'}})
            data = data[20:]
        elif link in (12, 14, 101, 228, 229) and data:
            et = 0x0800 if data[0] >> 4 == 4 else 0x86dd
        elif link == 0 and len(data) >= 5:
            data = data[4:]
            et = 0x0800 if data[0] >> 4 == 4 else 0x86dd
        else:
            layers.append({'name': 'Link layer', 'fields': {'DLT': link, 'Note': 'Unsupported or truncated link header'}})
        protocol = None
        source_port = destination_port = 0
        if et == 0x0800 and len(data) >= 20:
            h = (data[0] & 15) * 4
            if h < 20 or len(data) < h: raise ValueError('Short IPv4 header')
            total = struct.unpack('>H', data[2:4])[0]
            protocol = data[9]
            frag = struct.unpack('>H', data[6:8])[0]
            layers.append({'name': 'Internet Protocol Version 4', 'fields': {
                'Source': socket.inet_ntoa(data[12:16]), 'Destination': socket.inet_ntoa(data[16:20]),
                'Header length': h, 'Total length': total, 'TTL': data[8], 'Protocol number': protocol,
                'Identification': f'0x{struct.unpack(">H", data[4:6])[0]:04x}',
                'Fragment offset': frag & 0x1fff, 'More fragments': bool(frag & 0x2000)}})
            data = data[h:min(total, len(data))] if total >= h else data[h:]
            if frag & 0x1fff: protocol = None
        elif et == 0x86dd and len(data) >= 40:
            protocol = data[6]
            length6 = struct.unpack('>H', data[4:6])[0]
            layers.append({'name': 'Internet Protocol Version 6', 'fields': {
                'Source': socket.inet_ntop(socket.AF_INET6, data[8:24]),
                'Destination': socket.inet_ntop(socket.AF_INET6, data[24:40]),
                'Hop limit': data[7], 'Payload length': length6, 'Next header': protocol}})
            data = data[40:40+length6]
            while protocol in (0, 43, 60) and len(data) >= 8:
                next_header, size = data[0], (data[1] + 1) * 8
                layers.append({'name': 'IPv6 extension', 'fields': {'Type': protocol, 'Size': size}})
                protocol, data = next_header, data[size:]
        elif et == 0x0806 and len(data) >= 28:
            op = struct.unpack('>H', data[6:8])[0]
            layers.append({'name': 'Address Resolution Protocol', 'fields': {
                'Operation': 'request' if op == 1 else 'reply' if op == 2 else op,
                'Sender MAC': data[8:14].hex(':'), 'Sender IP': socket.inet_ntoa(data[14:18]),
                'Target MAC': data[18:24].hex(':'), 'Target IP': socket.inet_ntoa(data[24:28])}})
            data = data[28:]
        if protocol == 6 and len(data) >= 20:
            sport, dport, seq, ack = struct.unpack('>HHII', data[:12])
            source_port, destination_port = sport, dport
            size = (data[12] >> 4) * 4
            if size < 20 or len(data) < size: raise ValueError('Short TCP header')
            flags = data[13]
            layers.append({'name': 'Transmission Control Protocol', 'fields': {
                'Source port': sport, 'Destination port': dport, 'Sequence number': seq,
                'Acknowledgment number': ack, 'Header length': size,
                'Flags': ''.join(ch for bit, ch in FL if flags & bit) or 'none',
                'Window size': struct.unpack('>H', data[14:16])[0],
                'Checksum': f'0x{struct.unpack(">H", data[16:18])[0]:04x}'}})
            data = data[size:]
        elif protocol == 17 and len(data) >= 8:
            sport, dport, size, checksum = struct.unpack('>HHHH', data[:8])
            source_port, destination_port = sport, dport
            layers.append({'name': 'User Datagram Protocol', 'fields': {
                'Source port': sport, 'Destination port': dport, 'Length': size,
                'Checksum': f'0x{checksum:04x}'}})
            data = data[8:min(len(data), size)] if size >= 8 else data[8:]
        elif protocol in (1, 58) and len(data) >= 4:
            layers.append({'name': 'Internet Control Message Protocol' + (' v6' if protocol == 58 else ''), 'fields': {
                'Type': data[0], 'Code': data[1], 'Checksum': data[2:4].hex()}})
            data = data[4:]
        if 53 in (source_port, destination_port) and len(data) >= 12:
            dns = data[2:] if protocol == 6 and len(data) >= 14 else data
            if len(dns) >= 12:
                tid, flags, qcount, acount = struct.unpack('>HHHH', dns[:8])
                fields = {'Transaction ID': f'0x{tid:04x}', 'Type': 'response' if flags & 0x8000 else 'query',
                          'Questions': qcount, 'Answers': acount, 'Return code': flags & 15}
                # Decode the first uncompressed question safely; compressed
                # names are deliberately left uninterpreted here.
                i, labels = 12, []
                while i < len(dns) and len(labels) < 24 and 0 < dns[i] < 64:
                    n = dns[i]; i += 1
                    if i + n > len(dns): break
                    labels.append(dns[i:i+n].decode('ascii', 'replace')); i += n
                if labels: fields['Question name'] = '.'.join(labels)[:255]
                layers.append({'name': 'Domain Name System', 'fields': fields})
        if data:
            maybe_text = ''.join(chr(x) if 32 <= x < 127 else ('\n' if x in (10, 13) else '\t' if x == 9 else '.') for x in data[:2048])
            label = 'Application data'
            if data.startswith((b'GET ', b'POST ', b'HTTP/', b'HEAD ', b'PUT ', b'DELETE ', b'SSH-')):
                label = 'Text-based application data'
            layers.append({'name': label, 'fields': {'Bytes available': len(data), 'Preview': maybe_text[:512]}})
        else:
            maybe_text = ''
        return {'layers': layers, 'payload_text': maybe_text[:2048], 'payload_length': len(data)}
    except (IndexError, ValueError, OSError, struct.error) as exc:
        layers.append({'name': 'Decode warning', 'fields': {'Description': str(exc)}})
        return {'layers': layers, 'payload_text': '', 'payload_length': 0}


def pcap_header(link=1, snaplen=262144):
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, snaplen, link)


def pcap_record(ts, raw, original_len):
    sec = int(ts)
    usec = max(0, round((ts - sec) * 1e6))
    if usec >= 1000000: sec += 1; usec = 0
    return struct.pack('<IIII', sec, usec, len(raw), max(len(raw), original_len)) + raw
