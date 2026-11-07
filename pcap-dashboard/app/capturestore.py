"""Disk-backed, bounded packet index for uploads and remote capture.

Only the requested page is decoded into Python objects. SQLite handles the
index; raw frames are truncated for uploaded packet inspection, just like the
original UI. Persistent network maps live elsewhere in /data.
"""
import collections
import ipaddress
import os
import re
import secrets
import sqlite3
import tempfile
import threading
import time

import nlq
import pcap

ROOT = os.environ.get('CAPTURE_STORE_DIR', '/data/captures' if os.path.isdir('/data') else os.path.join(tempfile.gettempdir(), 'wirelight-captures'))
DISK_LIMIT = max(128, min(4096, int(os.environ.get('MAX_CAPTURE_STORE_MB', '768')))) * 1024 * 1024
FIELDS = ('n', 'ts', 'len', 'src', 'dst', 'sport', 'dport', 'tr', 'proto', 'flags', 'info', 'txt', 'link')
DBCOLS = ','.join(FIELDS)


def cleanup_stale():
    """Sessions don't survive restart; remove stale temporary indexes, never inventories."""
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    for name in os.listdir(ROOT):
        if name.startswith('capture-') and name.endswith(('.sqlite', '.sqlite-wal', '.sqlite-shm')):
            try: os.unlink(os.path.join(ROOT, name))
            except OSError: pass


def _ipnum(ip):
    try:
        value = ipaddress.ip_address(ip)
        return int(value) if value.version == 4 else None
    except ValueError:
        return None


def _sql_filter(q='', proto='', port='', host=''):
    """Compile existing NLQ filter chips to parameterized SQL, plus simple fields.

    This intentionally avoids running a Python predicate over millions of rows
    on each keypress. Unknown words become literal text searches.
    """
    conditions, args = [], []
    def append(expr, *values): conditions.append(expr); args.extend(values)
    def ip_condition(value, direction=None):
        try: net = ipaddress.ip_network(value, strict=False)
        except ValueError: return ('0', [])
        if net.version == 4:
            lo, hi = int(net.network_address), int(net.broadcast_address)
            col = {'src': 'src4', 'dst': 'dst4'}
            cols = [col[direction]] if direction else ['src4', 'dst4']
            return ('(' + ' OR '.join(f'{c} BETWEEN ? AND ?' for c in cols) + ')', [v for _ in cols for v in (lo, hi)])
        cols = [direction] if direction else ['src', 'dst']
        return '(' + ' OR '.join(f'{c} = ?' for c in cols) + ')', [value] * len(cols)
    if proto and proto.lower() != 'all':
        if proto.upper() not in ('TCP', 'UDP', 'DNS', 'HTTP', 'TLS', 'ICMP', 'ICMPV6', 'ARP', 'OTHER'):
            raise ValueError('Invalid protocol filter')
        append('(proto = ? OR tr = ?)', proto.upper() if proto.upper() != 'ICMPV6' else 'ICMPv6', proto.upper() if proto.upper() != 'ICMPV6' else 'ICMPv6')
    if port:
        if not port.isdecimal() or not 0 <= int(port) <= 65535: raise ValueError('Port must be between 0 and 65535')
        append('(sport = ? OR dport = ?)', int(port), int(port))
    if host:
        expr, v = ip_condition(host)
        append(expr, *v)
    q = q.strip()[:300]
    if q:
        # Common direct-input shortcuts (no special query language needed).
        m = re.fullmatch(r'(?i)(src|dst|host|ip):\s*(\S+)', q)
        if m:
            expr, v = ip_condition(m[2], m[1].lower() if m[1].lower() in ('src', 'dst') else None)
            append(expr, *v)
            return ' AND '.join(conditions) or '1', args, [], None
        m = re.fullmatch(r'(?i)(?:port:)\s*(\d{1,5})', q)
        if m:
            if int(m[1]) > 65535: raise ValueError('Port must be between 0 and 65535')
            append('(sport = ? OR dport = ?)', int(m[1]), int(m[1]))
            return ' AND '.join(conditions), args, [], None
        if q.isdecimal() and int(q) <= 65535:
            append('(sport = ? OR dport = ?)', int(q), int(q))
            return ' AND '.join(conditions), args, [], None
        try:
            net = ipaddress.ip_network(q, strict=False)
            expr, v = ip_condition(q)
            append(expr, *v)
            return ' AND '.join(conditions), args, [], None
        except ValueError:
            pass
    _, chips, limit = nlq.parse(q)
    for chip in chips:
        m = re.fullmatch(r'(src|dst|host) (.+)', chip)
        if m and not m[2].startswith('port '):
            expr, v = ip_condition(m[2], m[1] if m[1] != 'host' else None)
            append(expr, *v)
        elif chip.startswith('text "') and chip.endswith('"'):
            val = chip[6:-1].lower().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            term = '%' + val + '%'
            append("(txt LIKE ? ESCAPE '\\' OR lower(info) LIKE ? ESCAPE '\\' OR src LIKE ? ESCAPE '\\' OR dst LIKE ? ESCAPE '\\')", term, term, term, term)
        elif chip.startswith('protocol: '):
            values = chip[10:].split(' | ')
            append('(' + ' OR '.join('(proto = ? OR tr = ?)' for _ in values) + ')', *(v for x in values for v in (x, x)))
        elif chip.startswith('not '): append('(proto != ? AND tr != ?)', chip[4:], chip[4:])
        elif chip.startswith('port '): append('(sport = ? OR dport = ?)', int(chip[5:]), int(chip[5:]))
        elif chip.startswith('src port '): append('sport = ?', int(chip[9:]))
        elif chip.startswith('dst port '): append('dport = ?', int(chip[9:]))
        elif chip.endswith(')') and '(port ' in chip:
            number = int(chip.rsplit('(port ', 1)[1][:-1]); append('(sport = ? OR dport = ?)', number, number)
        elif chip.startswith('size > '): append('len > ?', int(chip[7:-2]))
        elif chip.startswith('size < '): append('len < ?', int(chip[7:-2]))
        elif chip == 'TCP SYN': append("instr(flags, 'S') > 0 AND instr(flags, 'A') = 0")
        elif chip == 'TCP SYN+ACK': append("instr(flags, 'S') > 0 AND instr(flags, 'A') > 0")
        elif chip == 'TCP RST': append("instr(flags, 'R') > 0")
        elif chip == 'TCP FIN': append("instr(flags, 'F') > 0")
        elif ' ↔ ' in chip:
            first, second = chip.split(' ↔ ', 1)
            a, va = ip_condition(first, 'src'); b, vb = ip_condition(second, 'dst')
            c, vc = ip_condition(second, 'src'); d, vd = ip_condition(first, 'dst')
            append(f'(({a} AND {b}) OR ({c} AND {d}))', *(va + vb + vc + vd))
    return ' AND '.join(f'({x})' for x in conditions) or '1', args, chips, limit


class Store:
    def __init__(self):
        os.makedirs(ROOT, mode=0o700, exist_ok=True)
        self.path = os.path.join(ROOT, 'capture-' + secrets.token_hex(16) + '.sqlite')
        self.conn = sqlite3.connect(self.path, timeout=20, check_same_thread=False)
        self.lock = threading.RLock()
        self.conn.execute('PRAGMA journal_mode=DELETE')
        self.conn.execute('PRAGMA synchronous=NORMAL')
        self.conn.execute('PRAGMA temp_store=MEMORY')
        self.conn.execute('PRAGMA cache_size=-12000')
        self.conn.execute('CREATE TABLE packets (n INTEGER PRIMARY KEY, ts REAL, len INTEGER, src TEXT, dst TEXT, sport INTEGER, dport INTEGER, tr TEXT, proto TEXT, flags TEXT, info TEXT, txt TEXT, link INTEGER, src4 INTEGER, dst4 INTEGER, frame BLOB)')
        self.count = 0
        self.wire_bytes = 0
        self.start = None
        self.end = None
        self.protocols = collections.Counter()
        self._pending = 0
        self._stats = None

    def close(self):
        with self.lock:
            try: self.conn.close()
            except sqlite3.Error: pass
            try: os.unlink(self.path)
            except OSError: pass

    def append(self, rec, *, full=False):
        with self.lock:
            ts, length, link, frame = rec
            p = pcap.dissect(self.count, rec)
            p['link'] = link
            blob = frame if full else frame[:pcap.SNAP]
            self.conn.execute('INSERT INTO packets VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                              tuple(p.get(k) for k in FIELDS) + (_ipnum(p['src']), _ipnum(p['dst']), blob))
            self.count += 1
            self.wire_bytes += length
            self.start = ts if self.start is None else min(self.start, ts)
            self.end = ts if self.end is None else max(self.end, ts)
            self.protocols[p['proto']] += 1
            self._stats = None
            self._pending += 1
            if self._pending >= 2048: self.flush()

    def flush(self):
        with self.lock:
            if self._pending:
                self.conn.commit(); self._pending = 0
                size = self.conn.execute('PRAGMA page_count').fetchone()[0] * self.conn.execute('PRAGMA page_size').fetchone()[0]
                if size > DISK_LIMIT:
                    raise ValueError(f'Capture index exceeds {DISK_LIMIT // (1024*1024)} MB disk limit; increase MAX_CAPTURE_STORE_MB or reduce capture size')

    def finalize(self):
        with self.lock:
            self.flush()
            self.conn.executescript('CREATE INDEX IF NOT EXISTS packet_src ON packets(src4); CREATE INDEX IF NOT EXISTS packet_dst ON packets(dst4); CREATE INDEX IF NOT EXISTS packet_proto ON packets(proto); CREATE INDEX IF NOT EXISTS packet_dport ON packets(dport);')
            size = os.path.getsize(self.path)
            if size > DISK_LIMIT:
                raise ValueError(f'Capture index exceeds {DISK_LIMIT // (1024*1024)} MB disk limit; increase MAX_CAPTURE_STORE_MB')
            self._stats = self.stats()

    def stats(self):
        with self.lock:
            if self._stats is not None: return self._stats
            if not self.count:
                return dict(packets=0, bytes=0, duration=0, start=time.time(), protocols=[], top_src=[], top_dst=[], timeline=[0]*40)
            span = max((self.end or 0) - (self.start or 0), 1e-9)
            tl = [0]*40
            # Time bins in SQL avoid keeping a million timestamps in memory.
            self.flush()
            for index, count in self.conn.execute('SELECT MIN(39,MAX(0,CAST((ts - ?)/? * 40 AS INTEGER))),COUNT(*) FROM packets GROUP BY 1', (self.start, span)):
                tl[index] = count
            top_src = self.conn.execute("SELECT src,COUNT(*) FROM packets WHERE src != '' GROUP BY src ORDER BY COUNT(*) DESC LIMIT 6").fetchall()
            top_dst = self.conn.execute("SELECT dst,COUNT(*) FROM packets WHERE dst != '' GROUP BY dst ORDER BY COUNT(*) DESC LIMIT 6").fetchall()
            return dict(packets=self.count, bytes=self.wire_bytes, duration=max(0, self.end-self.start), start=self.start,
                        protocols=self.protocols.most_common(), top_src=top_src, top_dst=top_dst, timeline=tl)

    def get(self, i):
        with self.lock:
            self.flush()
            row = self.conn.execute(f'SELECT {DBCOLS},frame FROM packets WHERE n=?', (i,)).fetchone()
        if row is None: raise IndexError('No such packet')
        return dict(zip(FIELDS, row[:-1])), row[-1]

    def page(self, q='', offset=0, limit=100, proto='', port='', host=''):
        where, params, chips, lim = _sql_filter(q, proto, port, host)
        with self.lock:
            self.flush()
            # Filter first and apply first/last limits before the UI page.
            if lim:
                order = 'DESC' if lim[0] == 'last' else 'ASC'
                sub = f'SELECT n FROM packets WHERE {where} ORDER BY n {order} LIMIT ?'
                expr, vals = f'n IN ({sub})', params + [lim[1]]
            else: expr, vals = where, params
            total = self.conn.execute(f'SELECT COUNT(*) FROM packets WHERE {expr}', vals).fetchone()[0]
            rows = self.conn.execute(f'SELECT n,ts,len,src,dst,sport,dport,proto,info FROM packets WHERE {expr} ORDER BY n LIMIT ? OFFSET ?', vals + [limit, offset]).fetchall()
            t0 = self.start or 0
            return {'total': total, 'filters': chips, 'rows': [dict(n=r[0], t=round(r[1]-t0,6), len=r[2], src=r[3], dst=r[4],sport=r[5],dport=r[6],proto=r[7],info=r[8]) for r in rows]}

    def ai_sample(self, max_rows=25000, question=''):
        """Deterministic capture-wide sample, including late packets and user-mentioned hosts.

        This is a sample, not full-capture forensic analysis; the UI/API labels
        its scope accurately and includes full-capture statistics.
        """
        with self.lock:
            self.flush()
            if self.count == 0: return [], []
            stride = max(1, (self.count + max_rows - 1) // max_rows)
            # Sample across whole capture; always include final packet.
            nums = list(range(0, self.count, stride))
            if nums[-1] != self.count - 1: nums.append(self.count - 1)
            mentioned = set(re.findall(r'(?:\d{1,3}\.){3}\d{1,3}', question))
            if mentioned:
                for host in list(mentioned)[:4]:
                    for (n,) in self.conn.execute('SELECT n FROM packets WHERE (src=? OR dst=?) ORDER BY n DESC LIMIT 120', (host, host)):
                        nums.append(n)
            # Suspicious/diagnostic candidates outside the uniform sample.
            for (n,) in self.conn.execute("SELECT n FROM packets WHERE flags LIKE '%S%' OR proto IN ('DNS','HTTP','ARP') ORDER BY n DESC LIMIT 500"):
                nums.append(n)
            nums = sorted(set(nums))[:max_rows+1100]
            result = []
            # One bounded indexed query per packet is expensive; use chunked IN queries.
            for start in range(0, len(nums), 700):
                batch = nums[start:start+700]
                marks = ','.join('?' for _ in batch)
                result.extend(self.conn.execute(f'SELECT {DBCOLS},frame FROM packets WHERE n IN ({marks}) ORDER BY n', batch))
        pk, raw = [], []
        for row in result:
            pk.append(dict(zip(FIELDS, row[:-1])))
            raw.append(row[-1])
        return pk, raw

    def iter_export(self, upto=None):
        """Separate reader so slow downloads don't block capture writes."""
        conn = sqlite3.connect(self.path, timeout=20)
        try:
            for row in conn.execute('SELECT ts,len,link,frame FROM packets WHERE n < ? ORDER BY n', (upto if upto is not None else self.count,)):
                yield row
        finally:
            conn.close()
