import collections, json, os, secrets, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import nlq, pcap

MAX_UP = int(os.environ.get('MAX_UPLOAD_MB', '64')) * 2 ** 20
TTL, MAX_SESS = 1800, 4
SESS, LOCK = {}, threading.Lock()
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
FILES = {k: (open(os.path.join(ROOT, f), 'rb').read(), t) for k, (f, t) in {
    '/': ('index.html', 'text/html; charset=utf-8'), '/app.css': ('app.css', 'text/css; charset=utf-8'),
    '/app.js': ('app.js', 'application/javascript; charset=utf-8')}.items()}
SEC = {'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
       'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer',
       'Cache-Control': 'no-store', 'Cross-Origin-Resource-Policy': 'same-origin'}

def stats(pk):
    t0, t1 = pk[0]['ts'], pk[-1]['ts']; span = max(t1 - t0, 1e-9); tl = [0] * 40
    for p in pk: tl[min(39, int((p['ts'] - t0) / span * 40))] += 1
    top = lambda k: collections.Counter(p[k] for p in pk if p[k]).most_common(6)
    return dict(packets=len(pk), bytes=sum(p['len'] for p in pk), duration=t1 - t0, start=t0,
                protocols=collections.Counter(p['proto'] for p in pk).most_common(), top_src=top('src'), top_dst=top('dst'), timeline=tl)

def session(sid):
    with LOCK:
        s = SESS.get(sid)
        if s and s['exp'] > time.time(): s['exp'] = time.time() + TTL; return s

class H(BaseHTTPRequestHandler):
    server_version, sys_version = 'pcapd', ''
    def log_message(self, *a): pass
    def out(self, code, body, ctype='application/json'):
        if not isinstance(body, bytes): body = json.dumps(body).encode()
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(body)))
        for k, v in SEC.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in FILES: return self.out(200, *FILES[u.path])
        if u.path == '/healthz': return self.out(200, {'ok': True})
        s = session(q.get('id', ''))
        if not s: return self.out(404, {'error': 'Session expired. Upload the file again.'})
        try:
            if u.path == '/api/packets':
                match, chips, lim = nlq.parse(q.get('q', ''))
                rows = [p for p in s['pk'] if match(p)]
                if lim: rows = rows[:lim[1]] if lim[0] == 'first' else rows[-lim[1]:]
                off, n = max(0, int(q.get('offset', 0))), min(500, max(1, int(q.get('limit', 100)))); t0 = s['pk'][0]['ts']
                keys = ('n', 'src', 'dst', 'sport', 'dport', 'proto', 'len', 'info')
                return self.out(200, dict(total=len(rows), filters=chips, rows=[dict({k: p[k] for k in keys}, t=round(p['ts'] - t0, 6)) for p in rows[off:off + n]]))
            if u.path == '/api/packet':
                i = int(q.get('n', -1)); p = s['pk'][i]
                return self.out(200, dict(p={k: p[k] for k in ('n', 'ts', 'len', 'src', 'dst', 'sport', 'dport', 'tr', 'proto', 'flags', 'info')}, hex=pcap.hexdump(s['raw'][i])))
        except (ValueError, IndexError): return self.out(400, {'error': 'Bad request'})
        self.out(404, {'error': 'Not found'})

    def do_POST(self):
        if self.path != '/api/upload': return self.out(404, {'error': 'Not found'})
        try: n = int(self.headers.get('Content-Length', ''))
        except ValueError: return self.out(411, {'error': 'Content-Length required'})
        if not 0 < n <= MAX_UP: return self.out(413, {'error': f'File must be under {MAX_UP >> 20} MB'})
        data = self.rfile.read(n)
        try:
            recs = pcap.read(data)
            if not recs: raise ValueError('No packets found in file')
        except Exception as e: return self.out(400, {'error': str(e) if isinstance(e, ValueError) else 'Could not parse file'})
        pk = [pcap.dissect(i, r) for i, r in enumerate(recs)]
        sid = secrets.token_urlsafe(24)
        with LOCK:
            for k in [k for k, v in SESS.items() if v['exp'] < time.time()]: del SESS[k]
            while len(SESS) >= MAX_SESS: del SESS[min(SESS, key=lambda k: SESS[k]['exp'])]
            SESS[sid] = dict(pk=pk, raw=[r[3][:pcap.SNAP] for r in recs], exp=time.time() + TTL)
        self.out(200, dict(id=sid, stats=stats(pk), truncated=len(recs) >= pcap.MAXPKT))

if __name__ == '__main__':
    ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
