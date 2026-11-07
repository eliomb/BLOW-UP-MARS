import collections, json, os, secrets, threading, time, subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import nlq, pcap, ssh, ai

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
    if not pk: return dict(packets=0, bytes=0, duration=0, start=time.time(), protocols=[], top_src=[], top_dst=[], timeline=[0] * 40)
    t0, t1 = pk[0]['ts'], pk[-1]['ts']; span = max(t1 - t0, 1e-9); tl = [0] * 40
    for p in pk: tl[min(39, int((p['ts'] - t0) / span * 40))] += 1
    top = lambda k: collections.Counter(p[k] for p in pk if p[k]).most_common(6)
    return dict(packets=len(pk), bytes=sum(p['len'] for p in pk), duration=t1 - t0, start=t0,
                protocols=collections.Counter(p['proto'] for p in pk).most_common(), top_src=top('src'), top_dst=top('dst'), timeline=tl)

def session(sid):
    with LOCK:
        s = SESS.get(sid)
        if s and s['exp'] > time.time(): s['exp'] = time.time() + TTL; return s

def new_session(pk, raw):
    sid = secrets.token_urlsafe(24)
    with LOCK:
        for k in [k for k, v in SESS.items() if v['exp'] < time.time()]: ssh.stop(SESS.pop(k))
        while len(SESS) >= MAX_SESS: ssh.stop(SESS.pop(min(SESS, key=lambda k: SESS[k]['exp'])))
        SESS[sid] = s = dict(pk=pk, raw=raw, exp=time.time() + TTL)
    return sid, s

class H(BaseHTTPRequestHandler):
    server_version, sys_version = 'pcapd', ''
    def log_message(self, *a): pass
    def out(self, code, body, ctype='application/json'):
        if not isinstance(body, bytes): body = json.dumps(body).encode()
        self.send_response(code); self.send_header('Content-Type', ctype); self.send_header('Content-Length', str(len(body)))
        for k, v in SEC.items(): self.send_header(k, v)
        self.end_headers(); self.wfile.write(body)

    def denied(self):  # No Host allowlist; retain same-origin and custom-header checks.
        h, o = self.headers.get('Host', ''), self.headers.get('Origin')
        if o and o not in ('http://' + h, 'https://' + h): return True
        return self.path.startswith('/api/') and self.headers.get('X-Requested-With') != 'wirelight'

    def jbody(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n > 8192: raise ValueError('Request too large')
        b = json.loads(self.rfile.read(n) or b'{}')
        if not isinstance(b, dict): raise ValueError('Bad JSON')
        return b

    def guarded(self, fn):
        if self.denied(): return self.out(403, {'error': 'Forbidden'})
        try: fn()
        except subprocess.TimeoutExpired: self.out(504, {'error': 'Timed out talking to the remote host'})
        except ai.ModelTimeout as e: self.out(504, {'error': str(e)})
        except ai.ModelRateLimited as e: self.out(429, {'error': str(e)})
        except (ai.ModelUnavailable, ai.ModelBadResponse) as e: self.out(502, {'error': str(e)})
        except (ValueError, IndexError, KeyError) as e: self.out(400, {'error': str(e) or 'Bad request'})
        except Exception: self.out(500, {'error': 'Internal error'})

    def do_GET(self): self.guarded(self.get)
    def do_POST(self): self.guarded(self.post)

    def get(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in FILES: return self.out(200, *FILES[u.path])
        if u.path == '/healthz': return self.out(200, {'ok': True})
        if u.path == '/api/keys': return self.out(200, {'keys': ssh.keys()})
        if u.path == '/api/ai/config':
            cfg = ai.config()
            return self.out(200, {'enabled': cfg['enabled'], 'configured': cfg['configured'],
                                  'provider': cfg['provider'], 'endpoint': cfg['endpoint'],
                                  'model': cfg['model'], 'timeout_seconds': cfg['timeout']})
        s = session(q.get('id', ''))
        if not s: return self.out(404, {'error': 'Session expired. Start again.'})
        pk = s['pk'][:]
        if u.path == '/api/packets':
            match, chips, lim = nlq.parse(q.get('q', ''))
            rows = [p for p in pk if match(p)]
            if lim: rows = rows[:lim[1]] if lim[0] == 'first' else rows[-lim[1]:]
            off, n = max(0, int(q.get('offset', 0))), min(500, max(1, int(q.get('limit', 100)))); t0 = pk[0]['ts'] if pk else 0
            keys = ('n', 'src', 'dst', 'sport', 'dport', 'proto', 'len', 'info')
            return self.out(200, dict(total=len(rows), filters=chips, rows=[dict({k: p[k] for k in keys}, t=round(p['ts'] - t0, 6)) for p in rows[off:off + n]]))
        if u.path == '/api/packet':
            i = int(q.get('n', -1))
            if not 0 <= i < len(pk): raise IndexError('No such packet')
            p = pk[i]
            return self.out(200, dict(p={k: p[k] for k in ('n', 'ts', 'len', 'src', 'dst', 'sport', 'dport', 'tr', 'proto', 'flags', 'info')}, hex=pcap.hexdump(s['raw'][i])))
        if u.path == '/api/ai/report':
            return self.out(200, {'report': s.get('ai_report'), 'packet_count': len(pk)})
        if u.path == '/api/ai/chat':
            return self.out(200, {'messages': s.get('ai_chat', []), 'packet_count': len(pk)})
        if u.path == '/api/live/status':
            L = s.get('live') or {}
            return self.out(200, dict(running=bool(L.get('running')), error=L.get('error', ''), stats=stats(pk)))
        self.out(404, {'error': 'Not found'})

    def post(self):
        p = self.path
        if p == '/api/upload':
            try: n = int(self.headers.get('Content-Length', ''))
            except ValueError: return self.out(411, {'error': 'Content-Length required'})
            if not 0 < n <= MAX_UP: return self.out(413, {'error': f'File must be under {MAX_UP >> 20} MB'})
            data = self.rfile.read(n)
            try:
                recs = pcap.read(data)
                if not recs: raise ValueError('No packets found in file')
            except Exception as e: return self.out(400, {'error': str(e) if isinstance(e, ValueError) else 'Could not parse file'})
            pk = [pcap.dissect(i, r) for i, r in enumerate(recs)]
            sid, _ = new_session(pk, [r[3][:pcap.SNAP] for r in recs])
            return self.out(200, dict(id=sid, stats=stats(pk), truncated=len(recs) >= pcap.MAXPKT))
        b = self.jbody()
        if p in ('/api/ai/analyze', '/api/ai/ask'):
            s = session(str(b.get('id', '')))
            if not s: return self.out(404, {'error': 'Session expired. Start again.'})
            question = b.get('question', '')
            if p == '/api/ai/ask' and (not isinstance(question, str) or not question.strip() or len(question.strip()) > ai.MAX_QUESTION):
                raise ValueError(f'Enter a question (1–{ai.MAX_QUESTION} characters)')
            with LOCK:
                if s.get('ai_busy'): return self.out(409, {'error': 'Another AI request is still running for this capture'})
                s['ai_busy'] = True
                packets = s['pk'][:]  # consistent snapshot, never forward raw packet contents
                history = s.get('ai_chat', [])[:]
            try:
                evidence = ai.observe(packets)
                if p == '/api/ai/analyze':
                    report = ai.analyze(evidence)
                    with LOCK: s['ai_report'] = report
                    return self.out(200, {'report': report})
                context = dict(evidence, question_specific_aggregates=ai.question_context(packets, question))
                answer = ai.ask(context, question, history)
                with LOCK:
                    s['ai_chat'] = (history + [{'role': 'user', 'content': question.strip()},
                                               {'role': 'assistant', 'content': answer}])[-12:]
                return self.out(200, {'answer': answer, 'packet_count': evidence['packet_count']})
            finally:
                with LOCK: s['ai_busy'] = False
        if p == '/api/keys': ssh.gen(str(b.get('name', ''))); return self.out(200, {'ok': True})
        if p == '/api/keys/delete': ssh.delete(str(b.get('name', ''))); return self.out(200, {'ok': True})
        if p == '/api/ssh/hostkey': return self.out(200, ssh.hostkey(b))
        if p == '/api/ssh/trust': ssh.trust(b.get('token')); return self.out(200, {'ok': True})
        if p == '/api/ssh/forget': ssh.forget(b); return self.out(200, {'ok': True})
        if p == '/api/ssh/interfaces': return self.out(200, {'interfaces': ssh.interfaces(ssh.conn(b))})
        if p == '/api/live/start':
            c = ssh.conn(b)
            with LOCK:
                if sum(1 for v in SESS.values() if v.get('live', {}).get('running')) >= 2: raise ValueError('Too many live captures running')
            sid, s = new_session([], [])
            try: ssh.live(s, c, str(b.get('iface', '')), str(b.get('filter', '')), int(b.get('seconds', 300)))
            except Exception:
                with LOCK: SESS.pop(sid, None)
                raise
            return self.out(200, {'id': sid})
        if p == '/api/live/stop':
            s = session(str(b.get('id', '')))
            if s: ssh.stop(s)
            return self.out(200, {'ok': True})
        self.out(404, {'error': 'Not found'})

if __name__ == '__main__':
    ssh.init()
    ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
