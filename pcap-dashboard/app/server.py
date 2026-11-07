import collections, json, os, secrets, threading, time, subprocess, struct, datetime, sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import nlq, pcap, ssh, ai, evidence, networkmap, capturestore

MAX_UP = max(1, min(512, int(os.environ.get('MAX_UPLOAD_MB', '256')))) * 2 ** 20
TTL, MAX_SESS = 1800, 4
SESS, LOCK = {}, threading.Lock()
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
FILES = {k: (open(os.path.join(ROOT, f), 'rb').read(), t) for k, (f, t) in {
    '/': ('index.html', 'text/html; charset=utf-8'), '/app.css': ('app.css', 'text/css; charset=utf-8'),
    '/app.js': ('app.js', 'application/javascript; charset=utf-8'),
    '/marked.js': ('marked.js', 'application/javascript; charset=utf-8')}.items()}
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

def discard(s):
    ssh.stop(s)
    if s.get('store'): s['store'].close()

def new_session(pk, raw, store=None):
    sid = secrets.token_urlsafe(24)
    with LOCK:
        for k in [k for k, v in SESS.items() if v['exp'] < time.time()]: discard(SESS.pop(k))
        while len(SESS) >= MAX_SESS: ssh.stop(SESS.pop(min(SESS, key=lambda k: SESS[k]['exp'])))
        SESS[sid] = s = dict(pk=pk, raw=raw, store=store, exp=time.time() + TTL)
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
        except sqlite3.Error as e: self.out(507, {'error': 'Packet index storage error. Check free disk space in the Wirelight data volume and MAX_CAPTURE_STORE_MB.'})
        except (ai.ModelUnavailable, ai.ModelBadResponse) as e: self.out(502, {'error': str(e)})
        except (ValueError, IndexError, KeyError) as e: self.out(400, {'error': str(e) or 'Bad request'})
        except Exception: self.out(500, {'error': 'Internal error'})

    def do_GET(self): self.guarded(self.get)
    def do_POST(self): self.guarded(self.post)

    def get(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if u.path in FILES: return self.out(200, *FILES[u.path])
        if u.path == '/healthz': return self.out(200, {'ok': True})
        if u.path == '/api/upload/config': return self.out(200, {'max_bytes': MAX_UP})
        if u.path == '/api/keys': return self.out(200, {'keys': ssh.keys()})
        if u.path == '/api/maps': return self.out(200, {'maps': networkmap.list_maps()})
        if u.path == '/api/maps/detail': return self.out(200, {'map': networkmap.detail(q.get('id', ''))})
        if u.path == '/api/maps/status': return self.out(200, networkmap.status(q.get('id', '')))
        if u.path == '/api/ai/config':
            cfg = ai.config()
            return self.out(200, {'enabled': cfg['enabled'], 'configured': cfg['configured'],
                                  'provider': cfg['provider'], 'endpoint': cfg['endpoint'],
                                  'model': cfg['model'], 'timeout_seconds': cfg['timeout'],
                                  'context_settings': evidence.options()})
        s = session(q.get('id', ''))
        if not s: return self.out(404, {'error': 'Session expired. Start again.'})
        store = s.get('store')
        pk = s['pk'][:] if not store else []
        if u.path == '/api/packets' and store:
            off, n = max(0, int(q.get('offset', 0))), min(500, max(1, int(q.get('limit', 100))))
            return self.out(200, store.page(q.get('q', ''), off, n, q.get('proto', ''), q.get('port', ''), q.get('host', '')))
        if u.path == '/api/packets':
            match, chips, lim = nlq.parse(q.get('q', ''))
            rows = [p for p in pk if match(p)]
            if lim: rows = rows[:lim[1]] if lim[0] == 'first' else rows[-lim[1]:]
            off, n = max(0, int(q.get('offset', 0))), min(500, max(1, int(q.get('limit', 100)))); t0 = pk[0]['ts'] if pk else 0
            keys = ('n', 'src', 'dst', 'sport', 'dport', 'proto', 'len', 'info')
            return self.out(200, dict(total=len(rows), filters=chips, rows=[dict({k: p[k] for k in keys}, t=round(p['ts'] - t0, 6)) for p in rows[off:off + n]]))
        if u.path == '/api/packet':
            i = int(q.get('n', -1))
            if store:
                p, stored = store.get(i)
            else:
                if not 0 <= i < len(pk): raise IndexError('No such packet')
                p, stored = pk[i], s['raw'][i]
            frame = stored[:8192]
            return self.out(200, dict(p={k: p[k] for k in ('n', 'ts', 'len', 'src', 'dst', 'sport', 'dport', 'tr', 'proto', 'flags', 'info')},
                                      decoded=pcap.packet_layers(frame, p.get('link', 1)),
                                      captured_bytes=len(stored), inspected_bytes=len(frame),
                                      hex=pcap.hexdump(frame)))
        if u.path == '/api/live/download' and store:
            if not s.get('live'):
                return self.out(400, {'error': 'Download is available for remote captures only'})
            if not store.count:
                return self.out(400, {'error': 'No remote packets captured yet'})
            with store.lock:
                store.flush()
                count = store.count  # Snapshot a fixed packet range while live capture can continue.
                types = store.conn.execute('SELECT DISTINCT link FROM packets WHERE n < ? LIMIT 2', (count,)).fetchall()
                if len(types) != 1:
                    return self.out(409, {'error': 'Multiple link types cannot be exported to classic PCAP'})
                size = 24 + 16 * count + store.conn.execute('SELECT SUM(LENGTH(frame)) FROM packets WHERE n < ?', (count,)).fetchone()[0]
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Length', str(size))
            self.send_header('Content-Disposition', 'attachment; filename="wirelight-remote-capture.pcap"')
            for key, val in SEC.items(): self.send_header(key, val)
            self.end_headers()
            try:
                self.wfile.write(pcap.pcap_header(types[0][0]))
                for ts, orig, link, frame in store.iter_export(count):
                    self.wfile.write(pcap.pcap_record(ts, frame, orig))
            except (BrokenPipeError, ConnectionResetError): pass
            return
        if u.path == '/api/live/download':
            if not s.get('live'):
                return self.out(400, {'error': 'Download is available for remote captures only'})
            with LOCK:
                pairs = list(zip(s['pk'], s['raw']))
            if not pairs:
                return self.out(400, {'error': 'No remote packets captured yet'})
            link = pairs[0][0].get('link', 1)
            if any(p.get('link', 1) != link for p, _ in pairs):
                return self.out(409, {'error': 'Multiple link types cannot be exported to classic PCAP'})
            size = 24 + sum(16 + len(raw) for _, raw in pairs)
            self.send_response(200)
            self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
            self.send_header('Content-Length', str(size))
            self.send_header('Content-Disposition', 'attachment; filename="wirelight-remote-capture.pcap"')
            for key, val in SEC.items(): self.send_header(key, val)
            self.end_headers()
            try:
                self.wfile.write(pcap.pcap_header(link))
                for p, raw in pairs:
                    self.wfile.write(pcap.pcap_record(p['ts'], raw, p['len']))
            except (BrokenPipeError, ConnectionResetError): pass
            return
        if u.path == '/api/ai/report':
            return self.out(200, {'report': s.get('ai_report'), 'packet_count': store.count if store else len(pk)})
        if u.path == '/api/ai/chat':
            return self.out(200, {'messages': s.get('ai_chat', []), 'packet_count': store.count if store else len(pk)})
        if u.path == '/api/live/status':
            L = s.get('live') or {}
            return self.out(200, dict(running=bool(L.get('running')), error=L.get('error', ''), stats=store.stats() if store else stats(pk)))
        self.out(404, {'error': 'Not found'})

    def post(self):
        p = self.path
        if p == '/api/upload':
            try: n = int(self.headers.get('Content-Length', ''))
            except ValueError: return self.out(411, {'error': 'Content-Length required'})
            if not 0 < n <= MAX_UP:
                return self.out(413, {'error': f'File must be under {MAX_UP >> 20} MB. Change MAX_UPLOAD_MB if needed.'})
            reader = pcap.CaptureReader()
            store = capturestore.Store()
            remaining = n
            try:
                while remaining:
                    chunk = self.rfile.read(min(128 * 1024, remaining))
                    if not chunk: raise ValueError('Upload interrupted before file was received')
                    remaining -= len(chunk)
                    for rec in reader.feed(chunk):
                        store.append(rec)
                reader.finish()
                if not store.count: raise ValueError('No packets found in file')
                store.finalize()
            except Exception:
                store.close()
                raise
            sid, _ = new_session([], [], store)
            return self.out(200, dict(id=sid, stats=store.stats(), truncated=False))
        b = self.jbody()
        if p == '/api/maps/create':
            return self.out(200, {'map': networkmap.create(b.get('name', ''), b.get('subnet', ''), b.get('notes', ''))})
        if p == '/api/maps/update':
            return self.out(200, {'map': networkmap.update(b.get('id', ''), b.get('name', ''), b.get('notes', ''))})
        if p == '/api/maps/host':
            return self.out(200, {'label': networkmap.label_host(b.get('id', ''), b.get('ip', ''), b.get('role', 'unknown'), b.get('notes', ''))})
        if p == '/api/maps/delete':
            networkmap.delete(b.get('id', ''))
            return self.out(200, {'ok': True})
        if p == '/api/maps/scan':
            return self.out(202, networkmap.start_scan(b.get('id', ''), b.get('skip_discovery', False), b.get('mode', 'quick')))
        if p in ('/api/ai/analyze', '/api/ai/ask'):
            s = session(str(b.get('id', '')))
            if not s: return self.out(404, {'error': 'Session expired. Start again.'})
            question = b.get('question', '')
            map_ids = b.get('map_ids', [])
            if (not isinstance(map_ids, list) or len(map_ids) > 4 or
                    any(not isinstance(x, str) or not x or len(x) > 60 for x in map_ids) or
                    len(set(map_ids)) != len(map_ids)):
                raise ValueError('Select up to four distinct saved network maps')
            numbers = b.get('packet_numbers', []) if p == '/api/ai/ask' else []
            if not isinstance(numbers, list) or len(numbers) > 3 or any(type(x) is not int for x in numbers):
                raise ValueError('Select up to three packet numbers to share with AI')
            if p == '/api/ai/ask' and (not isinstance(question, str) or not question.strip() or len(question.strip()) > ai.MAX_QUESTION):
                raise ValueError(f'Enter a question (1–{ai.MAX_QUESTION} characters)')
            with LOCK:
                if s.get('ai_busy'): return self.out(409, {'error': 'Another AI request is still running for this capture'})
                s['ai_busy'] = True
                packets, raws = s['store'].ai_sample(question=question if p == '/api/ai/ask' else '') if s.get('store') else (s['pk'][:], s['raw'][:])
                history = s.get('ai_chat', [])[:]
            try:
                selected_maps = [networkmap.context(map_id, packets) for map_id in map_ids]
                context = evidence.build(packets, raws,
                                         question if p == '/api/ai/ask' else '',
                                         numbers if p == '/api/ai/ask' and not s.get('store') else [],
                                         selected_maps)
                if s.get('store'):
                    capture_stats = s['store'].stats()
                    scope = context['context_scope']
                    scope['total_parsed_packets'] = s['store'].count
                    scope['evidence_subset_packet_count'] = len(packets)
                    scope['capture_packet_limit_reached'] = False
                    scope['sample_policy'] = 'Capture-wide strided metadata sample with recent protocol/flag examples and question-matched hosts; NOT full-packet analysis'
                    context['full_capture_statistics'] = capture_stats
                    context['analysis_limitations'] = [x for x in context['analysis_limitations'] if 'first 100,000' not in x] + [
                        f'Full capture contains {s["store"].count:,} indexed packets. Detailed behavioral inference is based on {len(packets):,} sampled packets, not all packets; summary totals use the entire capture.'
                    ]
                    if numbers:
                        chosen = []
                        for number in dict.fromkeys(numbers):
                            packet, frame = s['store'].get(number)
                            chosen.append(ai.packet_context(packet, frame))
                        context['explicitly_selected_packet_details'] = chosen

                if p == '/api/ai/analyze':
                    report = ai.analyze(context)
                    with LOCK: s['ai_report'] = report
                    return self.out(200, {'report': report, 'context_scope': context['context_scope']})
                answer = ai.ask(context, question, history)
                with LOCK:
                    s['ai_chat'] = (history + [{'role': 'user', 'content': question.strip()},
                                               {'role': 'assistant', 'content': answer}])[-12:]
                return self.out(200, {'answer': answer, 'packet_count': s['store'].count if s.get('store') else len(packets),
                                      'context_scope': context['context_scope']})
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
            store = capturestore.Store()
            sid, s = new_session([], [], store)
            try: ssh.live(s, c, str(b.get('iface', '')), str(b.get('filter', '')), int(b.get('seconds', 300)))
            except Exception:
                with LOCK: SESS.pop(sid, None)
                discard(s)
                raise
            return self.out(200, {'id': sid})
        if p == '/api/live/stop':
            s = session(str(b.get('id', '')))
            if s: ssh.stop(s)
            return self.out(200, {'ok': True})
        self.out(404, {'error': 'Not found'})

if __name__ == '__main__':
    ssh.init()
    capturestore.cleanup_stale()
    ThreadingHTTPServer(('0.0.0.0', 8080), H).serve_forever()
