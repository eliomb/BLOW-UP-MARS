"""Exercise original session/packet APIs and the new AI analysis routes."""
import http.server, json, os, socket, sys, threading, unittest, urllib.request
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import server
import urllib.error

class Endpoints(unittest.TestCase):
    def setUp(self):
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.H)
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True); self.t.start()
        self.base = f'http://127.0.0.1:{self.srv.server_port}'
    def tearDown(self):
        self.srv.shutdown(); self.srv.server_close()
        with server.LOCK:
            active = list(server.SESS.values()); server.SESS.clear()
        for item in active: server.discard(item)
    def request(self, path, obj=None):
        data = json.dumps(obj).encode() if obj is not None else None
        req = urllib.request.Request(self.base+path, data=data, headers={
            'X-Requested-With':'wirelight', **({'Content-Type':'application/json'} if data else {})})
        with urllib.request.urlopen(req) as r: return json.load(r)
    def test_arbitrary_host_is_allowed(self):
        """LAN Host headers no longer require app-level allowlisting."""
        req = urllib.request.Request(self.base + '/healthz', headers={'Host': '10.0.12.15:8080'})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertTrue(json.load(resp)['ok'])
        req = urllib.request.Request(self.base + '/api/ai/config', headers={
            'Host': '10.0.12.15:8080',
            'Origin': 'http://10.0.12.15:8080',
            'X-Requested-With': 'wirelight',
        })
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

    def test_cross_origin_and_missing_custom_header_still_denied(self):
        req = urllib.request.Request(self.base + '/api/ai/config', headers={
            'Host': '10.0.12.15:8080',
            'Origin': 'http://other-site.example',
            'X-Requested-With': 'wirelight',
        })
        with self.assertRaises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(req)
        self.assertEqual(err.exception.code, 403)
        req = urllib.request.Request(self.base + '/api/ai/config', headers={
            'Host': '10.0.12.15:8080',
            'Origin': 'http://10.0.12.15:8080',
        })
        with self.assertRaises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(req)
        self.assertEqual(err.exception.code, 403)

    def test_original_routes_and_ai(self):
        pk=[dict(n=0, ts=10., len=64, src='192.0.2.1', dst='192.0.2.2', sport=1234,
                 dport=80, proto='HTTP', tr='TCP', flags='PA', info='GET /', txt='get /')]
        sid,_=server.new_session(pk,[b'X'*64])
        self.assertEqual(self.request('/api/packets?id='+sid)['total'], 1)
        self.assertIn('hex', self.request('/api/packet?id='+sid+'&n=0'))
        self.assertEqual(self.request('/api/ai/report?id='+sid)['report'], None)
        fake = dict(summary='HTTP traffic observed', findings=[], confidence='low', narrative='',
                    next_steps=[], limitations=[], evidence={}, generated_utc='now', model='mock')
        with patch.object(server.ai, 'analyze', return_value=fake) as mock:
            result=self.request('/api/ai/analyze', {'id':sid})
        self.assertEqual(result['report'],fake)
        self.assertEqual(mock.call_args.args[0]['packet_count'], 1)
        self.assertEqual(self.request('/api/ai/report?id='+sid)['report'],fake)
        self.assertIn('endpoint',self.request('/api/ai/config'))
        with patch.object(server.ai, 'ask', return_value='Most traffic is HTTP.') as mock_chat:
            chat = self.request('/api/ai/ask', {'id':sid, 'question':'Which protocol is most common?'})
        self.assertEqual(chat['answer'], 'Most traffic is HTTP.')
        self.assertIn('question_specific_aggregates', mock_chat.call_args.args[0])
        self.assertEqual(len(self.request('/api/ai/chat?id='+sid)['messages']), 2)
        with patch.object(server.ai, 'ask', side_effect=server.ai.ModelTimeout('LM Studio timed out')):
            with self.assertRaises(urllib.error.HTTPError) as caught:
                self.request('/api/ai/ask', {'id':sid, 'question':'Any attacks?'})
        self.assertEqual(caught.exception.code, 504)
        self.assertEqual(len(self.request('/api/ai/chat?id='+sid)['messages']), 2)

if __name__ == '__main__': unittest.main()
