"""Dependency-free offline tests for both AI providers and metadata extraction."""
import http.server
import json
import os
import socketserver
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import ai

PACKETS = [dict(ts=100 + i * 0.1, len=90, src='192.0.2.1', dst='198.51.100.4', sport=40000+i,
                dport=20+i, tr='TCP', proto='TCP', flags='S', info='GET /secret', txt='password SECRET', n=i)
           for i in range(20)]

class Model(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_POST(self):
        assert self.path == '/v1/chat/completions'
        data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        prompt = data['messages'][1]['content']
        assert 'password SECRET' not in prompt and 'GET /secret' not in prompt
        assert '192.0.2.1' in prompt
        payload = json.dumps({'choices':[{'message':{'content':json.dumps({
            'summary':'Possible scanning from one source.', 'confidence':'medium',
            'findings':[{'category':'suspicious','title':'Unusual port spread','severity':'medium',
                         'detail':'20 SYN probes observed','evidence':['20 destination ports'],'recommendation':'Review flows'}],
            'narrative':'A source sent repeated SYN packets.', 'next_steps':['Correlate with firewall logs'],
            'limitations':['Metadata cannot confirm intent']})}}]}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)

class Tests(unittest.TestCase):
    def test_aggregates_no_payload(self):
        ev = ai.observe(PACKETS)
        self.assertEqual(ev['syn_only_count'], 20)
        self.assertEqual(len(ev['scan_candidates']), 1)
        self.assertNotIn('SECRET', json.dumps(ev))
        self.assertNotIn('/secret', json.dumps(ev))
    def test_bad_model_shape(self):
        with self.assertRaises(ValueError): ai.normalize({'findings':42}, ai.observe(PACKETS))
    def test_end_to_end_model(self):
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
        thread = threading.Thread(target=srv.serve_forever, daemon=True); thread.start()
        try:
            env = {'AI_PROVIDER':'lmstudio', 'LM_STUDIO_HOST':'127.0.0.1', 'LM_STUDIO_PORT':str(srv.server_port), 'LM_STUDIO_MODEL':'mock-model'}
            with patch.dict(os.environ, env):
                r = ai.analyze(ai.observe(PACKETS))
            self.assertEqual(r['findings'][0]['category'], 'suspicious')
            self.assertEqual(r['evidence']['packet_count'], 20)
            self.assertEqual(r['model'], 'mock-model')
        finally: srv.shutdown(); srv.server_close()
    def test_context_specific_host_and_port_counts(self):
        context = ai.question_context(PACKETS, 'Is 192.0.2.1 scanning port 20?')
        self.assertEqual(context['hosts'][0]['sent_packets'], 20)
        self.assertEqual(context['hosts'][0]['distinct_target_ports_for_syn'], 20)
        self.assertEqual(context['ports'][0]['destination_port_packets'], 1)
        self.assertNotIn('/secret', json.dumps(context))
        self.assertEqual(ai.question_context(PACKETS, 'What about port 70000?')['ports'], [])
    def test_chat_message_and_bounded_history(self):
        class ChatModel(Model):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                assert body['messages'][-1]['content'] == 'Any sign of a scan?'
                assert '/secret' not in json.dumps(body)
                assert body['messages'][-2]['content'] == 'Earlier answer'
                payload = json.dumps({'choices': [{'message': {'content': '20 SYN probes across 20 ports; possible scan.'}}]}).encode()
                self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(payload)))
                self.end_headers(); self.wfile.write(payload)
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), ChatModel)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with patch.dict(os.environ, {'AI_PROVIDER':'lmstudio', 'LM_STUDIO_HOST':'127.0.0.1', 'LM_STUDIO_PORT':str(srv.server_port), 'LM_STUDIO_MODEL':'mock-model'}):
                result = ai.ask(ai.observe(PACKETS), 'Any sign of a scan?', [{'role':'user','content':'Earlier question'}, {'role':'assistant','content':'Earlier answer'}])
            self.assertIn('20 SYN', result)
        finally: srv.shutdown(); srv.server_close()
    def test_timeout_reports_timeout_not_connection_failure(self):
        class SlowModel(Model):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                import time
                time.sleep(1.5)
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), SlowModel)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            # A server that accepted a request but does not reply in time is a gateway timeout.
            with patch.dict(os.environ, {'AI_PROVIDER':'lmstudio', 'LM_STUDIO_HOST':'127.0.0.1','LM_STUDIO_PORT':str(srv.server_port), 'LM_STUDIO_TIMEOUT':'10'}):
                with patch('ai.urllib.request.build_opener') as factory:
                    import socket
                    factory.return_value.open.side_effect = socket.timeout('timed out')
                    with self.assertRaises(ai.ModelTimeout): ai.ask(ai.observe(PACKETS), 'What happened?')
        finally: srv.shutdown(); srv.server_close()
    def test_mistral_config_without_key(self):
        with patch.dict(os.environ, {'AI_PROVIDER':'mistral', 'MISTRAL_API_KEY':'',
                                      'MISTRAL_MODEL':'ministral-8b-latest'}):
            cfg = ai.config()
            self.assertEqual(cfg['endpoint'], 'https://api.mistral.ai/v1/chat/completions')
            self.assertEqual(cfg['provider'], 'mistral')
            self.assertFalse(cfg['configured'])
            with self.assertRaisesRegex(ValueError, 'MISTRAL_API_KEY'):
                ai.ask(ai.observe(PACKETS), 'What happened?')

    def test_mistral_uses_https_and_bearer_server_side(self):
        from unittest.mock import MagicMock
        payload = json.dumps({'choices':[{'message':{'content':'These SYNs might indicate scanning.'}}]}).encode()
        response = MagicMock()
        response.read.return_value = payload
        response.__enter__.return_value = response
        with patch.dict(os.environ, {'AI_PROVIDER':'mistral', 'MISTRAL_API_KEY':'only-for-tests',
                                     'MISTRAL_MODEL':'ministral-8b-latest'}):
            with patch('ai.urllib.request.build_opener') as factory:
                factory.return_value.open.return_value = response
                answer = ai.ask(ai.observe(PACKETS), 'Is there scanning?')
            self.assertIn('SYNs', answer)
            req = factory.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, 'https://api.mistral.ai/v1/chat/completions')
            self.assertEqual(req.get_header('Authorization'), 'Bearer only-for-tests')
            sent = json.loads(req.data)
            self.assertEqual(sent['model'], 'ministral-8b-latest')
            self.assertNotIn('password SECRET', json.dumps(sent))

    def test_mistral_http_429_is_rate_limited(self):
        from io import BytesIO
        from urllib.error import HTTPError
        with patch.dict(os.environ, {'AI_PROVIDER':'mistral', 'MISTRAL_API_KEY':'only-for-tests'}):
            with patch('ai.urllib.request.build_opener') as factory:
                factory.return_value.open.side_effect = HTTPError(
                    'https://api.mistral.ai/v1/chat/completions', 429, 'Too Many Requests', {}, BytesIO(b''))
                with self.assertRaises(ai.ModelRateLimited):
                    ai.ask(ai.observe(PACKETS), 'What happened?')

    def test_bad_config(self):
        with patch.dict(os.environ, {'AI_PROVIDER':'lmstudio', 'LM_STUDIO_HOST':'127.0.0.1@evil.com'}):
            with self.assertRaises(ValueError): ai.config()
        with patch.dict(os.environ, {'AI_PROVIDER':'lmstudio', 'LM_STUDIO_PORT':'99999'}):
            with self.assertRaises(ValueError): ai.config()

if __name__ == '__main__': unittest.main()
