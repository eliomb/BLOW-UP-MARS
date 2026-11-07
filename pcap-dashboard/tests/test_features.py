"""Regression tests for streaming upload, structured reports, packet viewing and remote PCAP export."""
import http.server
import json
import os
import socket
import struct
import sys
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import ai, pcap, server


def sample_frame(payload=b'GET /example HTTP/1.1\r\nHost: example.test\r\n\r\n'):
    ethernet = bytes.fromhex('001122334455aabbccddeeff0800')
    tcp = struct.pack('>HHIIBBHHH', 12345, 80, 123, 0, 0x50, 0x18, 4096, 0, 0)
    ip = bytes.fromhex('450000000001000040060000c0000201c6336402')
    ip = ip[:2] + struct.pack('>H', 20 + 20 + len(payload)) + ip[4:]
    return ethernet + ip + tcp + payload


def capture(frame, count=1):
    return pcap.pcap_header() + b''.join(pcap.pcap_record(1234.0 + i, frame, len(frame)) for i in range(count))


class Features(unittest.TestCase):
    def setUp(self):
        self.srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:' + str(self.srv.server_port)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        with server.LOCK:
            active = list(server.SESS.values()); server.SESS.clear()
        for item in active: server.discard(item)

    def req(self, route, body=None, raw=False):
        headers = {'X-Requested-With': 'wirelight'}
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        elif body is not None:
            headers['Content-Type'] = 'application/octet-stream'
        request = urllib.request.Request(self.base + route, data=body, headers=headers)
        with urllib.request.urlopen(request, timeout=40) as res:
            data = res.read()
            return data if raw else json.loads(data)

    def test_packet_decode_exposes_text_and_fields(self):
        frame = sample_frame()
        j = self.req('/api/upload', capture(frame))
        detail = self.req('/api/packet?id=' + j['id'] + '&n=0')
        self.assertIn('GET /example', detail['decoded']['payload_text'])
        self.assertIn('Internet Protocol Version 4', [x['name'] for x in detail['decoded']['layers']])
        tcp = next(x for x in detail['decoded']['layers'] if x['name'] == 'Transmission Control Protocol')
        self.assertEqual(tcp['fields']['Destination port'], 80)
        self.assertIn('0010', detail['hex'])

    def test_packet_text_automatically_sampled_and_selected_adds_detail(self):
        sid = self.req('/api/upload', capture(sample_frame(b'SECRET-TEST-TOKEN')) )['id']
        with patch.object(server.ai, 'ask', return_value='I see test data.') as mock:
            self.req('/api/ai/ask', {'id': sid, 'question': 'Any issue?'})
            evidence = mock.call_args.args[0]
            self.assertNotIn('explicitly_selected_packet_details', evidence)
            self.assertIn('SECRET-TEST-TOKEN', json.dumps(evidence['packet_samples']))
            self.assertGreaterEqual(evidence['context_scope']['sampled_packets'], 1)
            self.req('/api/ai/ask', {'id': sid, 'question': 'Explain the selected packet', 'packet_numbers':[0]})
            evidence = mock.call_args.args[0]
            self.assertIn('SECRET-TEST-TOKEN', json.dumps(evidence['explicitly_selected_packet_details']))
        with self.assertRaises(urllib.error.HTTPError) as err:
            self.req('/api/ai/ask', {'id': sid, 'question': 'Bad', 'packet_numbers':[5]})
        self.assertEqual(err.exception.code, 400)

    def test_remote_download_has_real_complete_packet(self):
        frame = sample_frame(b'x' * 4000)
        packet = pcap.dissect(0, (1234., len(frame), 1, frame))
        packet['link'] = 1
        sid, s = server.new_session([packet], [frame])
        s['live'] = {'running': False, 'error': ''}
        data = self.req('/api/live/download?id=' + sid, raw=True)
        self.assertEqual(len(data), 24+16+len(frame))
        records = pcap.read(data)
        self.assertEqual(records[0][3], frame)
        self.assertEqual(records[0][1], len(frame))
        self.assertEqual(records[0][2], 1)

    def test_incremental_stream_classic_and_pcapng(self):
        frame = sample_frame(b'abc')
        reader = pcap.CaptureReader()
        data = capture(frame, 3)
        recs = []
        for offset in range(0, len(data), 7):
            recs.extend(reader.feed(data[offset:offset+7]))
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0][3], frame)
        # Build a section, one interface and an enhanced-packet block.
        def block(kind, body):
            size = len(body) + 12
            return struct.pack('<II', kind, size) + body + struct.pack('<I', size)
        section = block(0x0a0d0d0a, bytes.fromhex('4d3c2b1a01000000ffffffffffffffff'))
        idb = block(1, struct.pack('<HHI', 1, 0, 65535))
        pad = b'\x00' * (-len(frame) % 4)
        epb = block(6, struct.pack('<IIIII', 0, 0, 1234567, len(frame), len(frame)) + frame + pad)
        reader = pcap.CaptureReader()
        recs = []
        data = section + idb + epb
        for i in range(0, len(data), 5):
            recs += reader.feed(data[i:i+5])
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0][3], frame)

    def test_strict_json_with_unescaped_linebreak(self):
        evidence = ai.observe([pcap.dissect(0, (1234., len(sample_frame()), 1, sample_frame()))])
        bad = '{"summary":"a line\nline two", "findings":[], "next_steps":[]}'
        with patch.object(ai, 'send_messages', return_value=bad) as send:
            report = ai.analyze(evidence)
        self.assertIn('line two', report['summary'])
        self.assertTrue(send.call_args.kwargs['json_mode'])
        with patch.object(ai, 'send_messages', return_value='not even json'):
            report = ai.analyze(evidence)
        self.assertTrue(report['format_fallback'])
        self.assertEqual(report['confidence'], 'low')

    def test_oversized_upload_returns_http_413(self):
        # Force a tiny limit without constructing an oversized file.
        with patch.object(server, 'MAX_UP', 8):
            with self.assertRaises(urllib.error.HTTPError) as err:
                self.req('/api/upload', b'0123456789012345')
        self.assertEqual(err.exception.code, 413)


if __name__ == '__main__':
    unittest.main()
