"""Regression coverage for >100k packets and readable disk-backed search."""
import http.server
import json
import os
import struct
import sys
import threading
import unittest
import urllib.request
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import pcap, server, capturestore


def frame(port=443, flags=0x02):
    ethernet = bytes.fromhex('001122334455aabbccddeeff0800')
    ip = bytes.fromhex('450000280001000040060000c0a80101c0a80102')
    tcp = struct.pack('>HHIIBBHHH', 31234, port, 0, 0, 0x50, flags, 1024, 0, 0)
    return ethernet + ip + tcp


class LargeUpload(unittest.TestCase):
    def setUp(self):
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.H)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.root = f'http://127.0.0.1:{self.http.server_port}'

    def tearDown(self):
        self.http.shutdown(); self.http.server_close()
        with server.LOCK:
            active = list(server.SESS.values()); server.SESS.clear()
        for s in active: server.discard(s)

    def req(self, path, data=None):
        if isinstance(data, dict):
            data = json.dumps(data).encode()
        request = urllib.request.Request(self.root+path, data=data,
            headers={'X-Requested-With':'wirelight', 'Content-Type':'application/octet-stream' if path == '/api/upload' else 'application/json'})
        with urllib.request.urlopen(request, timeout=120) as resp: return json.load(resp)

    def test_end_to_end_beyond_old_limit_and_ai_sampling(self):
        original, final = frame(), frame(8443)
        # 100,010 records; final packet is distinct and must remain visible.
        count = 100010
        data = pcap.pcap_header() + (pcap.pcap_record(1000, original, len(original)) * (count - 1)) + pcap.pcap_record(1001, final, len(final))
        j = self.req('/api/upload', data)
        self.assertEqual(j['stats']['packets'], count)
        self.assertFalse(j['truncated'])
        sid = j['id']
        j = self.req(f'/api/packets?id={sid}&offset=100000')
        self.assertEqual(j['total'], count)
        self.assertEqual(j['rows'][0]['n'], 100000)
        j = self.req(f'/api/packets?id={sid}&q=8443')
        self.assertEqual(j['total'], 1)
        self.assertEqual(j['rows'][0]['n'], count-1)
        j = self.req(f'/api/packets?id={sid}&q=tcp%20syn%20to%20port%208443')
        self.assertEqual(j['total'], 1)
        j = self.req(f'/api/packets?id={sid}&q=last%2010')
        self.assertEqual(j['rows'][0]['n'], count-10)
        detail = self.req(f'/api/packet?id={sid}&n={count-1}')
        self.assertEqual(detail['p']['dport'], 8443)
        with patch.object(server.ai, 'ask', return_value='Done') as model:
            r = self.req('/api/ai/ask', {'id':sid, 'question':'What happened at the end?', 'packet_numbers':[count-1]})
        self.assertEqual(r['packet_count'], count)
        context = model.call_args.args[0]
        self.assertEqual(context['context_scope']['total_parsed_packets'], count)
        self.assertLess(context['context_scope']['evidence_subset_packet_count'], count)
        self.assertEqual(context['full_capture_statistics']['packets'], count)
        self.assertEqual(context['explicitly_selected_packet_details'][0]['packet_number'], count)

    def test_reader_pcapng_not_capped(self):
        def block(kind, body):
            n=len(body)+12
            return struct.pack('<II',kind,n) + body + struct.pack('<I',n)
        shb = block(0x0a0d0d0a,bytes.fromhex('4d3c2b1a01000000ffffffffffffffff'))
        iface = block(1, struct.pack('<HHI',1,0,65535))
        pkt = frame()
        body = struct.pack('<IIIII',0,0,1,len(pkt),len(pkt)) + pkt + b'\0'*(-len(pkt)%4)
        epb = block(6,body)
        reader=pcap.CaptureReader()
        total=0
        with patch.object(pcap,'MAXPKT',3):
            for chunk in (shb+iface+epb*7,):
                total+=len(reader.feed(chunk))
        reader.finish()
        self.assertEqual(total,7)

    def test_plain_filters(self):
        s=capturestore.Store()
        try:
            for i in range(12): s.append((1000+i,54,1,frame(443 if i%2 else 80)))
            s.finalize()
            self.assertEqual(s.page('tcp syn to port 443')['total'],6)
            self.assertEqual(s.page('src:192.168.1.1')['total'],12)
            self.assertEqual(s.page('', proto='HTTP')['total'],0)
            self.assertEqual(s.page('', port='80')['total'],6)
            self.assertEqual(s.page('last 3 tcp')['rows'][0]['n'],9)
            self.assertEqual(s.page('size > 50 B')['total'],12)
        finally: s.close()


if __name__ == '__main__': unittest.main()

class RemoteDiskExport(unittest.TestCase):
    def setUp(self):
        self.http = http.server.ThreadingHTTPServer(('127.0.0.1',0),server.H)
        threading.Thread(target=self.http.serve_forever,daemon=True).start()
        self.root=f'http://127.0.0.1:{self.http.server_port}'

    def tearDown(self):
        self.http.shutdown();self.http.server_close()
        with server.LOCK:
            sessions=list(server.SESS.values());server.SESS.clear()
        for s in sessions: server.discard(s)

    def test_remote_disk_download_preserves_full_frame(self):
        raw=frame()+b'PRIVATE-RAW-CAPTURE-BYTES'*10
        store=capturestore.Store()
        store.append((1234.5,len(raw),1,raw),full=True)
        store.finalize()
        sid,s=server.new_session([],[],store)
        s['live']={'running':False}
        req=urllib.request.Request(f'{self.root}/api/live/download?id={sid}',headers={'X-Requested-With':'wirelight'})
        with urllib.request.urlopen(req) as r: data=r.read()
        self.assertEqual(pcap.read(data)[0][3],raw)
        self.assertEqual(len(data),24+16+len(raw))
