"""Nmap safety, persistent inventory, async refresh, and AI context selection."""
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import urllib.error
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import networkmap, server

XML = b'''<?xml version="1.0"?><nmaprun>
<host><status state="up"/><address addr="172.25.0.2" addrtype="ipv4"/>
 <hostnames><hostname name="web-01"/></hostnames><ports>
 <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.24"/></port>
 <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
 </ports></host>
<host><status state="up"/><address addr="172.25.0.3" addrtype="ipv4"/>
 <ports><port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port></ports></host>
</nmaprun>'''

class Inventory(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.saved_path, self.saved_dir = networkmap.DB_PATH, networkmap.DATA
        networkmap.DATA = self.tmp.name
        networkmap.DB_PATH = os.path.join(self.tmp.name, 'network-maps.json')
        networkmap.ACTIVE.clear()

    def tearDown(self):
        networkmap.DB_PATH, networkmap.DATA = self.saved_path, self.saved_dir
        networkmap.ACTIVE.clear()
        self.tmp.cleanup()

    def test_cidr_rejects_public_large_and_injection(self):
        for cidr in ['8.8.8.0/24', '172.25.0.0/16', '172.25.0.5/24',
                     '10.0.1.0/24; touch /tmp/unsafe', '127.0.0.1/8', '::1/128']:
            with self.subTest(cidr=cidr), self.assertRaises(ValueError):
                networkmap.create('Lab', cidr)
        self.assertEqual(networkmap.create('Lab', '10.0.1.0/24')['subnet'], '10.0.1.0/24')

    def test_manual_role_survives_manual_rescan_and_restart(self):
        m = networkmap.create('Nested Docker', '172.25.0.0/24', 'LXC host is 10.0.1.9')
        ident = m['id']
        networkmap.label_host(ident, '172.25.0.2', 'docker container', 'nginx behind proxy')
        with patch.object(networkmap.subprocess, 'run', return_value=type('R', (), {'returncode': 0, 'stdout': XML, 'stderr': b''})()) as cmd:
            networkmap.start_scan(ident)
            for _ in range(120):
                if networkmap.status(ident)['status'] != 'running': break
                time.sleep(.01)
            self.assertEqual(networkmap.status(ident)['status'], 'completed')
            self.assertIn('-sT', cmd.call_args.args[0])
            self.assertNotIn('-Pn', cmd.call_args.args[0])
            self.assertEqual(cmd.call_args.args[0][-1], '172.25.0.0/24')
            self.assertEqual(networkmap.detail(ident)['hosts'][0]['ports'][0]['service'], 'http')
            # A later scan with no hosts must not discard manually entered roles.
            cmd.return_value = type('R', (), {'returncode': 0, 'stdout': b'<nmaprun/>', 'stderr': b''})()
            networkmap.start_scan(ident, True)
            for _ in range(120):
                if networkmap.status(ident)['status'] != 'running': break
                time.sleep(.01)
            self.assertEqual(networkmap.status(ident)['status'], 'completed')
            self.assertEqual(networkmap.detail(ident)['labels']['172.25.0.2']['role'], 'docker container')
            self.assertEqual(networkmap.detail(ident)['hosts'], [])
            self.assertEqual(networkmap.detail(ident)['scan_count'], 2)
            self.assertEqual(json.loads(Path(networkmap.DB_PATH).read_text())['maps'][0]['id'], ident)
            context = networkmap.context(ident, [{'src': '172.25.0.2', 'dst': '172.25.0.3'}])
            self.assertEqual(context['hosts'][0]['operator_label']['role'], 'docker container')
            self.assertTrue(context['selected_by_user_for_this_analysis'])
        networkmap.delete(ident)
        self.assertEqual(networkmap.list_maps(), [])

    def test_aggressive_scan_finds_non_ping_windows_and_ignores_phantom_hosts(self):
        xml = b'''<nmaprun>
          <host><status state="up" reason="user-set"/>
            <address addr="10.0.1.10" addrtype="ipv4"/>
            <ports><extraports state="filtered" count="1050"/></ports></host>
          <host><status state="up" reason="user-set"/>
            <address addr="10.0.1.9" addrtype="ipv4"/>
            <ports>
             <port protocol="tcp" portid="445"><state state="open"/>
              <service name="microsoft-ds" product="Windows SMB"/>
              <script id="smb-os-discovery" output="OS: Windows Server 2022\nComputer name: LAB-SRV"/>
             </port>
             <port protocol="tcp" portid="3389"><state state="open"/>
              <service name="ms-wbt-server"/>
              <script id="rdp-ntlm-info" output="Product_Version: 10.0.20348"/>
             </port>
            </ports></host>
          <host><status state="up" reason="user-set"/>
            <address addr="10.0.1.18" addrtype="ipv4"/>
            <ports><extraports state="closed" count="1050"/></ports></host>
          </nmaprun>'''
        ident = networkmap.create('Windows Lab', '10.0.1.0/24')['id']
        networkmap.label_host(ident, '10.0.1.10', 'virtual machine', 'manual host survives scan')
        with patch.object(networkmap.subprocess, 'run', return_value=type('R', (), {
                'returncode': 0, 'stdout': xml, 'stderr': b''})()) as runner:
            networkmap.start_scan(ident, mode='aggressive')
            for _ in range(120):
                if networkmap.status(ident)['status'] != 'running': break
                time.sleep(.01)
            self.assertEqual(networkmap.status(ident)['status'], 'completed')
            cmd = runner.call_args.args[0]
            self.assertIn('-Pn', cmd)
            self.assertIn('-sT', cmd)
            self.assertIn('smb-os-discovery,rdp-ntlm-info', cmd)
            self.assertIn('5985', cmd[cmd.index('-p') + 1])
            self.assertNotIn('-O', cmd)  # preserve unprivileged Docker restrictions
            self.assertEqual(runner.call_args.kwargs['timeout'], networkmap.AGGRESSIVE_TIMEOUT)
        m = networkmap.detail(ident)
        self.assertEqual(m['scan_mode'], 'aggressive')
        self.assertEqual(m['scan_count'], 1)
        self.assertTrue(m['skip_discovery'])
        self.assertEqual([h['ip'] for h in m['hosts']], ['10.0.1.9', '10.0.1.18'])
        self.assertEqual(m['hosts'][0]['platform_clues'][0]['source'], 'smb-os-discovery')
        self.assertEqual(m['hosts'][0]['platform_clues'][1]['source'], 'rdp-ntlm-info')
        self.assertEqual(m['labels']['10.0.1.10']['role'], 'virtual machine')
        ctx = networkmap.context(ident, [{'src': '10.0.1.9', 'dst': '10.0.1.18'}])
        self.assertIn('Windows Server 2022', str(next(h for h in ctx['hosts'] if h['ip'] == '10.0.1.9')['platform_clues']))
        self.assertEqual(ctx['scan_mode'], 'aggressive')

    def test_invalid_scan_mode_does_not_start_scan(self):
        ident = networkmap.create('Lab', '10.0.1.0/24')['id']
        with self.assertRaisesRegex(ValueError, 'Invalid scan mode'):
            networkmap.start_scan(ident, mode='--script=unsafe')
        self.assertEqual(networkmap.status(ident)['status'], 'idle')

    def test_aggressive_scan_failure_preserves_older_snapshot(self):
        ident = networkmap.create('Lab', '10.0.1.0/24')['id']
        with patch.object(networkmap.subprocess, 'run', return_value=type('R', (), {'returncode': 0, 'stdout': XML, 'stderr': b''})()):
            networkmap.start_scan(ident)
            while networkmap.status(ident)['status'] == 'running': time.sleep(.01)
        previous = networkmap.detail(ident)
        with patch.object(networkmap.subprocess, 'run', side_effect=TimeoutError('slow')):
            networkmap.start_scan(ident, mode='aggressive')
            while networkmap.status(ident)['status'] == 'running': time.sleep(.01)
        # Other OS errors may not always be TimeoutExpired; this assertion
        # confirms the persisted snapshot regardless of subprocess failure.
        self.assertEqual(networkmap.detail(ident), previous)

    def test_multiple_selected_contexts_are_independent_and_bounded(self):
        one = networkmap.create('LXC hosts', '10.0.1.0/24')['id']
        two = networkmap.create('Docker bridge', '172.25.0.0/24')['id']
        networkmap.label_host(one, '10.0.1.9', 'lxc container', 'running Docker Engine')
        networkmap.label_host(two, '172.25.0.2', 'docker container', 'web backend')
        import evidence
        packet = dict(n=0, ts=1., len=70, src='10.0.1.9', dst='172.25.0.2',
                      sport=443, dport=4444, proto='TCP', tr='TCP', flags='A', info='TCP')
        maps = [networkmap.context(one, [packet]), networkmap.context(two, [packet])]
        result = evidence.build([packet], [b'X' * 70], selected_maps=maps)
        self.assertEqual(len(result['selected_network_maps']), 2)
        self.assertEqual(result['context_scope']['selected_network_maps'], ['LXC hosts', 'Docker bridge'])
        self.assertEqual(result['selected_network_maps'][0]['hosts'][0]['operator_label']['role'], 'lxc container')
        self.assertEqual(result['selected_network_maps'][1]['hosts'][0]['operator_label']['role'], 'docker container')
        self.assertLessEqual(len(json.dumps(result)), evidence.options()['max_chars'])

    def test_failure_keeps_last_good_inventory(self):
        ident = networkmap.create('Lab', '172.25.0.0/24')['id']
        with patch.object(networkmap.subprocess, 'run', return_value=type('R', (), {'returncode': 0, 'stdout': XML, 'stderr': b''})()):
            networkmap.start_scan(ident)
            while networkmap.status(ident)['status'] == 'running': time.sleep(.01)
        with patch.object(networkmap.subprocess, 'run', side_effect=FileNotFoundError('nmap')):
            networkmap.start_scan(ident)
            while networkmap.status(ident)['status'] == 'running': time.sleep(.01)
        self.assertEqual(networkmap.status(ident)['status'], 'failed')
        self.assertEqual(len(networkmap.detail(ident)['hosts']), 2)
        self.assertEqual(networkmap.detail(ident)['scan_count'], 1)

    def test_missing_nmap_nse_runtime_provides_rebuild_instructions(self):
        ident = networkmap.create('Lab', '10.0.1.0/24')['id']
        missing_nse = type('R', (), {
            'returncode': 1,
            'stdout': b'',
            'stderr': b'NSE: failed to initialize the script engine: '
                      b'could not locate nse_main.lua\nQUITTING!'
        })()
        with patch.object(networkmap.subprocess, 'run', return_value=missing_nse):
            networkmap.start_scan(ident)
            for _ in range(120):
                if networkmap.status(ident)['status'] != 'running': break
                time.sleep(.01)
        result = networkmap.status(ident)
        self.assertEqual(result['status'], 'failed')
        self.assertIn('nmap-nselibs', result['error'])
        self.assertIn('Rebuild Wirelight', result['error'])
        self.assertEqual(networkmap.detail(ident)['scan_count'], 0)

    def test_ai_routes_receive_selected_map_only(self):
        ident = networkmap.create('Lab', '172.25.0.0/24', 'Docker is inside LXC 10.0.1.9')['id']
        networkmap.label_host(ident, '172.25.0.2', 'reverse proxy', 'confirmed by operator')
        pk = [dict(n=0, ts=1., len=70, src='172.25.0.2', dst='172.25.0.3',
                   sport=3333, dport=443, proto='TCP', tr='TCP', flags='PA', info='TCP segment')]
        sid, _ = server.new_session(pk, [b'Z' * 70])
        app = http.server.ThreadingHTTPServer(('127.0.0.1', 0), server.H)
        thread = threading.Thread(target=app.serve_forever, daemon=True); thread.start()
        try:
            def request(path, body=None):
                payload = json.dumps(body).encode() if body is not None else None
                req = urllib.request.Request(f'http://127.0.0.1:{app.server_port}{path}', data=payload, headers={
                    'X-Requested-With': 'wirelight', 'Content-Type': 'application/json'})
                with urllib.request.urlopen(req) as res: return json.load(res)
            self.assertEqual(request('/api/maps')['maps'][0]['id'], ident)
            self.assertEqual(request('/api/maps/detail?id='+ident)['map']['labels']['172.25.0.2']['role'], 'reverse proxy')
            with patch.object(server.ai, 'ask', return_value='Likely ordinary backend traffic') as model:
                request('/api/ai/ask', {'id': sid, 'question': 'What is this?', 'map_ids': [ident]})
                self.assertEqual(model.call_args.args[0]['selected_network_maps'][0]['hosts'][0]['operator_label']['role'], 'reverse proxy')
                request('/api/ai/ask', {'id': sid, 'question': 'Any anomalies?', 'map_ids': []})
                self.assertNotIn('selected_network_maps', model.call_args.args[0])
        finally:
            app.shutdown(); app.server_close()

if __name__ == '__main__': unittest.main()
