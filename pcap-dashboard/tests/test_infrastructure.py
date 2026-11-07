"""Behavior-specific regressions for neutral role assessment and topology."""
import json
import os
import struct
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import ai, evidence, infrastructure, pcap
from test_evidence import tcp_packet


def frame(n, src, dst, port=80, payload=b'', mac='02:42:ac:11:00:02'):
    pkt, data = tcp_packet(n, src, dst, 43000+n, port, 'PA', payload=payload)
    return pkt, data[:6] + bytes.fromhex(mac.replace(':', '')) + data[12:]


class InfrastructureTests(unittest.TestCase):
    def test_private_ip_does_not_alone_mean_docker_or_proxy(self):
        rows = [tcp_packet(i, '10.0.10.2', '10.0.10.9', 44000+i, 80, 'S') for i in range(20)]
        p, r = map(list, zip(*rows))
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':'', 'AI_NETWORK_NOTES':''}):
            result = infrastructure.summarize(p, r)
        self.assertEqual(result['host_role_hints'], [])
        self.assertIn('cannot establish Docker', result['interpretation'][0])

    def test_docker_mac_is_suggestive_but_not_proof(self):
        p, raw = frame(0, '10.0.10.2', '10.0.10.9')
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':''}):
            result = infrastructure.summarize([p], [raw])
        h = next(h for h in result['host_role_hints'] if h['ip'] == '10.0.10.2')
        self.assertIn('docker_style_virtual_mac', [x['role'] for x in h['hints']])
        self.assertIn('not_proof', h['hints'][0]['confidence'])

    def test_docker_range_is_weak_hint(self):
        p, r = tcp_packet(0, '172.17.0.3', '10.0.10.2', 43000, 443)
        # Generic MAC, no operator config: do not call the endpoint a container.
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':''}):
            result = infrastructure.summarize([p], [r])
        self.assertIn('address_in_common_docker_default_bridge_range',
                      [h['role'] for row in result['host_role_hints'] for h in row['hints']])
        self.assertNotIn('docker_container', json.dumps(result))

    def test_operator_topology_included_in_chat_and_report(self):
        rows = [tcp_packet(i, '10.0.12.15', '10.0.12.25', 44000+i, 8080, 'PA') for i in range(4)]
        p, r = map(list, zip(*rows))
        env = {'AI_DOCKER_NETWORKS':'10.0.12.0/24', 'AI_REVERSE_PROXY_IPS':'10.0.12.15',
               'AI_NETWORK_NOTES':'Traefik serves backend apps'}
        with patch.dict(os.environ, env):
            ev = evidence.build(p, r)
        ctx = ev['infrastructure_context']
        self.assertEqual(ctx['operator_declared_docker_networks'], ['10.0.12.0/24'])
        self.assertEqual(ctx['operator_declared_reverse_proxy_ips'], ['10.0.12.15'])
        self.assertEqual(ctx['operator_network_notes'], 'Traefik serves backend apps')
        self.assertIn('operator_designated_reverse_proxy', json.dumps(ctx))
        with patch('ai.send_messages', return_value='Normal proxy traffic') as send:
            result = ai.ask(ev, 'What is this traffic?')
            self.assertEqual(result, 'Normal proxy traffic')
            self.assertIn('operator_designated_reverse_proxy', send.call_args[0][0][1]['content'])
        with patch('ai.send_messages', return_value=json.dumps({
            'summary':'Normal reverse proxy connections', 'confidence':'medium',
            'findings':[{'category':'normal', 'title':'Proxy traffic'}]})) as send:
            result = ai.analyze(ev)
            self.assertEqual(result['findings'][0]['category'], 'normal')
            self.assertIn('operator_designated_reverse_proxy', send.call_args[0][0][1]['content'])

    def test_forwarded_headers_are_clues_not_assertions(self):
        payload = b'GET /health HTTP/1.1\r\nHost: backend\r\nX-Forwarded-For: 198.51.100.20\r\nX-Forwarded-Proto: https\r\n\r\n'
        pkt, raw = frame(0, '10.0.12.15', '10.0.12.25', 8080, payload)
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':''}):
            ev = evidence.build([pkt], [raw])
        hints = [h for row in ev['infrastructure_context']['host_role_hints']
                 for h in row['hints'] if h['role'] == 'http_proxy_or_forwarder_candidate']
        self.assertTrue(hints)
        self.assertEqual(hints[0]['headers']['x-forwarded-for'], 1)
        self.assertIn('can_be_client_supplied', hints[0]['confidence'])
        self.assertNotIn('198.51.100.20', json.dumps(hints))  # don't claim header value is true client IP

    def test_arbitrary_text_does_not_become_proxy_role(self):
        payload = b'GET / HTTP/1.1\r\nHost: backend\r\n\r\nX-Forwarded-For: fake'
        pkt, raw = frame(0, '10.0.12.15', '10.0.12.25', 8080, payload, 'aa:bb:cc:dd:ee:ff')
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':''}):
            ev = evidence.build([pkt], [raw])
        self.assertNotIn('http_proxy_or_forwarder_candidate', json.dumps(ev['infrastructure_context']))

    def test_tls_intermediary_topology_is_only_low_confidence(self):
        rows = [tcp_packet(i, f'10.0.11.{10+i}', '10.0.12.15', 48000+i, 443, 'PA')
                for i in range(4)]
        rows += [tcp_packet(4+i, '10.0.12.15', f'10.0.12.{30+i}', 49000+i, 8443, 'PA')
                 for i in range(3)]
        pk, frames = map(list, zip(*rows))
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'', 'AI_REVERSE_PROXY_IPS':''}):
            result = infrastructure.summarize(pk, frames)
        hints = [x for row in result['host_role_hints'] if row['ip'] == '10.0.12.15' for x in row['hints']]
        matching = [x for x in hints if x['role'] == 'possible_web_intermediary_traffic_topology']
        self.assertEqual(len(matching), 1)
        self.assertIn('ordinary_application_server', matching[0]['confidence'])
        self.assertNotIn('operator_designated_reverse_proxy', json.dumps(hints))

    def test_invalid_operator_settings_rejected(self):
        with patch.dict(os.environ, {'AI_DOCKER_NETWORKS':'not-a-subnet'}):
            with self.assertRaisesRegex(ValueError, 'AI_DOCKER_NETWORKS'):
                infrastructure.settings()
        with patch.dict(os.environ, {'AI_REVERSE_PROXY_IPS':'proxy.local'}):
            with self.assertRaisesRegex(ValueError, 'AI_REVERSE_PROXY_IPS'):
                infrastructure.settings()

    def test_prompt_is_neutral_about_attack(self):
        self.assertIn('not evidence\nof an attack', ai.SYSTEM)
        self.assertIn('do not assume an incident', ai.SYSTEM)
        self.assertIn('ordinary traffic', ai.CHAT_SYSTEM)


if __name__ == '__main__': unittest.main()
