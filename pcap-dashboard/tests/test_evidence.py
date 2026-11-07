"""Behavioral correlation, packet sampling, privacy configurability and integration."""
import json
import os
import sys
import struct
import unittest
from unittest.mock import patch
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'app'))
import pcap, evidence


def tcp_packet(n, src, dst, sport, dport, flags='S', ts=None, payload=b''):
    from socket import inet_aton
    bits = sum(bit for bit, ch in pcap.FL if ch in flags)
    tcp = struct.pack('>HHIIBBHHH', sport, dport, 1, 0, 0x50, bits, 4096, 0, 0)
    ip = bytearray(bytes.fromhex('4500000000010000400600000000000000000000'))
    ip[2:4] = struct.pack('>H', 40 + len(payload)); ip[12:16] = inet_aton(src); ip[16:20] = inet_aton(dst)
    frame = bytes.fromhex('001122334455aabbccddeeff0800') + bytes(ip) + tcp + payload
    rec = (float(n if ts is None else ts), len(frame), 1, frame)
    parsed = pcap.dissect(n, rec); parsed['link'] = 1
    return parsed, frame


class EvidenceTests(unittest.TestCase):
    def test_vertical_scan_correlation_and_payload(self):
        rows = [tcp_packet(i, '10.0.10.2', '10.0.10.9', 46000+i, 1000+i, 'S') for i in range(40)]
        rows += [tcp_packet(40+i, '10.0.10.9', '10.0.10.2', 1000+i, 46000+i, 'RA') for i in range(40)]
        rows.append(tcp_packet(80, '10.0.10.2', '10.0.10.9', 50000, 80, 'PA', payload=b'GET /?q=attack-pattern HTTP/1.1\r\n\r\n'))
        pk, raw = map(list, zip(*rows))
        data = evidence.build(pk, raw, 'Is 10.0.10.2 scanning 10.0.10.9?')
        candidates = data['behavioral_evidence']['detector_candidates']
        self.assertTrue(any(x['type'] == 'vertical_tcp_syn_scan_candidate' and x['ports_on_target'] >= 40 for x in candidates))
        self.assertEqual(data['behavioral_evidence']['tcp_flag_totals']['rst'], 40)
        self.assertEqual(data['packet_count'], 81)
        self.assertGreater(data['context_scope']['sampled_packets'], 10)
        self.assertIn('attack-pattern', json.dumps(data['packet_samples']))
        self.assertTrue(any(x['sample_reason'] == 'question_specific' for x in data['packet_samples']))

    def test_horizontal_scan_correlated_across_hosts(self):
        rows = [tcp_packet(i, '192.0.2.1', f'198.51.100.{i+1}', 42000+i, 445, 'S') for i in range(22)]
        pk, raw = map(list, zip(*rows))
        data = evidence.build(pk, raw)
        self.assertTrue(any(x['type'] == 'horizontal_tcp_syn_scan_candidate' and x['hosts_on_port'] == 22
                            for x in data['behavioral_evidence']['detector_candidates']))

    def test_suspicious_http_path_is_correlated(self):
        row = tcp_packet(0, '192.0.2.2', '198.51.100.2', 39000, 80, 'PA',
                         payload=b'GET /../../etc/passwd HTTP/1.1\r\nHost: example.test\r\n\r\n')
        data = evidence.build([row[0]], [row[1]])
        alerts = data['behavioral_evidence']['detector_candidates']
        self.assertTrue(any(a['type'] == 'http_request_attack_string_candidate' and
                            a['pattern'] == 'directory_traversal_like' for a in alerts))
        self.assertIn('/../../etc/passwd', json.dumps(data['packet_samples']))

    def test_repeated_auth_service_connections(self):
        rows = [tcp_packet(i, '192.0.2.5', '198.51.100.4', 40000+i, 22, 'S') for i in range(15)]
        pk, raw = map(list, zip(*rows))
        data = evidence.build(pk, raw)
        self.assertTrue(any(a['type'] == 'repeated_tcp_connections_to_auth_service' and a['syn_packets'] == 15
                            for a in data['behavioral_evidence']['detector_candidates']))

    def test_context_limits_and_payload_control(self):
        rows = [tcp_packet(i, '192.0.2.1', '198.51.100.4', 10000+i, 80, 'PA', payload=b'SECRET_TOKEN') for i in range(200)]
        pk, raw = map(list, zip(*rows))
        with patch.dict(os.environ, {'AI_CONTEXT_CHARS':'12000', 'AI_PACKET_SAMPLES':'70', 'AI_PAYLOAD_CHARS':'300'}):
            data = evidence.build(pk, raw)
            self.assertLessEqual(len(json.dumps(data, ensure_ascii=True, separators=(',', ':'))), 12000)
            self.assertGreater(data['context_scope']['sampled_packets'], 0)
            self.assertIn('SECRET_TOKEN', json.dumps(data['packet_samples']))
        with patch.dict(os.environ, {'AI_CONTEXT_CHARS':'12000', 'AI_PACKET_SAMPLES':'70', 'AI_PAYLOAD_CHARS':'0'}):
            data = evidence.build(pk, raw)
            self.assertNotIn('SECRET_TOKEN', json.dumps(data))

    def test_invalid_settings_raise_errors(self):
        with patch.dict(os.environ, {'AI_PACKET_SAMPLES':'unbounded'}):
            with self.assertRaisesRegex(ValueError, 'AI_PACKET_SAMPLES'): evidence.options()


if __name__ == '__main__': unittest.main()
