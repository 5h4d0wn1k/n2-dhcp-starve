#!/usr/bin/env python3
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from dhcp_starve import (DHCPDiscover, parse_dhcp_payload,
                         parse_bootp_payload, DHCPLeaseState,
                         find_msg_type, MSG_DISCOVER, run_harness,
                         MAGIC_COOKIE)


class DHCPDiscoverBuildTest(unittest.TestCase):
    def setUp(self):
        self.mac = '02:aa:bb:cc:dd:ee'

    def test_frame_layout(self):
        disc = DHCPDiscover(chaddr=self.mac, xid=0xDEADBEEF)
        raw = disc.build_eth(src_mac=self.mac)
        self.assertGreater(len(raw), 14 + 20 + 8 + 236 + 4)

    def test_parse_roundtrip(self):
        disc = DHCPDiscover(chaddr=self.mac, xid=0xC0FFEE,
                            req_ip='198.51.100.5')
        raw = disc.build_eth(src_mac=self.mac)
        p = parse_dhcp_payload(raw)
        self.assertEqual(p['op'], 1)
        self.assertEqual(p['xid'], 0xC0FFEE)
        self.assertEqual(p['msg_type'], MSG_DISCOVER)
        self.assertEqual(p['req_ip'], '198.51.100.5')
        self.assertEqual(bytes(p['chaddr']), bytes.fromhex('02aabbccddee'))

    def test_magic_cookie_present(self):
        disc = DHCPDiscover(chaddr=self.mac)
        payload = disc.build_udp_payload()
        self.assertEqual(payload[236:240], MAGIC_COOKIE)

    def test_server_offer_parse(self):
        import socket
        from dhcp_starve import FakeDHCPServer
        srv = FakeDHCPServer('198.51.100.10', 4)
        port = srv.start()
        import threading
        got = {}
        def serve():
            srv.sock.settimeout(0.5)
            data, addr = srv.sock.recvfrom(4096)
            got['offer'] = srv.respond(data, addr)
        t = threading.Thread(target=serve)
        t.start()
        disc = DHCPDiscover(chaddr=self.mac)
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        c.bind(('127.0.0.1', 0))
        c.settimeout(1)
        c.sendto(disc.build_udp_payload(), ('127.0.0.1', port))
        try:
            c.recvfrom(4096)
        except socket.timeout:
            pass
        t.join(timeout=1)
        c.close()
        srv.sock.close()
        self.assertIsNotNone(got.get('offer'))
        self.assertEqual(got['offer']['yiaddr'], '198.51.100.10')


class LeaseStateTest(unittest.TestCase):
    def test_exhaustion_after_pool_size(self):
        state = DHCPLeaseState(pool_size=8)
        for i in range(8):
            state.record_discover({'xid': i})
            state.leased_ips.add('198.51.100.%d' % (10 + i))
        self.assertFalse(state.exhausted)
        self.assertEqual(state.summary()['leased_ips'], 8)

    def test_not_exhausted_below_pool(self):
        state = DHCPLeaseState(pool_size=100)
        for i in range(10):
            state.leased_ips.add('198.51.100.%d' % (10 + i))
        self.assertFalse(state.exhausted)


class OfflineHarnessTest(unittest.TestCase):
    def test_harness_exhausts_pool(self):
        rc = run_harness(pool_size=8, rounds=12)
        self.assertEqual(rc, 0)


if __name__ == '__main__':
    unittest.main()
