# N2 — DHCP Starvation (Lab / Portfolio)

DHCP discover engine with a lease-exhaustion state machine, built on a **pure
standard-library DHCP/BOOTP packet engine** (no scapy dependency for the core).

## What Works

- **Real BOOTP + DHCP frame construction** (`DHCPDiscover`) — builds genuine
  Ethernet + IPv4 + UDP + BOOTP(236B) + magic cookie + DHCP options by hand,
  including a correct IP header checksum.
- **Real parsing** (`parse_bootp_payload` / `parse_dhcp_payload`) — a built
  frame round-trips through the parser and yields the right op, xid, chaddr,
  requested IP, and message type.
- **Lease-exhaustion state machine** (`DHCPLeaseState`) — offline, tracks how
  many leases were granted against a simulated pool and flips to `exhausted`
  once the pool is drained.
- **Offline loopback harness** (`--harness`) — spins up a `FakeDHCPServer` on a
  real localhost UDP socket, feeds it real DHCP discover payloads, receives
  real offer payloads back, and verifies the simulated pool is exhausted.
- **Live injection** (`--live/--iface`) — real scapy sendp on an interface,
  gated behind an explicit flag (root required).

## Installation

Core is stdlib-only. Optional for live injection:

```bash
pip install scapy
```

## Usage

```bash
# Offline loopback lease-exhaustion harness (no privileges)
python3 dhcp_starve.py --harness

# Tune the simulated pool / rounds
python3 dhcp_starve.py --harness --pool-size 16 --rounds 20

# Live injection on a real interface (root + scapy)
sudo python3 dhcp_starve.py --live --iface eth0 --count 256
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (198.51.100.x, 02:... MACs).

1. Build a controlled DHCP lab: a DHCP server on a closed range and no
   production clients, on an isolated switchport.
2. Run `sudo python3 dhcp_starve.py --live --iface <lab-iface> --count <pool-size*2>`.
3. Monitor the DHCP server lease table: the pool should fill with fake CHADDRs.
4. Confirm no legitimate client on the lab can obtain a lease while exhausted.
5. Stop the starve; confirm the server reclaims leases after TTL expiry.

## Metrics

- DHCP frame round-trip parse: PASS (7 unit tests)
- Invalid cookie / short payload rejected with `ValueError`
- Lease-exhaustion state machine reaches `exhausted=True` once pool is drained
- Offline loopback harness: exit code `0`
- No privileges required for harness or tests

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Denial-of-service against systems you do not own is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and denial-of-service statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Interfering with networks you do not own
- Disrupting services without authorization
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

## License

MIT
