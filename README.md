# N2 — DHCP Starvation

Exhaust DHCP lease pool to force clients offline.

## Overview

This project implements a DHCP starvation attack that:
- Sends massive DHCP discover requests with random MACs
- Exhausts the DHCP server's IP address pool
- Forces legitimate clients to go offline
- Detects DHCP exhaustion status

## Features

- **Random MAC generation**: Create thousands of unique MAC addresses
- **Rate control**: Configurable send rate
- **Statistics**: Track packets sent and timing
- **Clean exit**: Graceful shutdown on Ctrl+C

## Installation

```bash
pip install scapy
```

## Usage

```bash
# Basic starvation
sudo python3 dhcp_starve.py --interface eth0

# Custom count
sudo python3 dhcp_starve.py --interface eth0 --count 5000
```

## Example Output

```
=== N2 — DHCP Starvation ===
Interface: eth0
Target: 1000 requests

Starting DHCP starvation...
  Sent 100/1000 DHCP discovers
  Sent 200/1000 DHCP discovers
  ...

=== Starvation Complete ===
Sent: 1000 packets
Time: 12.34 seconds
Rate: 81 packets/sec
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
