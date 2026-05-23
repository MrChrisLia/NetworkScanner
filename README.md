# NetworkScanner

Discovers every device on your local network and returns each one's IP address, MAC address, hostname, and vendor. Optionally scans common ports on every host.

Works on macOS without root/sudo — no raw-packet libraries required.

## How it works

1. Sends a parallel ping sweep across the subnet to trigger ARP resolution
2. Reads the OS ARP table (`arp -a`) to collect IP → MAC mappings
3. Resolves hostnames and vendor info concurrently
4. Optionally connects to each host's common ports to find open services

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Auto-detect your local subnet and scan it
python3 main.py

# Scan a specific subnet
python3 main.py -i 192.168.1.0/24

# Also scan common ports on each device
python3 main.py -p

# Export results
python3 main.py -o results.json
python3 main.py -o results.csv

# Combine flags
python3 main.py -i 192.168.1.0/24 -p -o scan.json
```

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `-i`, `--ip` | Target subnet in CIDR notation | Auto-detected /24 |
| `-p`, `--ports` | Scan common ports on each device | Off |
| `-o`, `--output` | Save results to `.json` or `.csv` | Off |
| `--threads` | Worker threads for ping sweep and port scanning | 200 |

## Ports scanned (with `-p`)

| Port | Service |
|------|---------|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 135 | MSRPC |
| 139 | NetBIOS |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 3389 | RDP |
| 5900 | VNC |
| 8080 | HTTP-Alt |
| 8443 | HTTPS-Alt |

## Example output

```
Auto-detected subnet: 192.168.1.0/24
Scanning 192.168.1.0/24 ...
Found 8 device(s). Gathering details ...

192.168.1.0/24 — 2026-05-23 14:32:01

╭─────────────────┬───────────────────┬──────────────────────┬──────────────────────╮
│ IP              │ MAC               │ Hostname             │ Vendor               │
├─────────────────┼───────────────────┼──────────────────────┼──────────────────────┤
│ 192.168.1.1     │ a4:91:b1:xx:xx:xx │ router.local         │ NETGEAR              │
│ 192.168.1.42    │ dc:a6:32:xx:xx:xx │ raspberrypi.local    │ Raspberry Pi Trading │
│ 192.168.1.101   │ 3c:cd:57:xx:xx:xx │ macbook.local        │ Apple, Inc.          │
╰─────────────────┴───────────────────┴──────────────────────┴──────────────────────╯

Total: 8 device(s)
```
