#!/usr/bin/env python3

import argparse
import csv
import ipaddress
import json
import platform
import socket
import subprocess
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

WINDOWS = platform.system() == "Windows"

import requests


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def get_arguments():
    parser = argparse.ArgumentParser(
        description="Network scanner — discovers devices on your local network"
    )
    parser.add_argument(
        "-i", "--ip", dest="ip",
        help="Target subnet in CIDR notation (e.g. 192.168.1.0/24). "
             "Auto-detects local /24 if omitted.",
    )
    parser.add_argument(
        "-p", "--ports", dest="ports", action="store_true",
        help="Scan common ports on each discovered device",
    )
    parser.add_argument(
        "-o", "--output", dest="output",
        help="Save results to a file — supports .json and .csv",
    )
    parser.add_argument(
        "--threads", dest="threads", type=int, default=200,
        help="Worker threads for ping sweep and port scanning (default: 200)",
    )
    return parser.parse_args()


def auto_detect_subnet():
    # Route a dummy UDP socket to discover which local IP the OS would use.
    # No packets are actually sent.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return str(ipaddress.ip_interface(f"{local_ip}/24").network)
    except Exception:
        return None


def ping_host(ip):
    # Fire-and-forget ping — we only care that it triggers ARP resolution.
    flag = "-n" if WINDOWS else "-c"
    try:
        subprocess.run(
            ["ping", flag, "1", str(ip)],
            capture_output=True,
            timeout=2,
        )
    except subprocess.TimeoutExpired:
        pass


def normalize_mac(mac):
    sep = "-" if "-" in mac else ":"
    return ":".join(part.zfill(2) for part in mac.split(sep))


def read_arp_table(network):
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    devices, seen = [], set()
    for line in result.stdout.splitlines():
        if WINDOWS:
            # Windows format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})', line)
        else:
            # macOS/Linux format: "hostname (ip) at mac on iface ..."
            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+) on', line)
        if not match:
            continue
        ip, raw_mac = match.groups()
        if ip in seen or len(raw_mac) < 11:  # skip incomplete entries
            continue
        try:
            if ipaddress.ip_address(ip) in network:
                devices.append((ip, normalize_mac(raw_mac)))
                seen.add(ip)
        except ValueError:
            pass
    return devices


def arp_scan(subnet, threads):
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(ping_host, hosts)
    return read_arp_table(network)


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "N/A"


def get_mac_vendor(mac):
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return "Unknown"


def check_port(ip, port, timeout=0.5):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((ip, port)) == 0 else None
    except Exception:
        return None


def scan_ports(ip, threads):
    open_ports = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_port, ip, port): port for port in COMMON_PORTS}
        for future in as_completed(futures):
            result = future.result()
            if result is not None:
                open_ports.append(result)
    return sorted(open_ports)


def enrich_device(ip, mac, do_ports, threads):
    hostname = resolve_hostname(ip)
    vendor = get_mac_vendor(mac)
    device = {"IP": ip, "MAC": mac, "Hostname": hostname, "Vendor": vendor}
    if do_ports:
        ports = scan_ports(ip, threads)
        device["Open Ports"] = (
            ", ".join(f"{p}/{COMMON_PORTS[p]}" for p in ports) if ports else "None"
        )
    return device


COLS = [("IP", 16), ("MAC", 18), ("Hostname", 28), ("Vendor", 24)]
PORT_COL = ("Open Ports", 36)


def _cols(do_ports):
    return COLS + ([PORT_COL] if do_ports else [])


def _separator(do_ports):
    return "  ".join("─" * w for _, w in _cols(do_ports))


def _row(device, do_ports):
    return "  ".join(str(device.get(k, "")).ljust(w) for k, w in _cols(do_ports))


def run_scan(subnet, do_ports, threads):
    print(f"Scanning {subnet} ...")
    hosts = arp_scan(subnet, threads)

    if not hosts:
        print("No devices found.")
        return []

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\nFound {len(hosts)} device(s) — {subnet}  {ts}\n")

    sep = _separator(do_ports)
    header = "  ".join(k.ljust(w) for k, w in _cols(do_ports))
    print(sep)
    print(header)
    print(sep)

    devices = []
    with ThreadPoolExecutor(max_workers=min(len(hosts), 20)) as executor:
        futures = {
            executor.submit(enrich_device, ip, mac, do_ports, threads): ip
            for ip, mac in hosts
        }
        for future in as_completed(futures):
            device = future.result()
            devices.append(device)
            print(_row(device, do_ports))

    print(sep)
    print(f"\nTotal: {len(devices)} device(s)")
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["IP"]))


def save_results(devices, path):
    if path.endswith(".json"):
        with open(path, "w") as f:
            json.dump(devices, f, indent=2)
        print(f"Saved to {path}")
    elif path.endswith(".csv"):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=devices[0].keys())
            writer.writeheader()
            writer.writerows(devices)
        print(f"Saved to {path}")
    else:
        print(f"Unknown format for '{path}' — use .json or .csv")


if __name__ == "__main__":
    args = get_arguments()

    subnet = args.ip
    if not subnet:
        subnet = auto_detect_subnet()
        if not subnet:
            print("Could not detect local subnet. Use -i to specify one.")
            sys.exit(1)
        print(f"Auto-detected subnet: {subnet}")

    devices = run_scan(subnet, args.ports, args.threads)

    if args.output and devices:
        save_results(devices, args.output)
