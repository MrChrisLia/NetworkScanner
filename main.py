#!/usr/bin/env python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from tabulate import tabulate
import scapy.all as scapy
import socket
import argparse
import requests


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip", help="Target IP / Subnet")
    arguments = parser.parse_args()
    return arguments


def scan_ip(IP):
    print("Scanning " + str(IP))
    arp_request = scapy.ARP(pdst=IP)  # ARP request to find who has the Destination IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Flood the network by configuring the request to 6 ff
    arp_request_broadcast = broadcast/arp_request  # Custom packet we created. Ether/ARP
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    clients_list = [str(IP)]
    for element in answered_list:
        try:
            hostname = socket.gethostbyaddr(element[1].psrc)[0]  # Find the hostname
        except socket.herror:
            hostname = "Unknown Host"
        try:
            mac_url = "http://macvendors.co/api/%s"  # Uses Macvendor's API to find the vendor
            r = requests.get(mac_url % str(element[1].hwsrc))
            vendor = str(r.json()["result"]["company"])
        except:
            vendor = "Unknown Vendor"
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc, "HOSTNAME": hostname, "VENDOR": vendor}
        clients_list.append(client_dict)  # Populate the dictionary
    return clients_list  # List of dictionaries


def print_scan_results(results_list):
    print("Results of " + str(results_list[0]) + " scan:")  # The 0 index is the IP scanned
    data = results_list[1:]
    print(tabulate(data, headers={"foo": data[1:]}))


if __name__ == "__main__":
    arguments = get_arguments()
    scan_result = scan_ip(arguments.ip)  # clients_list data from CLI
    print_scan_results(scan_result)
