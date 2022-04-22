#!/bin/bash

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import scapy.all as scapy
import socket
import optparse

# Use scapy.ls(scapy.method_name_here()) to find a list of fields to set for the method
# Example scape.ls(scapy.Ether()) to find the fields for scapy.Ether()
# Use .show() to show the details of the frames/packets
# hwsrc = mac address (hardware source)
# psrc = source port


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--ip", dest="ip", help="Target IP / IP range.")
    options, arguments = parser.parse_args()
    return options


def scan(IP):
    arp_request = scapy.ARP(pdst=IP)  # ARP request to find who has the Destination IP
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Flood the network by configuring the request to 6 ff
    arp_request_broadcast = broadcast/arp_request  # Custom packet we created. Ether/ARP
    answered_list = scapy.srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    clients_list = [str(IP)]
    for element in answered_list:
        try:
            hostname = socket.gethostbyaddr(element[1].psrc)
            client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc, "hostname": hostname[0]}  # dictionary of keys IP and MAC
            clients_list.append(client_dict)  # Populate the dictionary
        except socket.herror:
            client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc, "hostname": "Unknown host"}  # dictionary of keys IP and MAC
            clients_list.append(client_dict)


    return clients_list  # List of dictionaries


def print_scan_results(results_list):
    print("Results of " + str(results_list[0]) + " scan:")  # The 0 index is the IP scanned
    print("IP\t\t\t MAC ADDRESS\t\t\t HOSTNAME \t\t")
    print("----------------------------------------------------------------------")
    for client in results_list[1:]:
        print(client["IP"] + "\t\t" + client["MAC"] + "\t\t" + str(client["hostname"]))


options = get_arguments()
scan_result = scan(options.ip)  # clients_list data from CLI
print_scan_results(scan_result)
