#!/usr/bin/env python3
import scapy.all as scapy
import argparse


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter your target address or your gateway address to scan all subnet")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(op=1, pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    scan_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return scan_list


def display_container(scan_display):
    client_list = []
    for element in scan_display:
        client_dict = {
            "IP":element[1].psrc,
            "MAC":element[1].hwsrc
        }
        client_list.append(client_dict)
    return client_list


def display_result(client_result):
    print(("-"*55) + "\n IP ADDRESS \t\t\t MAC ADDRESS \n" + ("-"*55))
    for element in client_result:
        print(element["IP"] + "\t\t\t" + element["MAC"])



opt = get_args()
scan_target = scan(opt.target)
display_cont = display_container(scan_target)
display_result(display_cont)




