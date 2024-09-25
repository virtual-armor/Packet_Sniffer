#!/usr/bin/env python
import scapy.all as sc
from scapy.layers import http

def sniff(interface):
	#For each packet captured, execute the process_packet function (via prn)
	#Store decides whether to store  packets in memory.
	sc.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		print(packet)

sniff("eth0")
