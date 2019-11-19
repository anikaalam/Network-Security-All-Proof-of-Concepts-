#!/usr/bin/python
from scapy.all import *
print("Sniffing ICMP and subnet packets")

def printpkt(pkt):
	pkt.show()

pkt = sniff(filter = 'ICMP', prn=printpkt)
pkt = sniff(filter = 'net 173.194.208.0/24', prn=printpkt)

