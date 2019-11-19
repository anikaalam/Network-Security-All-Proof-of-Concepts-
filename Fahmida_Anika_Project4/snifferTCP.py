#!/usr/bin/python
from scapy.all import *
print("Sniffing TCP on port 23")

def printpkt(pkt):
	pkt.show()

pkt = sniff(filter = 'tcp port 23', prn=printpkt)

