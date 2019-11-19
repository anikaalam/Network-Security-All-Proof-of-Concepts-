from scapy.all import *
import sys
#a.ttl = 1
a = IP()
a.dst = sys.argv[1]
a.ttl = 1
b = ICMP()
#a.ttl = i
pkt = a/b
reply = sr1(pkt,verbose=0)
for i in range(1,100):
	a.ttl = i
	pkt = a/b
	reply = sr1(pkt,verbose=0)
	if reply is None:
		break
	elif reply.type == 0:
		print("Destination Reached"+ reply.src)
		break
	else:
		print("%d hops away:" % i,reply.src)
	



