import sys
from scapy.all import *

print "Field Values of packet sent"
l2 = Ether(src=RandMAC(), dst="ff:ff:ff:ff:ff:ff")
l3 = IP(src=RandIP(), dst=RandIP())
l4_tcp = TCP()
l4_udp = UDP()
l4 = l4_tcp
payload = "test payload"
p = fuzz(l2/l3/l4/payload)
ls(p)

print "Sending Packets in 0.3 second intervals for timeout of 4 sec"
send(p, loop=1)
