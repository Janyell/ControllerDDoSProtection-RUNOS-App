from scapy.all import *

real_mac_src = "00:00:00:00:00:04"
real_ip_src = "10.0.0.4"
mac_dst = "00:00:00:00:00:10"
ip_dst = "10.0.0.10"
p = fuzz(Ether(src=real_mac_src, dst=mac_dst)/IP(src=real_ip_src, dst=ip_dst))
sendp(p, loop=1)