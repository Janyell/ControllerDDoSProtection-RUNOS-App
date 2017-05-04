import sys, getopt
from scapy.all import *

def main(argv):
	n = 1
	c = 1
	h = 'malicious_user.py -n <ip-number> -c <packet-count>'
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
	real_mac_src = "00:00:00:00:00:02"
	# broadcast_mac_dst="ff:ff:ff:ff:ff:ff"
	real_ip_src = "10.0.0.2"
	while i < n:
		mac_dst = RandMAC()
		ip_dst = RandIP()
		p = fuzz(Ether(src=real_mac_src, dst=mac_dst)/IP(src=real_ip_src, dst=ip_dst))
		sendp(p, count=c)
		i += 1

if __name__ == "__main__":
	main(sys.argv[1:])