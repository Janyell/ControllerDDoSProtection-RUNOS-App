import sys, getopt
from scapy.all import *

def main(argv):
	n = 1
	# packet-count = 1
	h = 'malicious_user.py -n <ip-number>'
	try:
		opts, args = getopt.getopt(argv,"hn:c:",["ip-number="])
	except getopt.GetoptError:
		print h
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print h
			sys.exit()
		elif opt in ("-n", "--ip-number"):
			n = int(arg)

	real_mac_src = "00:00:00:00:00:02"
	real_ip_src = "10.0.0.2"

	mac_dst = RandMAC()
	ip_dst = RandIP()
	p = fuzz(Ether(src=real_mac_src, dst=mac_dst)/IP(src=real_ip_src, dst=ip_dst))
	sendp(p, count=n)

if __name__ == "__main__":
	main(sys.argv[1:])