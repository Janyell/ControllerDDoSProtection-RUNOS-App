import sys, getopt, random
from scapy.all import *

def main(argv):
	n = 1
	# packet-count = 1
	t = 15
	h = 'malicious_user.py -n <ip-number> -t <host-number>'
	try:
		opts, args = getopt.getopt(argv,"hn:t:",["ip-number=", "host-number="])
	except getopt.GetoptError:
		print h
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print h
			sys.exit()
		elif opt in ("-n", "--ip-number"):
			n = int(arg)
		elif opt in ("-t", "--host-number"):
			t = int(arg)

	i = 0
	real_mac_src = "00:00:00:00:00:02"
	mac_dst_tmpl = "00:00:00:00:00:0"
	real_ip_src = "10.0.0.2"
	while i < n:
		ip_dst = RandIP()
		mac_dst = mac_dst_tmpl + format(random.randint(1, t), 'x')
		print (mac_dst)
		p = fuzz(Ether(src=real_mac_src, dst=mac_dst)/IP(src=real_ip_src, dst=ip_dst))
		sendp(p)
		i += 1

if __name__ == "__main__":
	main(sys.argv[1:])