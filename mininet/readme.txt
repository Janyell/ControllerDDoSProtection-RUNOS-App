Valid user:
	h1 sh mininet/scapy/valid_user.sh

Invalid malicious user:
	h2 sh mininet/scapy/malicious_user.sh

Invalid DDoS user:
	h3 python mininet/scapy/ddos_user.py

Special cases: 
	Malicious user (for host):
		h4 python mininet/scapy/ddos_user_host.py


Flows dump:
sh ovs-ofctl -O Openflow13 dump-flows s1