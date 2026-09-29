from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap

packets = []

# DNS packet
dns_packet = (
    IP(src="192.168.1.25", dst="8.8.8.8")
    / UDP(sport=53000, dport=53)
    / DNS(rd=1, qd=DNSQR(qname="example.com"))
)

packets.append(dns_packet)

# Normal TCP packet
tcp_packet = (
    IP(src="192.168.1.25", dst="192.168.1.50")
    / TCP(sport=50000, dport=80)
)

packets.append(tcp_packet)

# HTTP packet containing deliberately fake sensitive data
http_data = (
    "GET /account?token=fake123 HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Authorization: Bearer fake-secret\r\n"
    "Cookie: sessionid=fake-session\r\n"
    "\r\n"
)

http_packet = (
    IP(src="192.168.1.25", dst="192.168.1.50")
    / TCP(sport=50001, dport=80)
    / Raw(load=http_data)
)

packets.append(http_packet)

wrpcap("authorized_lab.pcap", packets)

print("authorized_lab.pcap created successfully.")
print("Contains 3 synthetic packets for authorized testing.")