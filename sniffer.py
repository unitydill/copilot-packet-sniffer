"""
Copilot-Assisted Packet Sniffer
For authorized educational/lab use only.

This program captures only explicitly allowed interfaces or reads
from an authorized PCAP file. Sensitive information is redacted
before being displayed.
"""

import argparse
import re
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw


# -------------------------
# REDACTION FUNCTIONS
# -------------------------

def redact_ip(ip):
    """Mask the final part of an IPv4 address."""
    if not ip:
        return "N/A"

    parts = ip.split(".")

    if len(parts) == 4:
        return ".".join(parts[:3]) + ".xxx"

    return "[REDACTED_IP]"


def redact_sensitive(text):
    """Remove potentially sensitive information before output."""

    if not text:
        return text

    # Email addresses
    text = re.sub(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        '[REDACTED_EMAIL]',
        text
    )

    # Authorization headers
    text = re.sub(
        r'(?i)(Authorization:\s*)[^\r\n]+',
        r'\1[REDACTED]',
        text
    )

    # Cookies
    text = re.sub(
        r'(?i)(Cookie:\s*)[^\r\n]+',
        r'\1[REDACTED]',
        text
    )

    # Passwords, tokens, API keys, session values
    text = re.sub(
        r'(?i)(password|passwd|token|api_key|apikey|sessionid)=([^&\s]+)',
        r'\1=[REDACTED]',
        text
    )

    return text


# -------------------------
# PACKET PARSING
# -------------------------

def process_packet(packet):
    """Decode supported packet information and print safe output."""

    result = []

    # IP information
    if packet.haslayer(IP):
        src = redact_ip(packet[IP].src)
        dst = redact_ip(packet[IP].dst)

        result.append(f"Source IP: {src}")
        result.append(f"Destination IP: {dst}")

    # TCP
    if packet.haslayer(TCP):
        result.append("Protocol: TCP")
        result.append(f"Source Port: {packet[TCP].sport}")
        result.append(f"Destination Port: {packet[TCP].dport}")

    # UDP
    elif packet.haslayer(UDP):
        result.append("Protocol: UDP")
        result.append(f"Source Port: {packet[UDP].sport}")
        result.append(f"Destination Port: {packet[UDP].dport}")

    # DNS query
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):

        try:
            domain = packet[DNSQR].qname.decode(
                "utf-8",
                errors="ignore"
            ).rstrip(".")

            result.append(f"DNS Query: {domain}")

        except Exception:
            result.append("DNS Query: [Unable to decode]")

    # HTTP-like unencrypted payload
    if packet.haslayer(Raw):

        try:
            payload = packet[Raw].load.decode(
                "utf-8",
                errors="ignore"
            )

            if payload.startswith(
                ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")
            ):

                lines = payload.splitlines()

                if lines:
                    request_line = redact_sensitive(lines[0])
                    result.append(f"HTTP Request: {request_line}")

                for line in lines:

                    lower = line.lower()

                    if lower.startswith("host:"):
                        result.append(
                            f"HTTP {redact_sensitive(line)}"
                        )

                    elif lower.startswith("authorization:"):
                        result.append(
                            f"HTTP {redact_sensitive(line)}"
                        )

                    elif lower.startswith("cookie:"):
                        result.append(
                            f"HTTP {redact_sensitive(line)}"
                        )

        except Exception:
            pass

    # Only display packets we successfully decoded
    if result:
        print("\n" + "=" * 50)

        for item in result:
            print(redact_sensitive(item))


# -------------------------
# SAFE CAPTURE
# -------------------------

def capture_packets(interface, packet_filter, count):
    """
    Capture packets only from an explicitly selected interface.
    """

    allowed_interfaces = [
        "lo",
        "lo0",
        "Loopback Pseudo-Interface 1"
    ]

    if interface not in allowed_interfaces:
        print("\nSAFETY BLOCK:")
        print("This program only allows approved loopback interfaces.")
        print("Use an authorized lab interface only after adding it")
        print("to the allowlist.")
        return

    print("\nAuthorized Packet Sniffer")
    print("-------------------------")
    print(f"Interface: {interface}")
    print(f"Filter: {packet_filter or 'None'}")
    print(f"Packet limit: {count}")
    print("\nWaiting for authorized traffic...\n")

    sniff(
        iface=interface,
        prn=process_packet,
        count=count,
        filter=packet_filter,
        store=False
    )


def read_pcap(filename, count):
    """
    Safely analyze packets from an authorized PCAP file.
    """

    print(f"\nReading authorized PCAP: {filename}")

    packets = rdpcap(filename)

    for packet in packets[:count]:
        process_packet(packet)


# -------------------------
# COMMAND LINE INTERFACE
# -------------------------

def main():

    parser = argparse.ArgumentParser(
        description="Ethical educational packet sniffer"
    )

    parser.add_argument(
        "--iface",
        help="Approved interface (loopback recommended)"
    )

    parser.add_argument(
        "--pcap",
        help="Read packets from an authorized PCAP file"
    )

    parser.add_argument(
        "--filter",
        default=None,
        help='BPF filter such as "tcp port 80" or "udp port 53"'
    )

    parser.add_argument(
        "--count",
        type=int,
        default=25,
        help="Number of packets to process (default: 25)"
    )

    args = parser.parse_args()

    # Ethical guardrail
    if args.count > 25:
        print("Safety limit: maximum capture is 25 packets.")
        args.count = 25

    if args.pcap:
        read_pcap(args.pcap, args.count)

    elif args.iface:
        capture_packets(
            args.iface,
            args.filter,
            args.count
        )

    else:
        print("\nNo capture source selected.")
        print("For safety, this program will NOT sniff all interfaces.")
        print("\nExamples:")
        print('python sniffer.py --iface "Loopback Pseudo-Interface 1"')
        print("python sniffer.py --pcap authorized_lab.pcap")


if __name__ == "__main__":
    main()