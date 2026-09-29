# Copilot-Assisted Packet Sniffer: Seeing the Network Ethically

## Overview

This project is an educational packet sniffer written in Python using Scapy. The program demonstrates how network packets can be captured and analyzed while using ethical safeguards to protect sensitive information.

The sniffer can identify IP, TCP, UDP, DNS, and unencrypted HTTP traffic. Sensitive information is redacted before it is displayed.

## Ethical Use

This project is intended only for authorized educational use.

Traffic should only be captured from:

- My own computer
- Loopback interfaces
- Instructor-provided lab environments
- Authorized PCAP files

The program does not automatically capture traffic from all network interfaces. An approved interface or PCAP file must be explicitly selected.

## Requirements

- Python 3.10 or newer
- Scapy

Install Scapy:

python -m pip install scapy

## Running the Program

Display the safe-use instructions:

python sniffer.py

Analyze an authorized PCAP:

python sniffer.py --pcap authorized_lab.pcap

Capture up to 25 packets from an approved loopback interface:

python sniffer.py --iface "Loopback Pseudo-Interface 1"

Example DNS filter:

python sniffer.py --iface "Loopback Pseudo-Interface 1" --filter "udp port 53"

Example HTTP filter:

python sniffer.py --iface "Loopback Pseudo-Interface 1" --filter "tcp port 80"

## Packet Decoding

The program can identify:

- IP source and destination addresses
- TCP traffic
- UDP traffic
- Source and destination ports
- DNS queries
- Unencrypted HTTP request information

## Redaction

Sensitive information is redacted before output.

Examples include:

- IP addresses: 192.168.1.25 becomes 192.168.1.xxx
- Email addresses become [REDACTED_EMAIL]
- Authorization headers become [REDACTED]
- Cookies become [REDACTED]
- Passwords become [REDACTED]
- Tokens and session identifiers become [REDACTED]

## Safety Controls

The program includes several ethical safeguards:

- Maximum capture limit of 25 packets
- Interface allowlist
- No automatic sniffing of all interfaces
- Sensitive-data redaction
- Authorized PCAP analysis mode

## Testing

Unit tests verify that sensitive information is properly redacted.

Run the tests with:

python -m unittest discover tests

The project includes tests for:

- IP address masking
- Email redaction
- Password redaction
- Token redaction
- Authorization header redaction

## AI Use Policy

GitHub Copilot may be used for:

- Boilerplate code
- CLI argument parsing
- JSON formatting
- Unit test scaffolding

GitHub Copilot must not be used for:

- Capturing other people's traffic
- Bypassing operating system permissions
- Creating stealth features
- Persistence
- Hiding packet-sniffing activity

All AI-assisted code must maintain an interface or PCAP allowlist and sensitive-data redaction. If live capture permissions are unavailable, PCAP analysis should be used instead.

## Disclaimer

This software was created for an authorized cybersecurity lab and educational purposes only.