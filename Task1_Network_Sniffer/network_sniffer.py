#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
Description: Captures and analyzes network packets in real-time, extracting
             IP addresses, protocols, port numbers, and payload data.
"""

import sys
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def format_payload(payload_bytes, max_len=64):
    """
    Safely converts raw payload bytes into readable ASCII text.
    Replaces non-printable characters with dots (.) for security/readability.
    """
    try:
        # Decode as ASCII, replacing unprintable bytes
        readable_text = ''.join(
            chr(b) if 32 <= b <= 126 else '.' for b in payload_bytes[:max_len]
        )
        return readable_text
    except Exception:
        return "[Non-printable Binary Data]"

def packet_callback(packet):
    """
    Callback function executed for every captured packet.
    Extracts Layer 3 (IP), Layer 4 (TCP/UDP/ICMP), and Layer 7 (Payload).
    """
    # We only care about IP packets for this sniffer
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol_num = packet[IP].proto
    ttl = packet[IP].ttl

    # Identify the Transport Layer Protocol
    protocol_name = "OTHER"
    src_port = "-"
    dst_port = "-"

    if packet.haslayer(TCP):
        protocol_name = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        protocol_name = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        protocol_name = "ICMP"

    # Print Packet Header Information
    print("=" * 80)
    print(f"[{timestamp}] Protocol: {protocol_name:<5} | TTL: {ttl}")
    if src_port != "-":
        print(f"Source:      {src_ip}:{src_port}")
        print(f"Destination: {dst_ip}:{dst_port}")
    else:
        print(f"Source:      {src_ip}")
        print(f"Destination: {dst_ip}")

    # Inspect and Display the Payload (Layer 7)
    if packet.haslayer(Raw):
        raw_payload = packet[Raw].load
        payload_size = len(raw_payload)
        preview = format_payload(raw_payload)
        print(f"Payload ({payload_size} bytes): {preview}")
    else:
        print("Payload: [No data payload / Handshake only]")

def start_sniffer(interface=None, packet_count=0):
    """
    Initializes the Scapy sniffing loop.
    :param interface: Specific network interface (e.g., 'eth0', 'wlan0'). If None, default is used.
    :param packet_count: Number of packets to capture (0 = infinite).
    """
    print(f"[*] Starting Network Sniffer on interface: {interface or 'Default'}")
    print("[*] Press Ctrl+C to stop capturing...\n")

    try:
        # sniff() captures packets and hands each one to prn (packet_callback)
        # store=False prevents keeping packets in RAM, avoiding memory leaks on long runs
        sniff(iface=interface, prn=packet_callback, store=False, count=packet_count)
    except PermissionError:
        print("\n[!] Error: Root privileges required. Run with 'sudo'.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped by user. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    # If an interface argument is passed (e.g., python3 network_sniffer.py eth0), use it
    selected_iface = sys.argv[1] if len(sys.argv) > 1 else None
    start_sniffer(interface=selected_iface)

