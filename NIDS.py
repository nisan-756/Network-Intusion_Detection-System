import argparse
import logging
from collections import defaultdict, deque
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# Configuration
THRESHOLD_PACKETS = 100  # Packets per window for DoS detection
TIME_WINDOW = 10         # Seconds for DoS time window
BLACKLISTED_IPS = {"192.168.1.100", "10.0.0.5"}  # Add your blacklisted IPs
ALLOWED_PORTS = {80, 443, 22, 53}  # HTTP, HTTPS, SSH, DNS

# Global variables for tracking
ip_packets = defaultdict(lambda: deque(maxlen=1000))
detected_ips = set()

def setup_logging():
    logging.basicConfig(
        filename='nids.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def analyze_packet(packet):
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    current_time = time.time()

    # Rule 1: Check blacklisted IPs
    if ip_src in BLACKLISTED_IPS:
        alert = f"Blacklisted IP detected: {ip_src} -> {ip_dst}"
        print(f"ALERT: {alert}")
        logging.warning(alert)
        return

    # Rule 2: DoS detection (excessive packets from single source)
    ip_packets[ip_src].append(current_time)
    
    # Clean old timestamps and check threshold
    while ip_packets[ip_src] and ip_packets[ip_src][0] < current_time - TIME_WINDOW:
        ip_packets[ip_src].popleft()
    
    if len(ip_packets[ip_src]) > THRESHOLD_PACKETS and ip_src not in detected_ips:
        alert = f"Possible DoS attack from {ip_src} ({len(ip_packets[ip_src])} packets in {TIME_WINDOW}s)"
        print(f"ALERT: {alert}")
        logging.warning(alert)
        detected_ips.add(ip_src)

    # Rule 3: Unusual port detection
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        protocol = "TCP"
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        protocol = "UDP"
    else:
        return

    if dst_port not in ALLOWED_PORTS:
        alert = f"Unusual port usage: {ip_src} -> {ip_dst}:{dst_port} ({protocol})"
        print(f"ALERT: {alert}")
        logging.warning(alert)

def main():
    parser = argparse.ArgumentParser(description="Basic Network Intrusion Detection System")
    parser.add_argument('-i', '--interface', help='Network interface for live capture')
    parser.add_argument('-f', '--file', help='PCAP file for offline analysis')
    args = parser.parse_args()

    setup_logging()
    print("Starting NIDS...")
    logging.info("NIDS started")

    if args.file:
        print(f"Analyzing pcap file: {args.file}")
        sniff(offline=args.file, prn=analyze_packet, store=0)
    elif args.interface:
        print(f"Monitoring interface: {args.interface}")
        sniff(iface=args.interface, prn=analyze_packet, store=0)
    else:
        print("Please specify either an interface (-i) or pcap file (-f)")
        sys.exit(1)

if __name__ == "__main__":
    main()
