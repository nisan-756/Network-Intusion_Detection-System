#!/usr/bin/env python3
from scapy.all import *
import random
import time

def create_sample_pcap(filename="sample_traffic.pcap"):
    # Create a list to store packets
    packets = []
    
    # Generate normal traffic
    print("Generating normal traffic...")
    for i in range(50):
        # Normal HTTP traffic
        pkt = Ether()/IP(src=f"192.168.1.{random.randint(2, 50)}", dst="93.184.216.34")/TCP(dport=80)
        packets.append(pkt)
        
        # Normal HTTPS traffic
        pkt = Ether()/IP(src=f"192.168.1.{random.randint(2, 50)}", dst="93.184.216.34")/TCP(dport=443)
        packets.append(pkt)
        
        # Normal DNS traffic
        pkt = Ether()/IP(src=f"192.168.1.{random.randint(2, 50)}", dst="8.8.8.8")/UDP(dport=53)
        packets.append(pkt)
    
    # Generate suspicious traffic patterns
    print("Generating suspicious traffic...")
    
    # 1. Blacklisted IP traffic
    pkt = Ether()/IP(src="192.168.1.100", dst="192.168.1.1")/TCP(dport=80)
    packets.append(pkt)
    
    # 2. DoS-like traffic (many packets from single source)
    for i in range(150):
        pkt = Ether()/IP(src="10.0.0.99", dst="192.168.1.1")/TCP(dport=80)
        packets.append(pkt)
    
    # 3. Unusual port traffic
    pkt = Ether()/IP(src="192.168.1.25", dst="192.168.1.1")/TCP(dport=31337)
    packets.append(pkt)
    pkt = Ether()/IP(src="192.168.1.30", dst="192.168.1.1")/TCP(dport=4444)
    packets.append(pkt)
    
    # Write packets to PCAP file
    print(f"Writing {len(packets)} packets to {filename}...")
    wrpcap(filename, packets)
    print(f"Sample PCAP file '{filename}' created successfully!")

if __name__ == "__main__":
    create_sample_pcap()