#!/usr/bin/env python3
from scapy.all import PcapReader, IP

path = "/home/mobisec/nfm-fase8/data/labeled/ngap_malformed/T3-03_up.pcap"
proto_counts = {}
n = 0
with PcapReader(path) as r:
    for pkt in r:
        n += 1
        if IP in pkt:
            proto = pkt[IP].proto
            proto_counts[proto] = proto_counts.get(proto, 0) + 1
        if n >= 2000:
            break
print(f"Scanned {n} packets")
print("IP proto field counts (6=TCP, 17=UDP, 1=ICMP, 132=SCTP):", proto_counts)
