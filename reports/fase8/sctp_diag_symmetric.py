#!/usr/bin/env python3
"""Check symmetric (bidirectional) association count for SCTP episodes, to
validate the split-key design before implementing the real splitter."""
import struct
from scapy.all import PcapReader, IP

FILES = [
    "/home/mobisec/nfm-fase8/data/labeled/bidding_down/NB2-BID-e1_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/bidding_down/NB2-BID-e5_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/ngap_malformed/T3-03_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/ngap_malformed/T3-03-e1_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/nas_replay_n1/NB2-REPLAY-e1_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/nas_tamper_registration/NB2-TAMPER-e1_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/ngap_ngsetup_flood/T3-02_up.pcap",
]

for path in FILES:
    assoc_sym = set()
    assoc_dir = set()
    n_pkts = 0
    try:
        with PcapReader(path) as r:
            for pkt in r:
                if IP in pkt and pkt[IP].proto == 132:
                    n_pkts += 1
                    payload = bytes(pkt[IP].payload)
                    if len(payload) >= 4:
                        sp, dp = struct.unpack(">HH", payload[0:4])
                        ep1 = (pkt[IP].src, sp)
                        ep2 = (pkt[IP].dst, dp)
                        assoc_dir.add((ep1, ep2))
                        assoc_sym.add(tuple(sorted([ep1, ep2])))
    except FileNotFoundError:
        print(f"{path}: NOT FOUND")
        continue
    print(f"{path}")
    print(f"  SCTP packets: {n_pkts}  directional-pairs: {len(assoc_dir)}  symmetric-pairs: {len(assoc_sym)}")
