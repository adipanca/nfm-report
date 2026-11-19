#!/usr/bin/env python3
"""SCTP diagnosis: read raw SCTP common-header fields (src/dst port,
verification tag) directly from a few representative pcaps, to check whether
each 'episode' file genuinely contains ONE SCTP association (single
verification tag / 4-tuple) or MULTIPLE associations that PcapSplitter's
protocol-unaware connection-mode would have wrongly merged into one output
file (which would explain the 1-row-per-episode outcome as an artifact, not
a true reflection of the data)."""
from scapy.all import PcapReader, IP
import struct

FILES = [
    "/home/mobisec/nfm-fase8/data/labeled/bidding_down/NB2-BID-e1_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/bidding_down/NB2-BID-e5_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/ngap_malformed/T3-03_up.pcap",
    "/home/mobisec/nfm-fase8/data/labeled/nas_tamper_registration/NB2-TAMPER-e1_up.pcap"
    if False else "/home/mobisec/nfm-fase8/data/labeled/pfcp_session_delete/T2-01-e1_up.pcap",
]

for path in FILES:
    print(f"=== {path} ===")
    assoc = set()  # (src_port, dst_port, verification_tag)
    n_pkts = 0
    n_sctp = 0
    try:
        with PcapReader(path) as r:
            for pkt in r:
                n_pkts += 1
                if IP in pkt and pkt[IP].proto == 132:
                    n_sctp += 1
                    payload = bytes(pkt[IP].payload)
                    if len(payload) >= 8:
                        src_port, dst_port = struct.unpack(">HH", payload[0:4])
                        vtag = struct.unpack(">I", payload[4:8])[0]
                        assoc.add((src_port, dst_port, vtag))
    except FileNotFoundError:
        print("  (file not found, skipping)")
        continue
    print(f"  total packets: {n_pkts}, SCTP packets: {n_sctp}")
    print(f"  distinct (src_port,dst_port,verification_tag) associations: {len(assoc)}")
    for a in list(assoc)[:5]:
        print(f"    {a}")
