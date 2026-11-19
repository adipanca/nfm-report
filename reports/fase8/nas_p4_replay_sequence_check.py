#!/usr/bin/env python3
"""P4 (follow-up to P1): now that nas_attack.py source is known, verify whether
nas_replay_n1 associations show the code's defining signature -- TWO DATA chunks
with IDENTICAL NGAP/NAS payload sent back-to-back in the SAME SCTP association --
versus bidding_down / nas_tamper_registration which should NOT (single attacker
send per association). Read-only: only reads existing pcaps, writes nothing.
"""
import pathlib
from collections import defaultdict
from scapy.all import PcapReader, IP

SCTP_PROTO = 132
CLASSES = {
    "bidding_down": "/home/mobisec/nfm-fase8/data/labeled/bidding_down",
    "nas_replay_n1": "/home/mobisec/nfm-fase8/data/labeled/nas_replay_n1",
    "nas_tamper_registration": "/home/mobisec/nfm-fase8/data/labeled/nas_tamper_registration",
}

def chunk_iter(payload, off=12):
    while off + 4 <= len(payload):
        ctype = payload[off]
        clen = int.from_bytes(payload[off+2:off+4], "big")
        if clen < 4:
            break
        yield ctype, payload[off:off+clen]
        pad = (4 - (clen % 4)) % 4
        off += clen + pad

for cls, d in CLASSES.items():
    files = sorted(pathlib.Path(d).glob("*.pcap"))
    assoc_data_counts = []
    assoc_dup_flags = []
    for f in files:
        # group by symmetric endpoint pair like the production splitter does
        packets_by_assoc = defaultdict(list)
        with PcapReader(str(f)) as r:
            for pkt in r:
                if IP not in pkt or pkt[IP].proto != SCTP_PROTO:
                    continue
                payload = bytes(pkt[IP].payload)
                if len(payload) < 16:
                    continue
                vtag = payload[4:8]
                sp, dp = payload[0:2], payload[2:4]
                key = tuple(sorted([(pkt[IP].src, sp), (pkt[IP].dst, dp)]))
                packets_by_assoc[key].append(payload)
        for key, pkts in packets_by_assoc.items():
            data_payloads = []
            for payload in pkts:
                for ctype, chunk in chunk_iter(payload):
                    if ctype == 0 and len(chunk) >= 16:  # DATA chunk
                        ngap_part = chunk[16:]
                        data_payloads.append(ngap_part[:40])
            if data_payloads:
                assoc_data_counts.append(len(data_payloads))
                assoc_dup_flags.append(len(set(data_payloads)) < len(data_payloads))
    n = len(assoc_data_counts)
    n_dup = sum(assoc_dup_flags)
    avg_data = sum(assoc_data_counts) / n if n else 0
    from collections import Counter
    dist = Counter(assoc_data_counts)
    print(f"{cls}: {n} associations analyzed, avg DATA-chunks/assoc={avg_data:.2f}, "
          f"associations with >=1 duplicate-payload DATA pair={n_dup} ({100*n_dup/n:.0f}%)" if n else f"{cls}: 0 associations")
    print(f"    DATA-chunk-count distribution: {dict(sorted(dist.items()))}")
