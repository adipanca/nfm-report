from scapy.all import PcapReader, IP

path = "/home/mobisec/nfm-fase8/data/labeled/pfcp_session_delete/T2-01_up.pcap"
pairs = set()
with PcapReader(path) as r:
    for pkt in r:
        if IP in pkt:
            pairs.add((pkt[IP].src, pkt[IP].dst))
print("Unique (src,dst) pairs in raw capture:", pairs)
