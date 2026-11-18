#!/usr/bin/env python3
"""W1 verification: per-class file count, raw packet count, total size, for
the freshly extracted data/labeled/ (23-class VM snapshot). Uses RawPcapReader
(no protocol dissection) for speed.
"""
import csv
import pathlib

from scapy.utils import RawPcapReader

LABELED_DIR = pathlib.Path("/home/mobisec/nfm-fase8/data/labeled")
OUT_CSV = pathlib.Path("/home/mobisec/nfm-fase8/reports/fase8/w1_class_distribution.csv")


def count_packets(path):
    n = 0
    for _ in RawPcapReader(str(path)):
        n += 1
    return n


def main():
    rows = []
    for label_dir in sorted(LABELED_DIR.iterdir()):
        if not label_dir.is_dir():
            continue
        pcaps = sorted(label_dir.glob("*.pcap"))
        n_files = len(pcaps)
        total_packets = 0
        total_bytes = 0
        for p in pcaps:
            total_packets += count_packets(p)
            total_bytes += p.stat().st_size
        rows.append({
            "label": label_dir.name,
            "n_pcap_files": n_files,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
        })
        print(f"{label_dir.name:30s} files={n_files:4d}  packets={total_packets:10d}  bytes={total_bytes:12d}")

    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["label", "n_pcap_files", "total_packets", "total_bytes"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nTotal classes: {len(rows)}")
    print(f"Saved -> {OUT_CSV}")


if __name__ == "__main__":
    main()
