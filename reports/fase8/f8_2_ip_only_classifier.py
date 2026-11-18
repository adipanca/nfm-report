#!/usr/bin/env python3
"""F8.2 gate: IP-only classifier before vs after IP masking.

Risk (from audit): 9 "container-sourced" classes (PFCP/NGAP/SBI/TLS, tiers 2-5)
all originate from a tiny set of fixed container IPs (172.22/23.0.50 etc).
If src/dst IP alone can near-perfectly predict the class, a model that sees
IP addresses would memorize infrastructure identity instead of learning
attack behavior.

This script:
  1. Reads every labeled PCAP under data/labeled/<label>/*.pcap with scapy and
     records (src_ip, dst_ip, label) per packet -> "before masking" dataset.
  2. Writes masked copies of every PCAP to data/labeled_masked/<label>/*.pcap
     where every packet's IP.src/IP.dst is rewritten to ONE global constant
     pair (same constant regardless of original class/label), simulating the
     IP-masking defense described in FASE8.md F8.2. Re-reads those masked
     PCAPs -> "after masking" dataset.
  3. Trains a DecisionTreeClassifier using ONLY (src_ip, dst_ip) as features
     to predict label, before vs after masking, with a fixed seed and a
     stratified train/test split. Reports accuracy on held-out test rows and
     compares against the majority-class baseline.

GATE PASS condition (per FASE8.md F8.2):
  - before-masking accuracy is high (model CAN cheat using IP)
  - after-masking accuracy collapses to ~majority-class baseline (+ small margin)
"""
import json
import pathlib
import random
import sys

import numpy as np
from scapy.all import IP, PcapReader, PcapWriter
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
LABELED_DIR = REPO_ROOT / "data" / "labeled"
MASKED_DIR = REPO_ROOT / "data" / "labeled_masked"
REPORT_DIR = REPO_ROOT / "reports" / "fase8"

MASK_SRC = "10.255.255.1"
MASK_DST = "10.255.255.2"

# 9 "container-sourced" classes flagged by the audit (tiers 2-5: PFCP/NGAP/SBI/TLS)
CONTAINER_CLASSES = {
    "pfcp_session_delete",
    "pfcp_session_modify",
    "pfcp_estab_flood",
    "pfcp_rule_misconfig",
    "ngap_ngsetup_flood",
    "ngap_malformed",
    "sbi_http2_dos",
    "sbi_attack_over_tls",
    "tls_handshake_flood",
}


def ip_to_int(ip_str):
    parts = [int(x) for x in ip_str.split(".")]
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def read_ip_rows(pcap_path, label):
    rows = []
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if IP in pkt:
                rows.append((pkt[IP].src, pkt[IP].dst, label))
    return rows


def write_masked_pcap(src_path, dst_path):
    dst_path.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapWriter(str(dst_path), append=False, sync=False)
    n_ip, n_total = 0, 0
    with PcapReader(str(src_path)) as reader:
        for pkt in reader:
            n_total += 1
            if IP in pkt:
                pkt[IP].src = MASK_SRC
                pkt[IP].dst = MASK_DST
                del pkt[IP].chksum  # force scapy to recompute checksum
                n_ip += 1
            writer.write(pkt)
    writer.close()
    return n_ip, n_total


def build_dataset(root_dir):
    rows = []
    label_dirs = sorted([d for d in root_dir.iterdir() if d.is_dir()])
    for label_dir in label_dirs:
        label = label_dir.name
        for pcap_file in sorted(label_dir.glob("*.pcap")):
            rows.extend(read_ip_rows(pcap_file, label))
    return rows


def fit_and_score(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    clf = DecisionTreeClassifier(random_state=SEED)
    clf.fit(X_train, y_train)
    acc = clf.score(X_test, y_test)
    vals, counts = np.unique(y_train, return_counts=True)
    majority_frac = counts.max() / counts.sum()
    return float(acc), float(majority_frac)


def evaluate_ip_only(rows, name):
    src = np.array([ip_to_int(r[0]) for r in rows])
    dst = np.array([ip_to_int(r[1]) for r in rows])
    X = np.stack([src, dst], axis=1)
    y = np.array([r[2] for r in rows])

    # (a) full 17-class task
    acc_full, majority_full = fit_and_score(X, y)

    # (b) restricted to the 9 audit-flagged container classes only (PFCP/NGAP/SBI/TLS
    #     among themselves) -- several of these share an IDENTICAL IP pair by lab
    #     design (e.g. all 4 PFCP classes come from the same container), so even a
    #     perfect IP-based model cannot separate them; this is a testbed limitation,
    #     not evidence that masking failed.
    mask_container = np.isin(y, list(CONTAINER_CLASSES))
    acc_container = majority_container = None
    if mask_container.sum() > 0:
        Xc, yc = X[mask_container], y[mask_container]
        acc_container, majority_container = fit_and_score(Xc, yc)

    # (c) binary task: "is this packet from a container-sourced class" vs everything
    #     else (benign + tier0/1). This is the task the audit actually meant when it
    #     said "9 container classes are ~100% guessable from IP" -- IP tells you the
    #     container, i.e. the protocol tier, even if not the exact sub-label.
    y_bin = np.isin(y, list(CONTAINER_CLASSES)).astype(int)
    acc_bin, majority_bin = fit_and_score(X, y_bin)

    result = {
        "name": name,
        "n_rows": int(len(rows)),
        "n_classes": int(len(np.unique(y))),
        "unique_ip_pairs": int(len(set(zip(src.tolist(), dst.tolist())))),
        "full_17class_accuracy": acc_full,
        "full_17class_majority_baseline": majority_full,
        "container_vs_rest_binary_accuracy": acc_bin,
        "container_vs_rest_binary_majority_baseline": majority_bin,
        "within_container_9class_accuracy": acc_container,
        "within_container_9class_majority_baseline": majority_container,
    }
    return result


def main():
    print(f"Reading raw (unmasked) PCAPs from {LABELED_DIR} ...")
    raw_rows = build_dataset(LABELED_DIR)
    print(f"  -> {len(raw_rows)} IP-bearing packets read")

    done_marker = MASKED_DIR / ".masking_done"
    if done_marker.exists():
        print(f"  -> {MASKED_DIR} already masked (found {done_marker}), skipping re-mask")
    else:
        print(f"Writing masked PCAP copies to {MASKED_DIR} (constant {MASK_SRC} -> {MASK_DST}) ...")
        label_dirs = sorted([d for d in LABELED_DIR.iterdir() if d.is_dir()])
        total_ip, total_pkt = 0, 0
        for label_dir in label_dirs:
            for pcap_file in sorted(label_dir.glob("*.pcap")):
                rel = pcap_file.relative_to(LABELED_DIR)
                out_path = MASKED_DIR / rel
                n_ip, n_total = write_masked_pcap(pcap_file, out_path)
                total_ip += n_ip
                total_pkt += n_total
        print(f"  -> masked {total_ip}/{total_pkt} packets across all PCAPs")
        done_marker.write_text("ok")

    print(f"Reading masked PCAPs back from {MASKED_DIR} ...")
    masked_rows = build_dataset(MASKED_DIR)
    print(f"  -> {len(masked_rows)} IP-bearing packets read")

    before = evaluate_ip_only(raw_rows, "before_masking")
    after = evaluate_ip_only(masked_rows, "after_masking")

    margin = 0.05
    # Before masking: IP should near-perfectly reveal "is this a container-sourced
    # (PFCP/NGAP/SBI/TLS) class" -- that's the actual leak the audit flagged.
    # After masking: that same binary signal must collapse to majority-class guessing.
    gate_pass = (
        before["container_vs_rest_binary_accuracy"] > 0.95
        and after["container_vs_rest_binary_accuracy"]
        <= after["container_vs_rest_binary_majority_baseline"] + margin
        and after["full_17class_accuracy"]
        <= after["full_17class_majority_baseline"] + margin
    )

    summary = {
        "mask_src": MASK_SRC,
        "mask_dst": MASK_DST,
        "margin_used": margin,
        "before_masking": before,
        "after_masking": after,
        "GATE_F8_2_PASS": bool(gate_pass),
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_json = REPORT_DIR / "f8_2_gate_result.json"
    with open(out_json, "w") as f:
        json.dump(summary, f, indent=2)

    print(json.dumps(summary, indent=2))
    print(f"\nSaved -> {out_json}")

    if not gate_pass:
        sys.exit(1)


if __name__ == "__main__":
    main()
