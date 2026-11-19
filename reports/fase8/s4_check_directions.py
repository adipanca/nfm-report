#!/usr/bin/env python3
"""S4: verify the 'directions' column contains both True (fwd) and False (bwd)
for the SCTP flow and for the TCP/UDP reference flows, after the internalIPs fix.
"""
import pathlib
import pyarrow.ipc as ipc

BASE = pathlib.Path("/home/mobisec/nfm-fase8/data/test/sctp_dev/final/shards")


def load_rows(path):
    with open(path, "rb") as f:
        reader = ipc.open_stream(f)
        batches = list(reader)
    rows = []
    for b in batches:
        d = b.to_pydict()
        for i in range(b.num_rows):
            rows.append({k: d[k][i] for k in d})
    return rows


for label_dir in sorted(BASE.iterdir()):
    if not label_dir.is_dir():
        continue
    print(f"=== {label_dir.name} ===")
    all_dirs_for_label = []
    for p in sorted(label_dir.rglob("*.arrow")):
        for row in load_rows(p):
            dirs = row["directions"]
            all_dirs_for_label.append(dirs)
    n_fwd_only = sum(1 for d in all_dirs_for_label if all(d))
    n_bwd_only = sum(1 for d in all_dirs_for_label if not any(d))
    n_mixed = sum(1 for d in all_dirs_for_label if any(d) and not all(d))
    print(f"  total flows: {len(all_dirs_for_label)}")
    print(f"  flows with ONLY forward bursts:  {n_fwd_only}")
    print(f"  flows with ONLY backward bursts: {n_bwd_only}")
    print(f"  flows with BOTH fwd+bwd bursts:  {n_mixed}")
    # show a couple example direction lists
    for d in all_dirs_for_label[:3]:
        print(f"  example directions: {d}")
