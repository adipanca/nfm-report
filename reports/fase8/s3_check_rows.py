#!/usr/bin/env python3
import pathlib
import pyarrow.ipc as ipc

base = pathlib.Path("/home/mobisec/nfm-fase8/data/test/sctp_dev/final/shards")
totals = {}
for label_dir in sorted(base.iterdir()):
    if not label_dir.is_dir():
        continue
    n = 0
    for p in label_dir.rglob("*.arrow"):
        with open(p, "rb") as f:
            reader = ipc.open_stream(f)
            n += sum(b.num_rows for b in reader)
    totals[label_dir.name] = n

for k, v in totals.items():
    print(f"{k}: {v} rows")
