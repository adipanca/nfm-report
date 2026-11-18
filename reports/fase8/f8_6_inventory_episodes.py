#!/usr/bin/env python3
"""Inventory step for F8.6: count rows (flows/bursts) per episode shard, after
F8.5 preprocessing, across all 16 final classes. Used to (a) sanity check data
loss (e.g. the benign PcapPlusPlus connection-split warnings seen in F8.5),
and (b) build the per-episode table that F8.6's split logic consumes.
"""
import csv
import datetime
import json
import pathlib
import re

import pyarrow as pa
import pyarrow.ipc as ipc

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
SHARDS_DIR = REPO_ROOT / "data" / "finetune_raw" / "final" / "shards"
GROUND_TRUTH_CSV = REPO_ROOT / "data" / "ground_truth.csv"
REPORT_DIR = REPO_ROOT / "reports" / "fase8"


def load_ground_truth():
    gt = {}
    with open(GROUND_TRUTH_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            gt[row["scenario_id"]] = row
    return gt


def count_rows_in_arrow(path):
    # Tokenize.py writes shards with pa.ipc.new_stream -> Arrow IPC stream format.
    with open(path, "rb") as f:
        reader = ipc.open_stream(f)
        total = 0
        for batch in reader:
            total += batch.num_rows
        return total


def parse_episode_id(label, folder_name):
    # folder_name looks like "<original_label>__<scenario_or_ts>_<iface>"
    # e.g. "pfcp_session_delete__T2-01-e1_up" -> scenario_id "T2-01-e1"
    #      "benign__up_up_20261114_084907"    -> timestamp "20261114_084907"
    name = folder_name
    if "__" in name:
        _, name = name.split("__", 1)
    m = re.match(r"^(?:cp_cp|dn_dn|up_up)_(\d{8}_\d{6})$", name)
    if m:
        return m.group(1)
    # strip trailing _<iface> (up/dn/cp)
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1] in ("up", "dn", "cp"):
        name = parts[0]
    return name


def main():
    gt = load_ground_truth()
    rows = []

    for label_dir in sorted(SHARDS_DIR.iterdir()):
        if not label_dir.is_dir():
            continue
        label = label_dir.name
        for episode_dir in sorted(label_dir.iterdir()):
            if not episode_dir.is_dir():
                continue
            folder_name = episode_dir.name
            arrow_files = sorted(episode_dir.glob("*.arrow"))
            n_rows = 0
            for af in arrow_files:
                try:
                    n_rows += count_rows_in_arrow(af)
                except Exception as e:
                    print(f"WARN: failed to read {af}: {e}")

            raw_episode_id = parse_episode_id(label, folder_name)

            if raw_episode_id in gt:
                start_epoch = int(gt[raw_episode_id]["start_epoch"])
                # benign capture-session id: group by timestamp so dn/up/cp of the
                # same capture session are treated as ONE episode (they are
                # simultaneous captures of the same time window on different
                # interfaces, not independent episodes)
                episode_group = raw_episode_id
            else:
                # benign: raw_episode_id is a "YYYYMMDD_HHMMSS" timestamp
                try:
                    dt = datetime.datetime.strptime(raw_episode_id, "%Y%m%d_%H%M%S")
                    start_epoch = int(dt.timestamp())
                except ValueError:
                    start_epoch = None
                episode_group = raw_episode_id

            rows.append(
                {
                    "label": label,
                    "folder_name": folder_name,
                    "episode_group": episode_group,
                    "start_epoch": start_epoch,
                    "n_arrow_files": len(arrow_files),
                    "n_rows": n_rows,
                }
            )

    out_csv = REPORT_DIR / "f8_6_episode_inventory.csv"
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["label", "folder_name", "episode_group", "start_epoch", "n_arrow_files", "n_rows"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Total episode-folders inventoried: {len(rows)}")
    by_label = {}
    for r in rows:
        by_label.setdefault(r["label"], {"n_episodes": 0, "n_rows": 0})
        by_label[r["label"]]["n_episodes"] += 1
        by_label[r["label"]]["n_rows"] += r["n_rows"]
    for label, info in sorted(by_label.items()):
        print(f"  {label:25s} episodes={info['n_episodes']:3d}  total_rows={info['n_rows']:8d}")

    print(f"\nSaved -> {out_csv}")


if __name__ == "__main__":
    main()
