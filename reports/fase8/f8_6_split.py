#!/usr/bin/env python3
"""F8.6 -- anti-leak train/val/test split.

Rule: every flow/burst belonging to one EPISODE (one ground-truth time window
= one original PCAP file, or for benign: one capture-session timestamp shared
by its dn/up/cp interface files) must land in exactly ONE split.

Strategy per final class (16 classes from F8.4):
  - If the class has >=3 distinct episodes: sort episodes by start time and
    assign whole episodes to train/val/test in time order (earliest -> train,
    latest -> test) -- this is the "ideal, time-based" option FASE8.md asks
    for, and gives a genuine temporal-generalization test.
  - If the class has only 1-2 episodes (8 of the 16 classes: all have exactly
    1 single-capture PCAP, see f8_4_label_mapping_log.txt), an episode-level
    70/15/15 split is mathematically impossible. Documented fallback: pool
    all of that class's flows and do a random stratified 70/15/15 split at
    the FLOW level with a fixed seed. This is NOT the same leak the audit
    flagged (that was about raw 5-tuples repeating across benign vs attack
    due to ephemeral port reuse); this is a single class's own flows from a
    single time window, split into disjoint train/val/test flows. Residual
    risk: flows from the same short capture may still share stylistic/
    temporal traits -- disclosed here and in F8.11, not hidden.

Classes with ZERO tokenized rows (ngap_malformed, ngap_ngsetup_flood -- NGAP
runs over SCTP, which netFound's tokenizer does not support; see
f8_6_ngap_sctp_limitation.md) get 0/0/0 and are excluded from the combined
arrow files, but are still listed in the distribution report for honesty.
"""
import csv
import datetime
import json
import pathlib

import numpy as np
import pyarrow as pa
import pyarrow.ipc as ipc

REPO_ROOT = pathlib.Path("/home/mobisec/nfm-fase8")
SHARDS_DIR = REPO_ROOT / "data" / "finetune_raw" / "final" / "shards"
GROUND_TRUTH_CSV = REPO_ROOT / "data" / "ground_truth.csv"
REPORT_DIR = REPO_ROOT / "reports" / "fase8"
SPLIT_OUT_DIR = REPO_ROOT / "data" / "finetune_raw" / "final" / "split"

SEED = 42
TRAIN_FRAC, VAL_FRAC, TEST_FRAC = 0.70, 0.15, 0.15

TABLE_SCHEMA = pa.schema(
    [
        pa.field("flow_duration", pa.uint64()),
        pa.field("burst_tokens", pa.list_(pa.list_(pa.uint16()))),
        pa.field("directions", pa.list_(pa.bool_())),
        pa.field("bytes", pa.list_(pa.uint32())),
        pa.field("iats", pa.list_(pa.uint64())),
        pa.field("counts", pa.list_(pa.uint32())),
        pa.field("protocol", pa.uint16()),
        pa.field("labels", pa.string()),
    ]
)


def load_ground_truth():
    gt = {}
    with open(GROUND_TRUTH_CSV) as f:
        for row in csv.DictReader(f):
            gt[row["scenario_id"]] = row
    return gt


import re

_BENIGN_SESSION_RE = re.compile(r"^(?:cp_cp|dn_dn|up_up)_(\d{8}_\d{6})$")


def parse_episode_id(folder_name):
    name = folder_name
    if "__" in name:
        _, name = name.split("__", 1)
    # benign capture sessions are named "<iface>_<iface>_<timestamp>" (cp_cp_/dn_dn_/
    # up_up_ are different interface taps of the SAME capture session, not separate
    # episodes) -- extract just the shared timestamp so all interface files of one
    # session group together into one episode.
    m = _BENIGN_SESSION_RE.match(name)
    if m:
        return m.group(1)
    parts = name.rsplit("_", 1)
    if len(parts) == 2 and parts[1] in ("up", "dn", "cp"):
        name = parts[0]
    return name


def read_arrow_table(path):
    with open(path, "rb") as f:
        reader = ipc.open_stream(f)
        batches = list(reader)
    if not batches:
        return pa.Table.from_batches([], schema=TABLE_SCHEMA)
    return pa.Table.from_batches(batches)


def main():
    gt = load_ground_truth()
    rng = np.random.RandomState(SEED)

    # label -> episode_group -> {"start_epoch":..., "table": pa.Table}
    per_label_groups = {}

    for label_dir in sorted(SHARDS_DIR.iterdir()):
        if not label_dir.is_dir():
            continue
        label = label_dir.name
        per_label_groups[label] = {}
        for episode_dir in sorted(label_dir.iterdir()):
            if not episode_dir.is_dir():
                continue
            folder_name = episode_dir.name
            raw_episode_id = parse_episode_id(folder_name)

            if raw_episode_id in gt:
                start_epoch = int(gt[raw_episode_id]["start_epoch"])
                episode_group = raw_episode_id
            else:
                try:
                    dt = datetime.datetime.strptime(raw_episode_id, "%Y%m%d_%H%M%S")
                    start_epoch = int(dt.timestamp())
                except ValueError:
                    start_epoch = 0
                episode_group = raw_episode_id

            tables = [read_arrow_table(p) for p in sorted(episode_dir.glob("*.arrow"))]
            tables = [t for t in tables if t.num_rows > 0]
            if not tables:
                combined = pa.Table.from_batches([], schema=TABLE_SCHEMA)
            else:
                combined = pa.concat_tables(tables)

            g = per_label_groups[label].setdefault(
                episode_group, {"start_epoch": start_epoch, "tables": []}
            )
            if combined.num_rows > 0:
                g["tables"].append(combined)

    split_tables = {"train": [], "val": [], "test": []}
    report_rows = []

    for label, groups in sorted(per_label_groups.items()):
        group_items = []
        for episode_group, info in groups.items():
            if info["tables"]:
                tbl = pa.concat_tables(info["tables"])
            else:
                tbl = pa.Table.from_batches([], schema=TABLE_SCHEMA)
            group_items.append((episode_group, info["start_epoch"], tbl))

        total_rows = sum(t.num_rows for _, _, t in group_items)
        n_groups_with_data = sum(1 for _, _, t in group_items if t.num_rows > 0)

        counts = {"train": 0, "val": 0, "test": 0}
        strategy = None

        if total_rows == 0:
            strategy = "NO_DATA"
        elif n_groups_with_data >= 3:
            strategy = "episode_time_ordered"
            group_items.sort(key=lambda x: x[1])  # sort by start_epoch asc
            n = len(group_items)
            n_val = max(1, round(n * VAL_FRAC))
            n_test = max(1, round(n * TEST_FRAC))
            n_train = n - n_val - n_test
            if n_train < 1:
                n_train = 1
                n_val = max(1, (n - 1) // 2)
                n_test = n - n_train - n_val
            train_groups = group_items[:n_train]
            val_groups = group_items[n_train:n_train + n_val]
            test_groups = group_items[n_train + n_val:]
            for bucket_name, bucket in (
                ("train", train_groups),
                ("val", val_groups),
                ("test", test_groups),
            ):
                tabs = [t for _, _, t in bucket if t.num_rows > 0]
                if tabs:
                    tbl = pa.concat_tables(tabs)
                    split_tables[bucket_name].append(tbl)
                    counts[bucket_name] = tbl.num_rows
        else:
            strategy = "flow_level_random_fallback"
            tabs = [t for _, _, t in group_items if t.num_rows > 0]
            full_tbl = pa.concat_tables(tabs)
            n = full_tbl.num_rows
            idx = rng.permutation(n)
            n_train = round(n * TRAIN_FRAC)
            n_val = round(n * VAL_FRAC)
            n_test = n - n_train - n_val
            train_idx = idx[:n_train]
            val_idx = idx[n_train:n_train + n_val]
            test_idx = idx[n_train + n_val:]
            for bucket_name, bucket_idx in (
                ("train", train_idx),
                ("val", val_idx),
                ("test", test_idx),
            ):
                if len(bucket_idx) > 0:
                    tbl = full_tbl.take(pa.array(bucket_idx))
                    split_tables[bucket_name].append(tbl)
                    counts[bucket_name] = tbl.num_rows

        report_rows.append(
            {
                "label": label,
                "n_episodes": len(group_items),
                "n_episodes_with_data": n_groups_with_data,
                "strategy": strategy,
                "total_rows": total_rows,
                "train_rows": counts["train"],
                "val_rows": counts["val"],
                "test_rows": counts["test"],
            }
        )

    SPLIT_OUT_DIR.mkdir(parents=True, exist_ok=True)
    for split_name, tabs in split_tables.items():
        out_path = SPLIT_OUT_DIR / f"{split_name}.arrow"
        if tabs:
            combined = pa.concat_tables(tabs)
        else:
            combined = pa.Table.from_batches([], schema=TABLE_SCHEMA)
        with pa.OSFile(str(out_path), "wb") as sink:
            with ipc.new_stream(sink, schema=TABLE_SCHEMA) as writer:
                for batch in combined.to_batches():
                    writer.write_batch(batch)
        print(f"{split_name}: {combined.num_rows} rows -> {out_path}")

    out_csv = REPORT_DIR / "f8_6_split_distribution.csv"
    with open(out_csv, "w", newline="") as f:
        fieldnames = [
            "label", "n_episodes", "n_episodes_with_data", "strategy",
            "total_rows", "train_rows", "val_rows", "test_rows",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_rows)

    print(f"\nPer-class distribution saved -> {out_csv}")
    print(f"\n{'label':25s} {'strategy':28s} {'total':>8s} {'train':>8s} {'val':>8s} {'test':>8s}")
    grand_total = {"train": 0, "val": 0, "test": 0}
    for r in report_rows:
        print(
            f"{r['label']:25s} {r['strategy']:28s} {r['total_rows']:8d} "
            f"{r['train_rows']:8d} {r['val_rows']:8d} {r['test_rows']:8d}"
        )
        grand_total["train"] += r["train_rows"]
        grand_total["val"] += r["val_rows"]
        grand_total["test"] += r["test_rows"]
    print(f"\nGrand total -> train={grand_total['train']} val={grand_total['val']} test={grand_total['test']}")

    with open(REPORT_DIR / "f8_6_split_summary.json", "w") as f:
        json.dump(
            {
                "seed": SEED,
                "fractions": {"train": TRAIN_FRAC, "val": VAL_FRAC, "test": TEST_FRAC},
                "per_class": report_rows,
                "grand_total": grand_total,
            },
            f,
            indent=2,
        )


if __name__ == "__main__":
    main()
