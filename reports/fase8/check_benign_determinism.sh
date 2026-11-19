#!/bin/bash
set -euo pipefail
exec > /home/mobisec/nfm-fase8/reports/fase8/check_benign_determinism_log.txt 2>&1
cd /home/mobisec/nfm-fase8/netFound
source /home/mobisec/nfm-fase8/.venv/bin/activate
export PATH="/usr/local/pcapplusplus/bin:$PATH"
BASE=/home/mobisec/nfm-fase8/data/finetune_raw

for run in run1 run2; do
  echo "=== $run ==="
  rm -rf "$BASE/split_test_$run" "$BASE/extracted_test_$run" "$BASE/final_test_$run"
  mkdir -p "$BASE/split_test_$run" "$BASE/extracted_test_$run" "$BASE/final_test_$run/shards"
  pre_process_src/2_pcap_splitting.sh "$BASE/filtered/benign" "$BASE/split_test_$run/benign"
  pre_process_src/3_extract_fields.sh "$BASE/split_test_$run/benign" "$BASE/extracted_test_$run/benign"
  for d in "$BASE/extracted_test_$run/benign"/*/; do
    name=$(basename "$d")
    mkdir -p "$BASE/final_test_$run/shards/$name"
    python3 pre_process_src/Tokenize.py --conf_file configs/DefaultConfigNoTCPOptions.json \
      --input_dir "$d" --output_dir "$BASE/final_test_$run/shards/$name" --label benign >/dev/null 2>&1
  done
  python3 - <<PYEOF
import pyarrow.ipc as ipc
import pathlib
total = 0
for p in pathlib.Path("$BASE/final_test_$run/shards").rglob("*.arrow"):
    with open(p, "rb") as f:
        reader = ipc.open_stream(f)
        total += sum(b.num_rows for b in reader)
print(f"$run total rows: {total}")
PYEOF
done
