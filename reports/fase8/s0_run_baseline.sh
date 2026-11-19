#!/bin/bash
set -euo pipefail
exec > /home/mobisec/nfm-fase8/reports/fase8/s0_baseline_log.txt 2>&1
cd /home/mobisec/nfm-fase8/netFound
source /home/mobisec/nfm-fase8/.venv/bin/activate
export PATH="/usr/local/pcapplusplus/bin:$PATH"
rm -rf /home/mobisec/nfm-fase8/data/test/sctp_dev/filtered \
       /home/mobisec/nfm-fase8/data/test/sctp_dev/split \
       /home/mobisec/nfm-fase8/data/test/sctp_dev/extracted \
       /home/mobisec/nfm-fase8/data/test/sctp_dev/final
python3 ./scripts/preprocess_data.py \
  --input_folder /home/mobisec/nfm-fase8/data/test/sctp_dev \
  --action finetune \
  --tokenizer_config configs/DefaultConfigNoTCPOptions.json
echo "EXIT=$?"
echo "--- arrow files ---"
find /home/mobisec/nfm-fase8/data/test/sctp_dev/final/shards -name "*.arrow"
echo "--- row counts ---"
python3 - <<'PY'
import pyarrow.ipc as ipc
import pathlib
for p in sorted(pathlib.Path("/home/mobisec/nfm-fase8/data/test/sctp_dev/final/shards").rglob("*.arrow")):
    with open(p, "rb") as f:
        reader = ipc.open_stream(f)
        n = sum(b.num_rows for b in reader)
    print(f"{p}: {n} rows")
PY
