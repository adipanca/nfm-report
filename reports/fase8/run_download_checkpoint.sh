#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 - > reports/fase8/f8_7_checkpoint_download_log.txt 2>&1 <<'PY'
from huggingface_hub import snapshot_download
path = snapshot_download(repo_id="snlucsb/netFound-base", local_dir="/home/mobisec/nfm-fase8/models/netFound-base")
print("Downloaded to:", path)
PY
echo "EXIT=$?" >> reports/fase8/f8_7_checkpoint_download_log.txt
