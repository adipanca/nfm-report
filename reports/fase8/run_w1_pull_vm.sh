#!/bin/bash
cd /home/mobisec/nfm-fase8
set -x

# backup old labeled data
mv data/labeled "data/labeled_prev_$(date +%Y%m%d)" 2>/dev/null || true

# try scp from VM first
scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no ubuntuserver26@192.168.56.50:/tmp/labeled_latest.tgz ~/nfm-fase8/ 2>&1
SCP_EXIT=$?
echo "SCP_EXIT=$SCP_EXIT"

if [ $SCP_EXIT -ne 0 ]; then
  echo "scp failed, trying /mnt/c fallback locations"
  for candidate in /mnt/c/Users/*/Downloads/labeled_latest.tgz /mnt/d/nfm/labeled_latest.tgz /mnt/d/labeled_latest.tgz; do
    if [ -f "$candidate" ]; then
      echo "Found fallback: $candidate"
      cp "$candidate" ~/nfm-fase8/
      break
    fi
  done
fi

ls -la ~/nfm-fase8/labeled_latest.tgz
