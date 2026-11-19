#!/bin/bash
cd /home/mobisec/nfm-fase8
set -x

mv data/labeled "data/labeled_prev_$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
rm -f labeled_latest.tgz

timeout 20 scp -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no \
  ubuntuserver26@192.168.56.50:~/nfm-testbed-5g/labeled_latest.tgz ~/nfm-fase8/ 2>&1
SCP_EXIT=$?
echo "SCP_EXIT=$SCP_EXIT"
ls -la ~/nfm-fase8/labeled_latest.tgz 2>&1
