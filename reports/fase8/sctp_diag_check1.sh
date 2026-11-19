#!/bin/bash
BASE=/home/mobisec/nfm-fase8/data/finetune_raw
echo "=== split/bidding_down episode dirs ==="
for d in "$BASE/split/bidding_down"/*/; do
  echo "$d:"
  ls "$d" | wc -l
done
echo
echo "=== split/ngap_malformed episode dirs ==="
for d in "$BASE/split/ngap_malformed"/*/; do
  echo "$d:"
  ls "$d" | wc -l
done
echo
echo "=== compare: pfcp_session_delete episode dirs (for reference, UDP, normal row counts) ==="
for d in "$BASE/split/pfcp_session_delete"/*/; do
  echo "$d:"
  ls "$d" | wc -l
done
