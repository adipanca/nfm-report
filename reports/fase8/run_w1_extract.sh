#!/bin/bash
set -e
cd /home/mobisec/nfm-fase8
tar tzf labeled_latest.tgz | head -20
echo "---extracting---"
tar xzf labeled_latest.tgz
echo "---done---"
echo "class dirs:"
ls data/labeled | sort
echo "---"
echo "n classes: $(ls data/labeled | grep -v '\.csv$' | wc -l)"
echo "---ground_truth.csv lines---"
wc -l data/ground_truth.csv
