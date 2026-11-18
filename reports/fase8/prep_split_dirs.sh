#!/bin/bash
set -e
cd /home/mobisec/nfm-fase8/data/finetune_raw/final/split
for s in train val test; do
  mkdir -p "${s}_dir"
  cp "${s}.arrow" "${s}_dir/"
done
ls -la train_dir val_dir test_dir
