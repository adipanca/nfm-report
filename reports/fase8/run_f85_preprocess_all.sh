#!/bin/bash
cd /home/mobisec/nfm-fase8/netFound
source /home/mobisec/nfm-fase8/.venv/bin/activate
export PATH="/usr/local/pcapplusplus/bin:$PATH"
rm -rf /home/mobisec/nfm-fase8/data/finetune_raw/filtered \
       /home/mobisec/nfm-fase8/data/finetune_raw/split \
       /home/mobisec/nfm-fase8/data/finetune_raw/extracted \
       /home/mobisec/nfm-fase8/data/finetune_raw/final
python3 ./scripts/preprocess_data.py \
  --input_folder /home/mobisec/nfm-fase8/data/finetune_raw \
  --action finetune \
  --tokenizer_config configs/DefaultConfigNoTCPOptions.json \
  > /home/mobisec/nfm-fase8/reports/fase8/f8_5_preprocess_all_log.txt 2>&1
echo "EXIT=$?" >> /home/mobisec/nfm-fase8/reports/fase8/f8_5_preprocess_all_log.txt
echo "--- shard tree ---" >> /home/mobisec/nfm-fase8/reports/fase8/f8_5_preprocess_all_log.txt
find /home/mobisec/nfm-fase8/data/finetune_raw/final/shards -name "*.arrow" | sort >> /home/mobisec/nfm-fase8/reports/fase8/f8_5_preprocess_all_log.txt
