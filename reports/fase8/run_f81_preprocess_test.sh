#!/bin/bash
set -e
cd /home/mobisec/nfm-fase8/netFound
source /home/mobisec/nfm-fase8/.venv/bin/activate
export PATH="/usr/local/pcapplusplus/bin:$PATH"
rm -rf data/test/pretraining/split data/test/pretraining/filtered data/test/pretraining/extracted data/test/pretraining/final
python3 ./scripts/preprocess_data.py --input_folder data/test/pretraining --action pretrain --tokenizer_config configs/DefaultConfigNoTCPOptions.json --combined
echo "PREPROCESS_EXIT=$?"
echo "--- output files ---"
find data/test/pretraining/final -type f
