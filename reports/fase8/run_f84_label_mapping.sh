#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 reports/fase8/f8_4_label_mapping.py > reports/fase8/f8_4_label_mapping_log.txt 2>&1
echo "EXIT=$?" >> reports/fase8/f8_4_label_mapping_log.txt
