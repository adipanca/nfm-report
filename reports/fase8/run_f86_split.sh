#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 reports/fase8/f8_6_split.py > reports/fase8/f8_6_split_log.txt 2>&1
echo "EXIT=$?" >> reports/fase8/f8_6_split_log.txt
