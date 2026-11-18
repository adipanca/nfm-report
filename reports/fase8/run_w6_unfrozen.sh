#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 reports/fase8/w6_train_unfrozen.py > reports/fase8/w6_train_unfrozen_log.txt 2>&1
echo "EXIT=$?" >> reports/fase8/w6_train_unfrozen_log.txt
