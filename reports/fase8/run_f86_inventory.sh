#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 reports/fase8/f8_6_inventory_episodes.py > reports/fase8/f8_6_inventory_log.txt 2>&1
echo "EXIT=$?" >> reports/fase8/f8_6_inventory_log.txt
