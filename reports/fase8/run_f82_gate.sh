#!/bin/bash
cd /home/mobisec/nfm-fase8
source .venv/bin/activate
python3 reports/fase8/f8_2_ip_only_classifier.py > reports/fase8/f8_2_gate_log.txt 2>&1
echo "SCRIPT_EXIT=$?" >> reports/fase8/f8_2_gate_log.txt
