#!/bin/bash
set -euo pipefail
exec > /home/mobisec/nfm-fase8/reports/fase8/s1_rebuild_log.txt 2>&1
cd /home/mobisec/nfm-fase8/netFound/pre_process_src/packets_processing_src
rm -rf build
mkdir build
cmake -S . -B build -DPcapPlusPlus_ROOT=/usr/local/pcapplusplus
cmake --build build
cp build/1_filter /home/mobisec/nfm-fase8/netFound/pre_process_src/1_filter
cp build/3_field_extraction /home/mobisec/nfm-fase8/netFound/pre_process_src/3_field_extraction
chmod +x /home/mobisec/nfm-fase8/netFound/pre_process_src/1_filter /home/mobisec/nfm-fase8/netFound/pre_process_src/3_field_extraction
echo "BUILD_EXIT=$?"
