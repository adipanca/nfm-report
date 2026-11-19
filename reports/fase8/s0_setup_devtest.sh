#!/bin/bash
set -euo pipefail
cd /home/mobisec/nfm-fase8
rm -rf data/test/sctp_dev
mkdir -p data/test/sctp_dev/raw/ngap_malformed
mkdir -p data/test/sctp_dev/raw/sbi_http2_attack
mkdir -p data/test/sctp_dev/raw/pfcp_session_delete

cp data/labeled/ngap_malformed/T3-03_up.pcap data/test/sctp_dev/raw/ngap_malformed/
cp data/labeled/sbi_attack_over_tls/T5-04_cp.pcap data/test/sctp_dev/raw/sbi_http2_attack/
cp data/labeled/pfcp_session_delete/T2-01_up.pcap data/test/sctp_dev/raw/pfcp_session_delete/

echo "--- dev test dir ---"
find data/test/sctp_dev -type f
