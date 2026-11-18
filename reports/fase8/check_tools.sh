#!/bin/bash
for c in tshark tcpdump editcap bittwiste tcprewrite; do
  if command -v "$c" >/dev/null 2>&1; then
    echo "$c: found at $(command -v "$c")"
  else
    echo "$c: MISSING"
  fi
done
echo "---"
echo "scapy python check:"
python3 -c "import scapy; print('scapy module present:', scapy.__file__)" 2>&1
