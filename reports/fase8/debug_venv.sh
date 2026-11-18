#!/bin/bash
cd /home/mobisec/nfm-fase8/netFound
source /home/mobisec/nfm-fase8/.venv/bin/activate
echo "VIRTUAL_ENV=$VIRTUAL_ENV"
echo "which python3: $(which python3)"
echo "python3 -c pandas check:"
python3 -c "import pandas; print('pandas ok', pandas.__version__)"
