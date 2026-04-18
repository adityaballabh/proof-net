#!/bin/bash
set -e

node_cnt=${1:-7}
acct_cnt=${2:-3}

rm -rf receipts keys state bootstrap/acct*
mkdir -p keys/pvt keys/pub state

docker build -t proof-net -f docker/Dockerfile .
python3 docker/gen_config.py $node_cnt $acct_cnt
GEN_KEY="docker run --rm -v $(pwd)/keys:/app/keys proof-net /gen_key"

for ((i = 0; i < node_cnt; i++)); do
    $GEN_KEY keys/pvt/node$i.key keys/pub/node$i.key
done

$GEN_KEY keys/pvt/acct_common.key keys/pub/acct_common.key

docker compose -f docker/docker-compose.yml up 2>&1 | tee logs/out.log
