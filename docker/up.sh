#!/bin/bash
set -e

node_cnt=7
acct_cnt=3
adversarial_config_path=""

while getopts "n:a:c:" opt; do
  case $opt in
    n) 
        node_cnt="$OPTARG"
        ;;
    a)
        acct_cnt="$OPTARG"
        ;;
    c) 
        adversarial_config_path="$OPTARG"
        ;;
    *) 
        echo "usage: up.sh [-n node_cnt] [-a acct_cnt] [-c adversarial_config_path]"; 
        exit 1 
        ;;
  esac
done

rm -rf receipts keys state bootstrap/acct*
mkdir -p keys/pvt keys/pub state logs

docker build -t proof-net -f docker/Dockerfile .
python3 docker/gen_config.py "$node_cnt" "$acct_cnt" "$adversarial_config_path"
GEN_KEY="docker run --rm -v $(pwd)/keys:/app/keys proof-net /gen_key"

for ((i = 0; i < node_cnt; i++)); do
    $GEN_KEY keys/pvt/node$i.key keys/pub/node$i.key
done

$GEN_KEY keys/pvt/acct_common.key keys/pub/acct_common.key

docker compose -f docker/docker-compose.yml up 2>&1 | tee logs/out.log
