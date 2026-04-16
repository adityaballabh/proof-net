#!/bin/bash

rm -rf receipts keys state
mkdir -p keys/pvt keys/pub
mkdir -p state

docker build -t proof-net -f docker/Dockerfile .
GEN_KEY="docker run --rm -v $(pwd)/keys:/app/keys proof-net /gen_key"

for i in {0..3}; do
    $GEN_KEY keys/pvt/node$i.key keys/pub/node$i.key
done

$GEN_KEY keys/pvt/acct_common.key keys/pub/acct_common.key

docker compose -f docker/docker-compose.yml up 2>&1 | tee logs/out.log
