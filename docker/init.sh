#!/bin/bash

rm -rf receipts keys state
mkdir -p keys/pvt keys/pub
mkdir -p state

docker build -t proof-net -f docker/Dockerfile .
GEN_KEY="docker run --rm -v $(pwd)/keys:/app/keys proof-net /gen_key"

for i in {0..3}; do
    mkdir -p receipts/node$i
    $GEN_KEY keys/pvt/node$i.key keys/pub/node$i.key
done

for i in {1000..1001}; do
    id=$((i - 1000))
    $GEN_KEY keys/pvt/acct$id.key keys/pub/acct$id.key
done

docker compose -f docker/docker-compose.yml up 2>&1 | tee logs/out.log
