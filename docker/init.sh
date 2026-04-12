#!/bin/bash

rm -rf receipts keys state
mkdir -p keys/pvt keys/pub

make gen_key

for i in {0..3}; do
    mkdir -p receipts/node$i
    mkdir -p state/node$i
    ./gen_key keys/pvt/node$i.key keys/pub/node$i.key
done

for i in {1000..1001}; do
    id=$((i - 1000))
    ./gen_key keys/pvt/acct$id.key keys/pub/acct$id.key
    mkdir -p state/acct$id
done

docker build -t proof-net -f docker/Dockerfile .
docker compose -f docker/docker-compose.yml up
