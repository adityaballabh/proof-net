#!/bin/bash

rm -rf receipts keys
mkdir -p keys/pvt keys/pub

make gen_key

for i in {0..3}; do
    mkdir -p receipts/$i
    ./gen_key keys/pvt/$i.key keys/pub/$i.key
done

for i in {1000..1001}; do
    ./gen_key keys/pvt/$i.key keys/pub/$i.key
done

docker build -t proof-net -f docker/Dockerfile .
docker compose -f docker/docker-compose.yml up
