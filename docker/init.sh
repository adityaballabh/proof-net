#!/bin/bash

rm -rf receipts keys

for i in {0..3}; do
    key_dir=keys/$i
    mkdir -p receipts/$i $key_dir
    openssl genpkey -algorithm Ed25519 -out $key_dir/pvt.pem -outpubkey $key_dir/pub.pem
done

docker build -t proof-net -f docker/Dockerfile .
docker compose -f docker/docker-compose.yml up