#!/bin/sh
rm -rf receipts

for i in {0..3}; do
    mkdir -p receipts/$i
done

docker build -t proof-net -f docker/Dockerfile .
docker compose -f docker/docker-compose.yml up