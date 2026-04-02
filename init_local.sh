#!/bin/sh
pkill -f "./node"
rm -rf receipts
make node

for i in {0..3}; do
    mkdir -p receipts/$i
    ./node "$i" config_local.txt &
done
wait