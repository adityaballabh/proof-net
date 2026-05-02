## ProofNet

A partially decentralized anonymous network that uses bandwidth contribution proofs to achieve fairness while preserving privacy.

## Overview

- Onion routing
- Next hop sends signed receipts for bandwidth contributions
- Nodes send contribution proofs along with route commitments to their designated accounting node
- Accounting nodes track utilization and validate proofs. If valid, they sign route commitments. Verified at each hop
- Source routing with hop length randomization
- Length-based framing for reliable delivery
- Topology discovery through bootstrapping
- Adversarial nodes try to break fairness

## Usage

`./docker/up.sh [-n node_cnt] [-a acct_cnt] [-c adversarial_config_path]`

## Adversarial Modes

- skip_verify: Send without valid accounting signatures
- selfish_send: Send without receipts
- self_receipts: Send using self-issued receipts
- replay: Send using old packet ids

Example: [docker/adversarial_config.txt](docker/adversarial_config.txt)

ProofNet prevents these attacks. However, it is susceptible to colluding nodes exchanging fake receipts with each other.

## Sample Logs

- Without adversarial nodes: [sample-logs/non_adversarial.log](sample-logs/non_adversarial.log)
- With adversarial nodes: [sample-logs/adversarial.log](sample-logs/adversarial.log)

## References

[Beej's Guide](https://beej.us/guide/bgnet/pdf/bgnet_usl_c_1.pdf)

[Libsodium Docs](https://libsodium.gitbook.io/doc)
