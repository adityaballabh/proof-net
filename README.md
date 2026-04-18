## ProofNet
A partially decentralized anonymous network that uses bandwidth contribution proofs to achieve fairness while preserving privacy.

## Key Features
- Onion routing
- Next hop sends signed receipts for bandwidth contributions
- Nodes send contribution proofs along with route commitments to their designated accounting node
- Accounting nodes track utilization and validate proofs. If valid, they sign route commitments. Verified at each hop
- Source routing with hop length randomization
- Length-based framing for reliable delivery
- Topology discovery through bootstrapping

## Usage
`./docker/up.sh [node_cnt] [acct_cnt]`

## References
[Beej's Guide](https://beej.us/guide/bgnet/pdf/bgnet_usl_c_1.pdf)

[Libsodium Docs](https://libsodium.gitbook.io/doc)
