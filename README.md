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

For adversarial testing, we use up.sh and pass in the spec (there's exmaple below, basically will replace node n with adversarial behavior):
`./docker/up.sh [node_cnt] [acct_cnt] [adversary_spec]`

`adversary_spec` is a semicolon-separated list of nodes to run as `/adversary` instead of `/node`:

- `node_id:skip_verify:dest`
- `node_id:selfish_send:dest[:count]`

## Adversarial Testing

We run adversarial nodes through Docker by passing an `adversary_spec` to `up.sh`. Any node not listed still runs as a normal `/node`.

Examples:

- `./docker/up.sh 7 3 '2:skip_verify:1'`
- `./docker/up.sh 7 3 '2:selfish_send:1:6'`

That third example starts nodes `2` and `5` as colluding adversaries while the rest of the network remains honest.

Modes:

- `./adversary <id> skip_verify <dest>` => sends a packet without valid accounting signatures. The first relay should log `signature verification failed ... dropping packet`. And the real logs will look like this: `node2-1  | signature verification failed for packet oWvSrHf2uTg=. dropping packet`
- `./adversary <id> selfish_send <dest> [count]` keeps requesting sends with an empty proof. The node gets the initial allowance, then accounting starts returning `NAK` once it exceeds the threshold. And the real logs will look like this: `node2-1  | [selfish_send] accounting denied packet S7wPvmeVosI=`

## References

[Beej's Guide](https://beej.us/guide/bgnet/pdf/bgnet_usl_c_1.pdf)

[Libsodium Docs](https://libsodium.gitbook.io/doc)
