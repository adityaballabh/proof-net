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
- `node_id:collude:dest:peer[:fake_receipt_cnt]`
- `node_id:mutual_collude:dest:peer[:fake_receipt_cnt]`

## Adversarial Testing

We run adversarial nodes through Docker by passing an `adversary_spec` to `up.sh`. Any node not listed still runs as a normal `/node`.

Examples:

- `./docker/up.sh 7 3 '2:skip_verify:1'`
- `./docker/up.sh 7 3 '2:selfish_send:1:6'`
- `./docker/up.sh 7 3 '2:sendFakeReceiptsSelf:1:2'`
- `./docker/up.sh 7 3 '1:mutual_collude:3:2:2;2:mutual_collude:3:1:2'`

Modes:

- `./adversary <id> skip_verify <dest>` => sends a packet without valid accounting signatures. The first relay should log `signature verification failed ... dropping packet`. And the real logs will look like this: `node2-1  | signature verification failed for packet oWvSrHf2uTg=. dropping packet`
- `./adversary <id> selfish_send <dest> [count]` keeps requesting sends with an empty proof. The node gets the initial allowance, then accounting starts returning `NAK` once it exceeds the threshold. And the real logs will look like this: `node2-1  | [selfish_send] accounting denied packet S7wPvmeVosI=`
- `./adversary <id> sendFakeReceiptsSelf <dest> [fake_receipt_cnt]` self-issued fake receipt flow. Node `<id>` sends signed fake receipts to `<self>`, loads whatever receipts are stored locally, and tries to spend them when requesting approval for a packet to `<dest>`.
- `./adversary <id> mutual_collude <dest> <peer> [fake_receipt_cnt]` is for reciprocal fake-credit testing. Run it on both colluding nodes so each side sends fake receipts to the other, then each node submits the peer-issued receipts in its own proof.

## References

[Beej's Guide](https://beej.us/guide/bgnet/pdf/bgnet_usl_c_1.pdf)

[Libsodium Docs](https://libsodium.gitbook.io/doc)
