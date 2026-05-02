import sys
from pathlib import Path

DOCKER_DIR = Path("docker")
BOOTSTRAP_DIR = Path("bootstrap")
DEF_NODE_CNT = 7
DEF_ACCT_CNT = 3
NW_BASE_PORT = 2000
ACCT_BASE_ID = 3000
ACCT_BASE_PORT = 3000


class Mode:
    SKIP_VERIFY = "skip_verify"
    SELFISH_SEND = "selfish_send"
    SELF_RECEIPTS = "self_receipts"
    REPLAY = "replay"


def parse_adversary_spec(path):
    adversaries = {}
    if not path:
        return adversaries
    file = Path(path).read_text().splitlines()

    for entry in file:
        entry = entry.strip()
        parts = entry.split()
        if not entry or entry.startswith("#"):
            continue

        assert len(parts) >= 3, f"invalid adversary spec: {entry}"
        try:
            node_id = int(parts[0])
            dest = int(parts[2])
        except Exception:
            sys.exit(f"invalid adversary spec: {entry}")

        mode = parts[1]
        extra_args = parts[3:]

        match mode:
            case Mode.SKIP_VERIFY | Mode.SELFISH_SEND | Mode.SELF_RECEIPTS | Mode.REPLAY:
                if len(extra_args) > 1:
                    sys.exit(f"usage: <node_id> {mode} <dest> [rep_cnt]")
            case _:
                sys.exit(f"unknown mode: {mode}")

        if node_id in adversaries:
            sys.exit(f"invalid adversary spec: duplicate config for node {node_id}")
        adversaries[node_id] = [mode, str(dest), *extra_args]

    return adversaries


def gen_node(id, acct_cnt, adversary_args):
    svc_name = f"node{id}"
    acct_id = id % acct_cnt
    command = f"/node {id}"
    if adversary_args is not None:
        command = "/adversary " + " ".join([str(id), *adversary_args])
    return f"""
  {svc_name}:
    image: proof-net
    command: {command}
    depends_on:
      - acct{acct_id}
    volumes:
      - ../messages/{svc_name}:/app/messages
      - ../receipts/{svc_name}:/app/receipts
      - ../state/{svc_name}:/app/state
      - ../bootstrap/acct{acct_id}.txt:/app/acct.txt:ro
      - ../keys/pvt/{svc_name}.key:/app/keys/pvt/pvt.key:ro
      - ../keys/pub:/app/keys/pub:ro
"""


def gen_acct(id):
    svc_name = f"acct{id}"
    acct_id = ACCT_BASE_ID + id
    return f"""
  {svc_name}:
    image: proof-net
    command: /acct {acct_id}
    volumes:
      - ../state/{svc_name}:/app/state
      - ../keys/pvt/acct_common.key:/app/keys/pvt/acct_common.key:ro
      - ../keys/pub:/app/keys/pub:ro
      - ../bootstrap/topo.txt:/app/topo.txt:ro
"""


argc = len(sys.argv)
node_cnt = int(sys.argv[1]) if argc > 1 else DEF_NODE_CNT
acct_cnt = int(sys.argv[2]) if argc > 2 else DEF_ACCT_CNT
adversary_spec = sys.argv[3] if argc > 3 else ""
adversaries = parse_adversary_spec(adversary_spec)

if node_cnt <= 0 or acct_cnt <= 0:
    sys.exit("node_cnt and acct_cnt must be positive integers")

for node_id in adversaries:
    if node_id < 0 or node_id >= node_cnt:
        sys.exit(
            f"invalid adversary spec: node id {node_id} is not in [0, {node_cnt - 1}]"
        )

compose_path = DOCKER_DIR / "docker-compose.yml"
nw_config_path = DOCKER_DIR / "nw_config.txt"
acct_config_path = DOCKER_DIR / "acct_config.txt"

compose_out = "services:"
nw_out = ""
acct_out = ""

for id in range(node_cnt):
    node_port = NW_BASE_PORT + id
    compose_out += gen_node(id, acct_cnt, adversaries.get(id))
    nw_out += f"{id} {node_port} node{id}\n"

for id in range(acct_cnt):
    compose_out += gen_acct(id)
    acct_name = f"acct{id}"
    acct_id = ACCT_BASE_PORT + id
    bootstrap_out = f"{acct_id} {acct_id} {acct_name}\n"
    bootstrap_path = BOOTSTRAP_DIR / f"{acct_name}.txt"
    bootstrap_path.write_text(bootstrap_out)
    acct_out += bootstrap_out

compose_path.write_text(compose_out)
nw_config_path.write_text(nw_out)
acct_config_path.write_text(acct_out)

print(f"generated {compose_path}: node_cnt={node_cnt}, acct_cnt={acct_cnt}")
if adversaries:
    print(f"adversarial nodes: {sorted(adversaries)}")
