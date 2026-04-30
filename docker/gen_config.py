import sys
from pathlib import Path

DOCKER_DIR = Path("docker")
BOOTSTRAP_DIR = Path("bootstrap")
DEF_NODE_CNT = 7
DEF_ACCT_CNT = 3
NW_BASE_PORT = 2000
ACCT_BASE_ID = 3000
ACCT_BASE_PORT = 3000


def parse_adversary_spec(spec):
    adversaries = {}
    if not spec:
        return adversaries

    spec_sp = spec.split(";")
    for raw_entry in spec_sp:
        entry = raw_entry.strip()
        if not entry:
            continue

        entry_sp = entry.split(":")
        parts = [part.strip() for part in entry_sp]
        assert len(parts) >= 3, "invalid spec entry for adversary"
        try:
            node_id = int(parts[0])
            dest = int(parts[2])
        except Exception:
            __import__("sys").exit(f"invalid adversary spec entry '{entry}'")

        if node_id and dest:
            mode = parts[1]
            extra_args = parts[3:]

            if mode == "skip_verify":
                if extra_args:
                    __import__("sys").exit(
                        f"invalid adversary spec entry '{entry}': "
                        "skip_verify only accepts node_id:mode:dest"
                    )
            elif mode == "selfish_send":
                if len(extra_args) > 1:
                    __import__("sys").exit(
                        f"invalid adversary spec entry '{entry}': "
                        "selfish_send accepts at most one optional count"
                    )
            elif mode == "sendFakeReceiptsSelf":
                if len(extra_args) < 1 or len(extra_args) > 2:
                    __import__("sys").exit(
                        f"invalid adversary spec entry '{entry}': "
                        "sendFakeReceiptsSelf requires dest and optional fake_receipt_cnt"
                    )
            elif mode == "mutual_collude":
                if len(extra_args) < 1 or len(extra_args) > 2:
                    __import__("sys").exit(
                        f"invalid adversary spec entry '{entry}': "
                        "mutual_collude requires peer and optional fake_receipt_cnt"
                    )
            else:
                __import__("sys").exit(
                    f"invalid adversary spec entry '{entry}': unknown mode '{mode}'"
                )

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
            f"invalid adversary spec: node id {node_id} is outside "
            f"configured range [0, {node_cnt - 1}]"
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
