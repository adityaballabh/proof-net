import sys
from pathlib import Path

DOCKER_DIR = Path("docker")
BOOTSTRAP_DIR = Path("bootstrap")
DEF_NODE_CNT = 7
DEF_ACCT_CNT = 3
NW_BASE_PORT = 2000
ACCT_BASE_ID = 3000
ACCT_BASE_PORT = 3000

def gen_node(id, acct_cnt):
    svc_name = f"node{id}"
    acct_id = id % acct_cnt
    return f"""
  {svc_name}:
    image: proof-net
    command: /node {id}
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

if node_cnt <= 0 or acct_cnt <= 0:
    sys.exit("node_cnt and acct_cnt must be positive integers")

compose_path = DOCKER_DIR / "docker-compose.yml"
nw_config_path = DOCKER_DIR / "nw_config.txt"
acct_config_path = DOCKER_DIR / "acct_config.txt"

compose_out = "services:"
nw_out = ""
acct_out = ""

for id in range(node_cnt):
    node_port = NW_BASE_PORT + id
    compose_out += gen_node(id, acct_cnt)
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
