#include "utils.h"

struct AttackMessage {
  string content;
  deque<int> route;
  string packet_id;
};

string convertReceipt(Receipt receipt) {
  return RECEIPT_PREFIX + ' ' + getReceiptPayload(receipt) + ' ' +
         receipt.signature;
}

string convertProof(Proof proof) {
  string proof_str;
  for (Receipt receipt : proof.receipts)
    proof_str += convertReceipt(receipt) + RECEIPT_DELIM;
  return proof_str;
}

string getRandomId(int len) {
  string raw(len, 0);
  randombytes_buf(raw.data(), len);
  return getBase64Encoded((unsigned char *)raw.data(), len);
}

Proof getProof() {
  Proof proof;
  for (auto file : fs::directory_iterator(RECEIPTS_DIR)) {
    ifstream in(file.path());
    string receipt_str;
    getline(in, receipt_str);
    Receipt receipt;
    stringstream ss(receipt_str);
    ss >> receipt.packet_id >> receipt.generator >> receipt.receiver >>
        receipt.bytes >> receipt.signature;
    proof.receipts.push_back(receipt);
    fs::remove(file.path());
  }
  return proof;
}

Node getAcctNode(map<int, Node> &acct_config, int node_id) {
  int ind = node_id % acct_config.size();
  return next(acct_config.begin(), ind)->second;
}

string sendProofWithCommitments(unordered_map<int, PubKey> &pub_keys,
                                Node acct_node, Proof proof, Packet packet,
                                string packet_id) {
  int sockfd = createConnection(acct_node.ip, acct_node.port);
  string proof_str = packet_id + convertProof(proof) + RECEIPT_COMMITMENT_DELIM;
  for (string commitment : packet.commitments)
    proof_str += ' ' + commitment;

  string encrypted_proof =
      getOnionEncrypted(pub_keys, {acct_node.id}, {}, {}, "", proof_str);
  sendPacket(PROOF_PREFIX + encrypted_proof, sockfd);
  string acct_resp = getPacket(sockfd);
  close(sockfd);
  return acct_resp;
}

bool canSendPacket(map<int, Node> &acct_config,
                   unordered_map<int, PubKey> &pub_keys, Proof proof,
                   Packet &packet, unsigned char *pvt_encryption,
                   string packet_id, int node_id) {
  Node acct_node = getAcctNode(acct_config, node_id);
  string encrypted_resp =
      sendProofWithCommitments(pub_keys, acct_node, proof, packet, packet_id);
  Layer layer = getOnionDecrypted(pub_keys[node_id], pvt_encryption,
                                  encrypted_resp, true);
  string acct_resp = layer.payload;
  if (acct_resp == ACCT_RESP_PREFIX + NAK_STR)
    return false;

  stringstream ss(acct_resp);
  string prefix, signature;
  ss >> prefix;
  while (ss >> signature)
    packet.signatures.push_back(signature);
  return true;
}

Packet buildPacket(const deque<int> &route, string packet_id, string content,
                   bool use_valid_signatures) {
  Packet packet;
  string salt(SALT_LEN, 0);
  for (int hop : route) {
    randombytes_buf(salt.data(), SALT_LEN);
    packet.salts.push_back(salt);

    string hash_out = getHash(salt, hop);
    packet.commitments.push_back(getBase64Encoded(
        (unsigned char *)hash_out.data(), crypto_hash_sha256_BYTES));

    if (!use_valid_signatures) {
      string bogus_sig(crypto_sign_BYTES, 0);
      randombytes_buf(bogus_sig.data(), crypto_sign_BYTES);
      packet.signatures.push_back(getBase64Encoded(
          (unsigned char *)bogus_sig.data(), crypto_sign_BYTES));
    }
  }
  return packet;
}

AttackMessage makeAttackMessage(unordered_map<int, vector<int>> &adj,
                                int node_id, int dest, string content) {
  AttackMessage message;
  message.content = content;
  message.route = computeRoute(adj, node_id, dest);
  message.packet_id = getRandomId(PACKET_ID_LEN);
  return message;
}

void sendPacketWithoutAcct(unordered_map<int, Node> &nw_config,
                           unordered_map<int, PubKey> &pub_keys,
                           unsigned char *pvt_signing,
                           unsigned char *pvt_encryption, int node_id,
                           const AttackMessage &message) {
  Packet packet =
      buildPacket(message.route, message.packet_id, message.content, false);
  packet.payload =
      getOnionEncrypted(pub_keys, message.route, packet.salts,
                        packet.signatures, message.packet_id, message.content);
  cout << "\n[skip_verify] sending packet " << message.packet_id
       << " without accounting approval\n";
  processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption,
                node_id, -1);
}

void sendSelfishPackets(unordered_map<int, Node> &nw_config,
                        map<int, Node> &acct_config,
                        unordered_map<int, PubKey> &pub_keys,
                        unordered_map<int, vector<int>> &adj,
                        unsigned char *pvt_signing,
                        unsigned char *pvt_encryption, int node_id, int dest,
                        int count) {
  for (int i = 0; i < count; i++) {
    AttackMessage message =
        makeAttackMessage(adj, node_id, dest, "selfish packet " + to_string(i));
    Packet packet =
        buildPacket(message.route, message.packet_id, message.content, true);

    cout << "\n[selfish_send] attempt " << (i + 1) << " packet "
         << message.packet_id << '\n';
    if (!canSendPacket(acct_config, pub_keys, {}, packet, pvt_encryption,
                       message.packet_id, node_id)) {
      cout << "[selfish_send] accounting denied packet " << message.packet_id
           << '\n';
      continue;
    }

    packet.payload = getOnionEncrypted(pub_keys, message.route, packet.salts,
                                       packet.signatures, message.packet_id,
                                       message.content);
    processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption,
                  node_id, -1);
    sleep(1);
  }
}

void sendFakeReceipt(unordered_map<int, Node> &nw_config,
                     unordered_map<int, PubKey> &pub_keys,
                     unsigned char *pvt_signing, int node_id, int peer_id,
                     int bytes) {
  Receipt receipt{getRandomId(PACKET_ID_LEN), "", node_id, peer_id, bytes};
  signReceipt(receipt, pvt_signing);

  int sockfd = createConnection(nw_config[peer_id].ip, nw_config[peer_id].port);
  string encrypted_receipt =
      getOnionEncrypted(pub_keys, {peer_id}, {}, {}, "",
                        getReceiptPayload(receipt) + ' ' + receipt.signature);
  sendPacket(RECEIPT_PREFIX + encrypted_receipt, sockfd);
  close(sockfd);
  cout << "\n[collude] sent fake receipt " << receipt.packet_id << " to node "
       << peer_id << '\n';
}

void runCollusion(unordered_map<int, Node> &nw_config,
                  map<int, Node> &acct_config,
                  unordered_map<int, PubKey> &pub_keys,
                  unordered_map<int, vector<int>> &adj,
                  unsigned char *pvt_signing, unsigned char *pvt_encryption,
                  int node_id, int peer_id, int dest, int fake_receipt_cnt) {
  for (int i = 0; i < fake_receipt_cnt; i++)
    sendFakeReceipt(nw_config, pub_keys, pvt_signing, node_id, peer_id,
                    MAX_LEN);

  sleep(2);
  Proof proof = getProof();
  cout << "\n[collude] loaded " << proof.receipts.size()
       << " exchanged receipts before requesting send approval\n";

  AttackMessage message =
      makeAttackMessage(adj, node_id, dest, "colluding packet");
  Packet packet =
      buildPacket(message.route, message.packet_id, message.content, true);
  if (!canSendPacket(acct_config, pub_keys, proof, packet, pvt_encryption,
                     message.packet_id, node_id)) {
    cout << "[collude] accounting denied packet " << message.packet_id << '\n';
    return;
  }

  packet.payload =
      getOnionEncrypted(pub_keys, message.route, packet.salts,
                        packet.signatures, message.packet_id, message.content);
  cout << "[collude] accounting accepted fake receipts for packet "
       << message.packet_id << '\n';
  processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption,
                node_id, -1);
}

int main(int argc, char **argv) {
  map<int, Node> acct_config;
  unordered_map<int, Node> nw_config;
  unordered_map<int, vector<int>> adj;
  unordered_map<int, PubKey> pub_keys;
  unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES],
      pvt_encryption[crypto_box_SECRETKEYBYTES];
  HostType host_type = HostType::Node;
  cout << unitbuf;

  try {
    if (argc < 4)
      throw runtime_error("usage: adversary <id> <mode> <dest> [count|peer]");

    int node_id = stoi(argv[1]), sockfd, dest = stoi(argv[3]);
    string mode = argv[2];
    init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption,
         host_type, "", BOOTSTRAP_CONFIG_PATH, node_id, 2);
    sockfd = createServer(nw_config[node_id].port);

    if (!fork()) {
      sleep(2);
      close(sockfd);

      if (mode == "skip_verify") {
        AttackMessage message =
            makeAttackMessage(adj, node_id, dest, "skip verification");
        sendPacketWithoutAcct(nw_config, pub_keys, pvt_signing, pvt_encryption,
                              node_id, message);
      } else if (mode == "selfish_send") {
        int count = argc > 4 ? stoi(argv[4]) : 4;
        sendSelfishPackets(nw_config, acct_config, pub_keys, adj, pvt_signing,
                           pvt_encryption, node_id, dest, count);
      } else if (mode == "collude") {
        if (argc < 5)
          throw runtime_error(
              "usage: adversary <id> collude <dest> <peer> [fake_receipt_cnt]");
        int peer_id = stoi(argv[4]);
        int fake_receipt_cnt = argc > 5 ? stoi(argv[5]) : 2;
        runCollusion(nw_config, acct_config, pub_keys, adj, pvt_signing,
                     pvt_encryption, node_id, peer_id, dest, fake_receipt_cnt);
      } else
        throw runtime_error("unknown mode: " + mode);
      exit(0);
    }
    processConnections(nw_config, acct_config, pub_keys, adj, pvt_signing,
                       pvt_encryption, sockfd, node_id, host_type);
  } catch (exception &e) {
    cerr << e.what() << '\n';
    return 1;
  }
}
