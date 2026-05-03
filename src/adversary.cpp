#include "utils.h"

struct AttackMessage {
    string content;
    deque<int> route;
    string packet_id;
};

Packet buildPacket(const deque<int> &route, bool use_valid_signatures) {
    Packet packet;
    string salt(SALT_LEN, 0);
    for (int hop : route) {
        randombytes_buf(salt.data(), SALT_LEN);
        packet.salts.push_back(salt);

        string hash_out = getHash(salt, hop);
        packet.commitments.push_back(getBase64Encoded((unsigned char *)hash_out.data(), crypto_hash_sha256_BYTES));

        if (!use_valid_signatures) {
            string bogus_sig(crypto_sign_BYTES, 0);
            randombytes_buf(bogus_sig.data(), crypto_sign_BYTES);
            packet.signatures.push_back(getBase64Encoded((unsigned char *)bogus_sig.data(), crypto_sign_BYTES));
        }
    }
    return packet;
}

AttackMessage makeAttackMessage(unordered_map<int, vector<int>> &adj, int node_id, int dest, string content) {
    AttackMessage message;
    message.content = content;
    message.route = computeRoute(adj, node_id, dest);
    message.packet_id = generateId(PACKET_ID_LEN);
    return message;
}

void sendAttackPacket(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                      unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id,
                      const AttackMessage &message, Packet &packet, const string &mode) {
    packet.payload =
        getOnionEncrypted(pub_keys, message.route, packet.salts, packet.signatures, message.packet_id, message.content);
    stringstream out;
    out << "\n[" << mode << "] sending packet " << message.packet_id << '\n';
    cout << out.str();

    processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1, HostType::Adversary);
    sleep(DEFAULT_SLEEP_SEC);
}

void sendPacketWithoutAcct(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                           unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id,
                           const AttackMessage &message, string mode) {
    Packet packet = buildPacket(message.route, false);
    sendAttackPacket(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, packet, mode);
}

void sendSkipVerifyPackets(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                           unordered_map<int, vector<int>> &adj, unsigned char *pvt_signing,
                           unsigned char *pvt_encryption, int node_id, int dest, int rep_cnt, string mode) {
    for (int i = 0; i < rep_cnt; i++) {
        AttackMessage message = makeAttackMessage(adj, node_id, dest, mode + to_string(i));
        sendPacketWithoutAcct(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, mode);
    }
}

void sendFakeReceipt(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                     unsigned char *pvt_signing, int node_id, int peer_id, int bytes, string mode) {
    Receipt receipt{generateId(PACKET_ID_LEN), "", node_id, peer_id, bytes};
    signReceipt(receipt, pvt_signing);

    int sockfd = createConnection(nw_config[peer_id].ip, nw_config[peer_id].port);
    string encrypted_receipt =
        getOnionEncrypted(pub_keys, {peer_id}, {}, {}, "", getReceiptPayload(receipt) + ' ' + receipt.signature);
    sendPacket(RECEIPT_PREFIX + encrypted_receipt, sockfd);
    close(sockfd);
    stringstream out;
    out << "\n[" << mode << "] sent fake receipt " << receipt.packet_id << " to node " << peer_id << '\n';
    cout << out.str();
}

string sendAttackPacketIfApproved(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                                  unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                                  unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest,
                                  Proof proof, string mode, int attempt = 0, string packet_id = "") {
    string content = mode + to_string(attempt);
    AttackMessage message = makeAttackMessage(adj, node_id, dest, content);
    if (!packet_id.empty())
        message.packet_id = packet_id;

    Packet packet = buildPacket(message.route, true);
    if (!canSendPacket(acct_config, pub_keys, proof, packet, pvt_encryption, message.packet_id, node_id)) {
        stringstream out;
        out << "[" << mode << "] acct denied packet " << message.packet_id << '\n';
        cout << out.str();
        return "";
    }

    sendAttackPacket(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, packet, mode);
    return message.packet_id;
}

void sendSelfishPackets(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                        unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                        unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest, int count,
                        string mode) {
    for (int i = 0; i < count; i++) {
        stringstream out;
        out << "\n[" << mode << "] attempt " << i << '\n';
        cout << out.str();
        sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   {}, mode, i);
    }
}

void sendSelfIssuedReceipts(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                            unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                            unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest,
                            int rep_cnt, string mode) {
    // use up initial credit
    int init_cnt = INIT_ALLOWED / MAX_LEN;
    for (int i = 0; i < init_cnt; i++)
        sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   {}, mode + "_honest", i);

    for (int i = 0; i < rep_cnt; i++)
        sendFakeReceipt(nw_config, pub_keys, pvt_signing, node_id, node_id, MAX_LEN, mode);
    sleep(DEFAULT_SLEEP_SEC);

    Proof proof = getProof();
    stringstream out;
    out << "\n[" << mode << "] loaded " << proof.receipts.size() << " receipts (including " << rep_cnt << " self-issued)\n";
    cout << out.str();
    sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest, proof,
                               mode);
}

void sendReplayPackets(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                       unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                       unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest, int rep_cnt,
                       string mode) {
    vector<string> packet_ids;
    // initial non-malicious sends
    for (int i = 0; i < rep_cnt; i++) {
        string packet_id = sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing,
                                                      pvt_encryption, node_id, dest, {}, mode + "_honest", i);
        if (!packet_id.empty())
            packet_ids.push_back(packet_id);
    }

    if (packet_ids.empty()) {
        stringstream out;
        out << "\n[" << mode << "] no packet ids to replay\n";
        cout << out.str();
        return;
    }

    stringstream out;
    out << "\n[" << mode << "] replaying " << packet_ids.size() << " packet ids\n";
    cout << out.str();
    for (int i = 0; i < packet_ids.size(); i++)
        sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   {}, mode, i, packet_ids[i]);
}

int main(int argc, char **argv) {
    map<int, Node> acct_config;
    unordered_map<int, Node> nw_config;
    unordered_map<int, vector<int>> adj;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Adversary;
    cout << unitbuf;

    try {
        if (argc < 4 || argc > 5)
            throw runtime_error("usage: adversary <id> <mode> <dest> [rep_cnt]");

        int node_id = stoi(argv[1]), sockfd, dest = stoi(argv[3]);
        string mode = argv[2];
        init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, host_type, "", BOOTSTRAP_CONFIG_PATH,
             2);
        sockfd = createServer(nw_config[node_id].port);

        if (!fork()) {
            sleep(DEFAULT_SLEEP_SEC);
            close(sockfd);
            int rep_cnt = argc == 5 ? stoi(argv[4]) : DEFAULT_REP_CNT;
            if (mode == SKIP_VERIFY)
                sendSkipVerifyPackets(nw_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest, rep_cnt,
                                      mode);
            else if (mode == SELFISH_SEND)
                sendSelfishPackets(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   rep_cnt, mode);
            else if (mode == SELF_RECEIPTS)
                sendSelfIssuedReceipts(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id,
                                       dest, rep_cnt, mode);
            else if (mode == REPLAY)
                sendReplayPackets(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                  rep_cnt, mode);
            else
                throw runtime_error("unknown mode: " + mode);
            exit(0);
        }
        processConnections(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, sockfd, node_id,
                           host_type);
    } catch (exception &e) {
        cerr << e.what() << '\n';
        return 1;
    }
}
