#include "utils.h"

struct AttackMessage {
    string content;
    deque<int> route;
    string packet_id;
};

Packet buildPacket(const deque<int> &route, string packet_id, string content, bool use_valid_signatures) {
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
    cout << "\n[" << mode << "] sending packet " << message.packet_id << '\n';

    processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1);
    sleep(2);
}

void sendPacketWithoutAcct(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                           unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id,
                           const AttackMessage &message, string mode) {
    Packet packet = buildPacket(message.route, message.packet_id, message.content, false);
    sendAttackPacket(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, packet, mode);
}

void sendSkipVerifyPackets(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys,
                           unordered_map<int, vector<int>> &adj, unsigned char *pvt_signing,
                           unsigned char *pvt_encryption, int node_id, int dest, int rep_cnt, string mode) {
    for (int i = 0; i < rep_cnt; i++) {
        AttackMessage message = makeAttackMessage(adj, node_id, dest, mode + to_string(i));
        sendPacketWithoutAcct(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, mode);
        sleep(2);
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
    cout << "\n[" << mode << "] sent fake receipt " << receipt.packet_id << " to node " << peer_id << '\n';
}

void sendAttackPacketIfApproved(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                                unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                                unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest,
                                Proof proof, string mode, int attempt = 0) {
    AttackMessage message = makeAttackMessage(adj, node_id, dest, mode + to_string(attempt));
    Packet packet = buildPacket(message.route, message.packet_id, message.content, true);
    if (!canSendPacket(acct_config, pub_keys, proof, packet, pvt_encryption, message.packet_id, node_id)) {
        cout << "[" << mode << "] acct denied packet " << message.packet_id << '\n';
        return;
    }
    sendAttackPacket(nw_config, pub_keys, pvt_signing, pvt_encryption, node_id, message, packet, mode);
}

void sendSelfishPackets(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                        unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                        unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest, int count,
                        string mode) {
    for (int i = 0; i < count; i++) {
        cout << "\n[" << mode << "] attempt " << i << '\n';
        sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   {}, mode, i);
    }
}

void sendSelfIssuedReceipts(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                            unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                            unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int dest,
                            int rep_cnt, string mode) {
    for (int i = 0; i < rep_cnt; i++)
        sendFakeReceipt(nw_config, pub_keys, pvt_signing, node_id, node_id, MAX_LEN, mode);
    sleep(2);

    Proof proof = getProof();
    cout << "\n[" << mode << "] loaded " << proof.receipts.size() << " self-issued receipts\n";
    sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest, proof,
                               mode);
}

void runCollusion(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                  unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &adj,
                  unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int peer_id, int dest,
                  int rep_cnt, string mode) {
    for (int i = 0; i < rep_cnt; i++)
        sendFakeReceipt(nw_config, pub_keys, pvt_signing, node_id, peer_id, MAX_LEN, mode);
    sleep(2);

    Proof proof = getProof();
    cout << "\n[" << mode << "] loaded " << proof.receipts.size() << " fake peer-issued receipts\n";
    sendAttackPacketIfApproved(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest, proof,
                               mode);
}

int main(int argc, char **argv) {
    map<int, Node> acct_config;
    unordered_map<int, Node> nw_config;
    unordered_map<int, vector<int>> adj;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Node;
    cout << unitbuf;

    try {
        if (argc < 4)
            throw runtime_error("usage: adversary <id> <mode> <dest> [mode_args]");

        int node_id = stoi(argv[1]), sockfd, dest = stoi(argv[3]);
        string mode = argv[2];
        init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, host_type, "", BOOTSTRAP_CONFIG_PATH,
             node_id, 2);
        sockfd = createServer(nw_config[node_id].port);

        if (!fork()) {
            sleep(2);
            close(sockfd);

            if (mode == SKIP_VERIFY) {
                if (argc > 5)
                    throw runtime_error("usage: adversary <id> skip_verify <dest> [rep_cnt]");
                int rep_cnt = argc == 5 ? stoi(argv[4]) : 1;
                sendSkipVerifyPackets(nw_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest, rep_cnt,
                                      mode);
            } else if (mode == SELFISH_SEND) {
                if (argc > 5)
                    throw runtime_error("usage: adversary <id> selfish_send <dest> [rep_cnt]");
                int rep_cnt = argc == 5 ? stoi(argv[4]) : 4;
                sendSelfishPackets(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, dest,
                                   rep_cnt, mode);
            } else if (mode == SELF_RECEIPTS) {
                if (argc > 5)
                    throw runtime_error("usage: adversary <id> self_receipts <dest> [rep_cnt]");
                int rep_cnt = argc == 5 ? stoi(argv[4]) : 2;
                sendSelfIssuedReceipts(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id,
                                       dest, rep_cnt, mode);
            } else if (mode == COLLUDE) {
                if (argc < 5 || argc > 6)
                    throw runtime_error("usage: adversary <id> collude <dest> <peer> [rep_cnt]");
                int peer_id = stoi(argv[4]), rep_cnt = argc == 6 ? stoi(argv[5]) : 2;
                runCollusion(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, node_id, peer_id, dest,
                             rep_cnt, mode);
            } else if (mode == REPLAY) {

            } else
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
