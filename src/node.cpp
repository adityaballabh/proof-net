#include "utils.h"

struct Message{
    string id, content;
    deque<int> route;
    int dest, delay;
};

Message parseMessage(string message){
    stringstream ss_msg(message);
    Message msg;
    string content;
    ss_msg >> msg.id >> msg.delay >> msg.dest;
    getline(ss_msg, content);
    if(content.empty())
        throw runtime_error("no packet content found");
    msg.content = content.substr(1);
    return msg;
}

vector<pair<Message, Packet>> loadMessages(unordered_map<int, vector<int>> &adj, vector<int> &delays, int node_id){
    vector<pair<Message, Packet>> msg_pkt_pairs;
    string line, salt(SALT_LEN, 0), msg_id(PACKET_ID_LEN, 0);
    fs::path messages_path = fs::path(MESSAGES_DIR) / (INIT + TXT);
    ifstream in(messages_path);
    while(getline(in, line)){
        Message message = parseMessage(line);
        message.route = computeRoute(adj, node_id, message.dest);
        randombytes_buf(msg_id.data(), PACKET_ID_LEN);
        msg_id = getBase64Encoded((unsigned char*) msg_id.data(), PACKET_ID_LEN);
        cout << "\nprev packet id: " << message.id << ", new packet id: " << msg_id << '\n';
        message.id = msg_id;

        Packet packet;
        for(int hop : message.route){
            randombytes_buf(salt.data(), SALT_LEN);
            string hash_out = getHash(salt, hop);
            packet.salts.push_back(salt);

            string enc_hash = getBase64Encoded((unsigned char*) hash_out.data(), crypto_hash_sha256_BYTES);
            packet.commitments.push_back(enc_hash);
        }

        msg_pkt_pairs.push_back({message, packet});
        cout << "delay: " << message.delay  << "s message: " << line << '\n';
        delays.push_back(message.delay);
    }
    return msg_pkt_pairs;
}

string convertReceipt(Receipt receipt){
    return RECEIPT_PREFIX + ' ' + getReceiptPayload(receipt) + ' ' + receipt.signature;
}

string convertProof(Proof proof){
    string proof_str;
    for(Receipt r : proof.receipts)
        proof_str += convertReceipt(r) + RECEIPT_DELIM;
    return proof_str;
}

Proof getProof(){
    Proof proof;
    for(auto file : filesystem::directory_iterator(RECEIPTS_DIR)){
        ifstream in(file.path());
        string receipt_str;
        getline(in, receipt_str);
        Receipt r;
        stringstream ss(receipt_str);
        ss >> r.packet_id >> r.generator >> r.receiver >> r.bytes >> r.signature;
        proof.receipts.push_back(r);
        filesystem::remove(file.path());
    }
    return proof;
}

string sendProofWithCommitments(unordered_map<int, PubKey> &pub_keys, Node acct_node, Proof proof, Packet packet, string packet_id){
    string proof_str, packet_str, encrypted_proof_str;
    int sockfd = createConnection(acct_node.ip, acct_node.port);

    proof_str = packet_id + convertProof(proof) + RECEIPT_COMMITMENT_DELIM;
    for(string commitment: packet.commitments)
        proof_str += ' ' + commitment;
    encrypted_proof_str = getOnionEncrypted(pub_keys, {acct_node.id}, {}, {}, "", proof_str);

    packet_str = PROOF_PREFIX + encrypted_proof_str;
    sendPacket(packet_str, sockfd);
    string acct_resp = getPacket(sockfd);
    close(sockfd);
    return acct_resp;
}

Node getAcctNode(map<int, Node> &acct_config, int node_id){
    int n = acct_config.size(), ind = node_id % n;
    auto node_entry = next(acct_config.begin(), ind);
    return node_entry->second;
}

bool canSendPacket(map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Proof proof, Packet &packet, unsigned char* pvt_encryption, string packet_id, int node_id){
    Node acct_node = getAcctNode(acct_config, node_id);
    string encrypted_resp = sendProofWithCommitments(pub_keys, acct_node, proof, packet, packet_id);
    Layer layer = getOnionDecrypted(pub_keys[node_id], pvt_encryption, encrypted_resp, true);
    string acct_resp = layer.payload;
    
    if (acct_resp == ACCT_RESP_PREFIX + NAK_STR)
        return false;

    stringstream ss(acct_resp);
    string pref, signature;
    ss >> pref;
    while(ss >> signature)
        packet.signatures.push_back(signature);
    return true;
}

void validateAndSendPacket(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Proof proof, Message message, Packet packet, 
                       unsigned char* pvt_signing, unsigned char* pvt_encryption, int node_id){
    if(canSendPacket(acct_config, pub_keys, proof, packet, pvt_encryption, message.id, node_id)){
        packet.payload = getOnionEncrypted(pub_keys, message.route, packet.salts, packet.signatures, message.id, message.content);
        cout << "\nsending packet " << message.id << '\n';
        processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1);
    }
    else
        cout << "\nsend was denied for packet " << message.id << '\n';
}

int main(int argc, char **argv){
    map<int, Node> acct_config;
    unordered_map<int, Node> nw_config;
    unordered_map<int, vector<int>> adj;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Node;
    cout << unitbuf;

    try{
        int node_id = stoi(argv[1]), sockfd;
        init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, host_type, "", BOOTSTRAP_CONFIG_PATH, node_id, argc);
        sockfd = createServer(nw_config[node_id].port);

        if(!fork()){
            sleep(2);
            close(sockfd);
            vector<int> delays;
            vector<pair<Message, Packet>> msg_pkt_pairs = loadMessages(adj, delays, node_id);
            int packet_cnt = msg_pkt_pairs.size();
            for(int i = 0; i < packet_cnt; i++){
                auto [message, packet] = msg_pkt_pairs[i];
                sleep(delays[i]);
                Proof proof = getProof();
                validateAndSendPacket(nw_config, acct_config, pub_keys, proof, message, packet, pvt_signing, pvt_encryption, node_id);
            }
            exit(0);
        }
        processConnections(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, sockfd, node_id, host_type);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
