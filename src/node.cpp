#include "utils.h"

struct Message{
    string id, content;
    deque<int> route;
    int delay;
};

string getEncrypted(unsigned char *pub_key, string message){
    string encrypted;
    int encrypted_len = message.size() + crypto_box_SEALBYTES;
    encrypted.resize(encrypted_len);
    crypto_box_seal((unsigned char*) encrypted.data(), (unsigned char*) message.data(), message.size(), pub_key);
    return encrypted;
}

string getOnionEncrypted(unordered_map<int, PubKey> &pub_keys, deque<int> route, string content){
    // next_hop for dest is -1
    int next_hop = -1, n = route.size(), node = route[n - 1];
    string curr = string((char*) &next_hop, 4) + content, encrypted;
    encrypted = getEncrypted(pub_keys[node].encryption, curr);

    for(int i = n - 2; i >= 0; i--){
        next_hop = htonl(route[i + 1]), node = route[i];
        curr = string((char*) &next_hop, 4) + encrypted;
        encrypted = getEncrypted(pub_keys[node].encryption, curr);
    }
    return getBase64Encoded((unsigned char*) encrypted.data(), encrypted.size());
}

Message parseMessage(string message){
    stringstream ss_msg(message);
    Message msg;
    string route, tok, content;
    ss_msg >> msg.id >> msg.delay >> route;
    getline(ss_msg, content);
    if(content.empty())
        throw runtime_error("no packet content found");
    msg.content = content.substr(1);

    stringstream ss_route(route);
    while(getline(ss_route, tok, ',')){
        int node = stoi(tok);
        msg.route.push_back(node);
    }
    return msg;
}

vector<Packet> loadMessages(unordered_map<int, PubKey> &pub_keys, vector<int> &delays, int node_id){
    vector<Packet> packets;
    string path = "messages/init.txt", line;
    ifstream fp(path);
    while(getline(fp, line)){
        Message message = parseMessage(line);
        Packet packet;
        packet.id = message.id;
        packet.payload = getOnionEncrypted(pub_keys, message.route, message.content);
        packets.push_back(packet);
        cout << "\ndelay: " << message.delay  << "s message: " << line << '\n';
        delays.push_back(message.delay);
    }
    return packets;
}

string convertProof(Proof proof){
    string proof_str;
    for(Receipt r : proof.receipts)
        proof_str += convertReceipt(r) + RECEIPT_DELIM;
    return proof_str;
}

Proof getProof(){
    Proof proof;
    for(auto file : filesystem::directory_iterator("receipts/")){
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

string sendProof(Node acct_node, unordered_map<int, PubKey> &pub_keys, Proof proof, int node_id){
    string proof_str, packet_str, encrypted_proof_str;
    int sockfd = createConnection(acct_node.ip, acct_node.port);

    if(!proof.receipts.empty()){
        proof_str = convertProof(proof);
        encrypted_proof_str = getOnionEncrypted(pub_keys, {acct_node.id}, proof_str);
    }

    packet_str = PROOF_PREFIX + encrypted_proof_str + '\n';
    sendWrapper(packet_str, sockfd);
    string acct_resp = getPacket(sockfd);
    close(sockfd);
    return acct_resp;
}

Node getAcctNode(map<int, Node> &acct_config, int node_id){
    int n = acct_config.size(), ind = node_id % n;
    auto it = acct_config.begin();
    advance(it, ind);
    return it->second;
}

bool canSendPacket(map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Proof proof, int node_id){
    Node acct_node = getAcctNode(acct_config, node_id);
    string acct_resp = sendProof(acct_node, pub_keys, proof, node_id);
    return acct_resp == ACCT_RESP_PREFIX + ACK_STR;
}

void sendPacketWrapper(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Proof proof, Packet packet, 
                       unsigned char* pvt_signing, unsigned char* pvt_encryption, int node_id, int prev_node, HostType host_type){
    if(canSendPacket(acct_config, pub_keys, proof, node_id)){
        cout << "\nsending packet " << packet.id << '\n';
        processPacket(nw_config, acct_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1, host_type);
    }
    else
        cout << "\nsend was denied for packet " << packet.id << '\n';
}

int main(int argc, char **argv){
    unordered_map<int, Node> nw_config;
    map<int, Node> acct_config;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Node;
    cout << unitbuf;

    try{
        init(nw_config, acct_config, pub_keys, pvt_signing, pvt_encryption, argv[2], argv[3], argc);
        int node_id = stoi(argv[1]), sockfd = createServer(nw_config[node_id].port);

        if(!fork()){
            sleep(2);
            close(sockfd);
            vector<int> delays;
            vector<Packet> packets = loadMessages(pub_keys, delays, node_id);
            int packet_cnt = packets.size();
            for(int i = 0; i < packet_cnt; i++){
                Packet packet = packets[i];
                sleep(delays[i]);
                Proof proof = getProof();
                sendPacketWrapper(nw_config, acct_config, pub_keys, proof, packet, pvt_signing, pvt_encryption, node_id, -1, host_type);
            }
            exit(0);
        }
        processConnections(nw_config, acct_config, pub_keys, pvt_signing, pvt_encryption, sockfd, node_id, host_type);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
