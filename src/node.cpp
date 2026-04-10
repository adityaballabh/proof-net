#include "utils.h"

struct Message{
    string id, content;
    deque<int> route;
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
    ss_msg >> msg.id >> route;
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

vector<Packet> loadMessages(unordered_map<int, PubKey> &pub_keys, int node_id){
    vector<Packet> packets;
    string path = "messages/" + to_string(node_id) + ".txt", line;
    ifstream fp(path);
    while(getline(fp, line)){
        cout << node_id << " sending: " << line << '\n';
        Message message = parseMessage(line);
        Packet packet;
        packet.id = message.id;
        packet.payload = getOnionEncrypted(pub_keys, message.route, message.content);
        packets.push_back(packet);
    }
    return packets;
}

int main(int argc, char **argv){
    unordered_map<int, Node> config;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Node;
    
    try{
        if(argc != 3)
            throw runtime_error("usage: node <id> <nw_config_path>");
        
        init(config, pub_keys, pvt_signing, pvt_encryption, argv[2]);
        int node_id = stoi(argv[1]), sockfd = createServer(config[node_id].port);

        if(!fork()){
            sleep(2);
            close(sockfd);
            vector<Packet> packets = loadMessages(pub_keys, node_id);
            for(Packet packet : packets)
                processPacket(config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1, host_type);
            exit(0);
        }
        processConnections(config, pub_keys, pvt_signing, pvt_encryption, sockfd, node_id, host_type);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
