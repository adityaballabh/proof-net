#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <deque>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <netdb.h>
#include <cstring>
#include <sodium.h>
using namespace std;

struct Node{
    int id, port;
    string ip;
};

struct Message{
    string id, content;
    deque<int> route;
};

struct Packet{
    string id, payload;
};

struct Receipt{
    string packet_id, signature;
    int generator, receiver, bytes;
};

struct PubKey{
    unsigned char signing[crypto_sign_ed25519_PUBLICKEYBYTES], encryption[crypto_box_PUBLICKEYBYTES];
};

const int BACKLOG = 8, MAX_LEN = 4096;
const string receipt_prefix = "receipt ";

unordered_map<int, Node> getConfig(string config_path){
    ifstream fp_config(config_path);
    unordered_map<int, Node> config;
    string str;
    int id = 0;
    while(getline(fp_config, str)){
        stringstream ss(str);
        Node node;
        ss >> node.port >> node.ip;
        config[id++] = node;
    }
    return config;
}

// adapted from Beej's guide
int createServer(int port){
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("socket");
        exit(1);
    }

    int reuse = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) == -1){
        perror("setsockopt");
        exit(1);
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if(::bind(sockfd, (sockaddr *)&addr, sizeof(addr)) == -1){
        close(sockfd);
        perror("bind");
        exit(1);
    }

    if(listen(sockfd, BACKLOG) == -1){
        perror("listen");
        exit(1);
    }
    return sockfd;
}

void sigchld_handler(int s){
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

int createConnection(string ip, int port){
    int sockfd, rv;
    struct addrinfo hints, *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    string port_str = to_string(port);
    if((rv = getaddrinfo(ip.c_str(), port_str.c_str(), &hints, &servinfo)) != 0){
        cerr << "getaddrinfo: " << gai_strerror(rv);
        exit(1);
    }

    for(p = servinfo; p != NULL; p = p->ai_next){
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("client: socket");
            continue;
        }
        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            perror("client: connect");
            continue;
        }
        break;
    }
    if(!p){
        cerr << "client: failed to connect\n";
        exit(1);
    }
    freeaddrinfo(servinfo);
    return sockfd;
}

void sendWrapper(string message, int sockfd){
    int len = message.size(), sent = 0;
    while(sent < len){
        int curr = send(sockfd, message.c_str() + sent, len - sent, 0);
        if(curr < 0){
            perror("send");
            exit(1);
        }
        sent += curr;
    }
}

string getReceiptPayload(Receipt receipt){
    return receipt.packet_id + ' ' + to_string(receipt.generator) + ' ' + to_string(receipt.receiver) + ' ' + to_string(receipt.bytes);
}

string convertReceipt(Receipt receipt){
    return receipt_prefix + ' ' + getReceiptPayload(receipt) + ' ' + receipt.signature  + '\n';
}

Receipt parseReceipt(string receipt_str){
    stringstream ss(receipt_str);
    string pref;
    Receipt receipt;
    ss >> pref >> receipt.packet_id >> receipt.generator >> receipt.receiver >> receipt.bytes >> receipt.signature;
    return receipt;
}

void storeReceipt(Receipt receipt){
    string file_path = "receipts/" + receipt.packet_id + ".txt";
    ofstream out(file_path);
    out << getReceiptPayload(receipt) + ' ' + receipt.signature << '\n';
}

string getBase64Encoded(unsigned char* data, int len){
    int b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char b64_encoded[b64_len];
    return sodium_bin2base64(b64_encoded, b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);                             
}

void signReceipt(Receipt &receipt, unsigned char *pvt_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    crypto_sign_detached(signature, NULL, (unsigned char*) payload.c_str(), payload.size(), pvt_key);
    receipt.signature = getBase64Encoded(signature, crypto_sign_BYTES);
}

bool isValidReceipt(Receipt receipt, PubKey pub_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    if(sodium_base642bin(signature, sizeof(signature), receipt.signature.c_str(), receipt.signature.size(), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL))
        return false;

    bool valid = !crypto_sign_verify_detached(signature, (unsigned char*) payload.c_str(), payload.size(), pub_key.signing);
    return valid;
}

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

pair<int, string> getOnionDecrypted(PubKey &node_pub, unsigned char *pvt_encryption, string encoded){
    string bin, decoded, payload;
    bin.resize(encoded.size());
    size_t bin_len;
    if(sodium_base642bin((unsigned char*) bin.data(), bin.size(), encoded.c_str(), encoded.size(), NULL, &bin_len, NULL, sodium_base64_VARIANT_ORIGINAL))
        return {INT_MIN, ""};
    bin.resize(bin_len);

    decoded.resize(bin_len - crypto_box_SEALBYTES);
    if(crypto_box_seal_open((unsigned char*) decoded.data(), (unsigned char*) bin.data(), bin_len, node_pub.encryption, pvt_encryption))
        return {INT_MIN, ""};

    int next_hop;
    memcpy(&next_hop, decoded.data(), 4);
    next_hop = ntohl(next_hop);
    payload = decoded.substr(4);
    return {next_hop, payload};
}

void processPacket(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, Packet packet, unsigned char* pvt_signing, unsigned char* pvt_encryption, int node_id, int prev_node){
    if(prev_node != -1){
        Node prev_hop = config[prev_node];
        int sockfd = createConnection(prev_hop.ip, prev_hop.port);
        Receipt receipt{packet.id, "", node_id, prev_node, (int) packet.payload.size()};
        signReceipt(receipt, pvt_signing);
        string receipt_str = convertReceipt(receipt);
        sendWrapper(receipt_str, sockfd);
        close(sockfd);
    }

    auto [next_hop_id, payload] = getOnionDecrypted(pub_keys[node_id], pvt_encryption, packet.payload);
    if(next_hop_id == INT_MIN){
        cerr << node_id << " decryption failed for packet " + packet.id << '\n';
        return;
    }
    else if(next_hop_id == -1){
        cout << node_id << " packet reached destination: " + packet.id + ' ' + payload << '\n';
        return;
    }
    
    if(!config.count(next_hop_id))
        throw runtime_error("invalid next hop");
    
    string b64_payload = getBase64Encoded((unsigned char*) payload.data(), payload.size());
    Node next_hop = config[next_hop_id];
    int sockfd = createConnection(next_hop.ip, next_hop.port);
    
    string message = packet.id + ' ' + b64_payload + '\n';
    sendWrapper(message, sockfd);
    close(sockfd);
}

// messages are always a single line
string getPacket(int sockfd){
    string data;
    char buf[MAX_LEN];
    size_t term_pos;
    int rcvd = 0;
    while((rcvd = recv(sockfd, buf, MAX_LEN, 0)) > 0){
        data.append(buf, rcvd);
        term_pos = data.find('\n');
        if(term_pos != string::npos){
            data.erase(term_pos);
            break;
        }
    }
    return data;
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

Packet parsePacket(string message){
    stringstream ss(message);
    Packet packet;
    ss >> packet.id >> packet.payload;
    return packet;
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

int getNodeID(unordered_map<int, Node> &config, sockaddr_storage addr){
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));   
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    in_addr_t ip_addr = ((sockaddr_in*) &addr)->sin_addr.s_addr;
    for(auto [id, node] : config){
        addrinfo *servinfo;
        if(getaddrinfo(node.ip.c_str(), NULL, &hints, &servinfo) != 0)
            continue;
        sockaddr_in* curr = (sockaddr_in*) servinfo->ai_addr;
        in_addr_t curr_addr = curr->sin_addr.s_addr;
        freeaddrinfo(servinfo);

        if(curr_addr == ip_addr)
            return id;
    }
    return -1;
}

void processConnections(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, int sockfd, int node_id){
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if(sigaction(SIGCHLD, &sa, NULL) == -1){
        perror("sigaction");
        exit(1);
    }

    while(true){
        sockaddr_storage their_addr;
        socklen_t sin_size = sizeof(their_addr);

        int new_fd = accept(sockfd, (sockaddr *)&their_addr, &sin_size);
        if(new_fd == -1){
            perror("accept");
            continue;
        }
        if(!fork()){
            close(sockfd);
            string packet_str = getPacket(new_fd);
            cout << node_id << " received: " << packet_str << '\n';
            
            if(packet_str.substr(0, receipt_prefix.size()) == receipt_prefix){
                Receipt receipt = parseReceipt(packet_str);
                if(isValidReceipt(receipt, pub_keys[receipt.generator]))
                    storeReceipt(receipt);
            }
            else{
                int prev_node = getNodeID(config, their_addr);
                Packet packet = parsePacket(packet_str);
                processPacket(config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, prev_node);
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
}

unordered_map<int, PubKey> getPubKeys(int node_cnt){
    unordered_map<int, PubKey> pub_keys;

    for(int i = 0; i < node_cnt; i++){
        string path = "keys/pub/" + to_string(i) + ".key";
        ifstream fp(path, ios::binary);
        PubKey curr;
        fp.read((char*) curr.signing, crypto_sign_ed25519_PUBLICKEYBYTES);
        crypto_sign_ed25519_pk_to_curve25519(curr.encryption, curr.signing);
        pub_keys[i] = curr;
    }
    return pub_keys;
}

void loadPvtKey(unsigned char* pvt_signing, unsigned char* pvt_encryption){
    string path = "keys/pvt.key";
    ifstream fp(path, ios::binary);
    if(!fp.is_open())
        throw runtime_error("unable to load private key");
    fp.read((char*) pvt_signing, crypto_sign_ed25519_SECRETKEYBYTES);
    crypto_sign_ed25519_sk_to_curve25519(pvt_encryption, pvt_signing);
}

int main(int argc, char **argv){
    try{
        if(argc != 3)
            throw runtime_error("usage: node <id> <config_path>");
        if(sodium_init() == -1)
            throw runtime_error("sodium_init failed");

        int node_id = stoi(argv[1]);
        string config_path = argv[2];
        unordered_map<int, Node> config = getConfig(config_path);
        if(config.empty())
            throw runtime_error("no config found at " + config_path);
        
        int node_cnt = config.size();
        unordered_map<int, PubKey> pub_keys = getPubKeys(node_cnt);

        unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
        loadPvtKey(pvt_signing, pvt_encryption);
        
        int sockfd = createServer(config[node_id].port);
        if(!fork()){
            sleep(2);
            close(sockfd);
            vector<Packet> packets = loadMessages(pub_keys, node_id);
            for(Packet packet : packets)
                processPacket(config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1);
            exit(0);
        }
        processConnections(config, pub_keys, pvt_signing, pvt_encryption, sockfd, node_id);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
