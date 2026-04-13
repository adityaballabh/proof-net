#include "utils.h"

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

Receipt parseReceipt(string receipt_str){
    stringstream ss(receipt_str);
    string pref;
    Receipt receipt;
    ss >> pref >> receipt.packet_id >> receipt.generator >> receipt.receiver >> receipt.bytes >> receipt.signature;
    return receipt;
}

string getReceiptPayload(Receipt receipt){
    return receipt.packet_id + ' ' + to_string(receipt.generator) + ' ' + to_string(receipt.receiver) + ' ' + to_string(receipt.bytes);
}

string convertReceipt(Receipt receipt){
    return RECEIPT_PREFIX + ' ' + getReceiptPayload(receipt) + ' ' + receipt.signature;
}

string getBase64Encoded(unsigned char* data, int len){
    int b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char b64_encoded[b64_len];
    return sodium_bin2base64(b64_encoded, b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);                             
}

bool isValidReceipt(Receipt receipt, PubKey pub_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    if(sodium_base642bin(signature, sizeof(signature), receipt.signature.c_str(), receipt.signature.size(), NULL, NULL, NULL, sodium_base64_VARIANT_ORIGINAL))
        return false;

    bool valid = !crypto_sign_verify_detached(signature, (unsigned char*) payload.c_str(), payload.size(), pub_key.signing);
    return valid;
}

// packets are always a single line
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

template<typename T>
T getConfig(string config_path){
    ifstream fp_config(config_path);
    T config;
    string str;
    int id = 0;
    while(getline(fp_config, str)){
        stringstream ss(str);
        Node node;
        ss >> node.id >> node.port >> node.ip;
        config[node.id] = node;
    }
    if(config.empty())
        throw runtime_error("no config found at " + config_path);
    return config;
}

PubKey getPubKey(HostType host_type, string ip){
    string path = "keys/pub/" + ip + ".key";
    ifstream fp(path, ios::binary);
    PubKey curr;
    fp.read((char*) curr.signing, crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_sign_ed25519_pk_to_curve25519(curr.encryption, curr.signing);
    return curr;
}

unordered_map<int, PubKey> getPubKeys(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config){
    unordered_map<int, PubKey> pub_keys;
    for(auto [id, node] : nw_config)
        pub_keys[id] = getPubKey(HostType::Node, node.ip);
    for(auto [id, acct] : acct_config)
        pub_keys[id] = getPubKey(HostType::Acct, acct.ip);

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

Packet parsePacket(string message){
    stringstream ss(message);
    Packet packet;
    ss >> packet.id >> packet.payload;
    return packet;
}

void storeReceipt(Receipt receipt){
    string file_path = "receipts/" + receipt.packet_id + ".txt";
    ofstream out(file_path);
    out << getReceiptPayload(receipt) + ' ' + receipt.signature << '\n';
}

int getNodeID(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, sockaddr_storage addr){
    addrinfo hints;
    memset(&hints, 0, sizeof(hints));   
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    in_addr_t ip_addr = ((sockaddr_in*) &addr)->sin_addr.s_addr;

    auto matchID = [hints, ip_addr](auto &config){
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
    };

    int id = matchID(nw_config);
    if(id == -1)
        id = matchID(acct_config);
    return id;
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

void signReceipt(Receipt &receipt, unsigned char *pvt_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    crypto_sign_detached(signature, NULL, (unsigned char*) payload.c_str(), payload.size(), pvt_key);
    receipt.signature = getBase64Encoded(signature, crypto_sign_BYTES);
}

NodeState getNodeState(int node){
    string path = "state/" + to_string(node) + ".txt";
    ifstream in(path);

    NodeState node_state{};
    in >> node_state.allowed >> node_state.forwarded >> node_state.used;
    string id;
    while(in >> id)
        node_state.receipt_ids.insert(id);
    return node_state;
}

void writeNodeState(NodeState node_state, int node){
    string path = "state/" + to_string(node) + ".txt";
    ofstream out(path);
    out << node_state.allowed << ' ' << node_state.forwarded << ' ' << node_state.used << ' ';
    for(string id : node_state.receipt_ids)
        out << id << ' ';
}

void processPacket(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Packet packet, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
                   int node_id, int prev_node, HostType host_type){
    int payload_size = packet.payload.size();

    if(prev_node != -1 && nw_config.count(prev_node) && host_type == HostType::Node){ // prevents source from getting receipts since first hop is always Acct
        Node prev_hop = nw_config[prev_node];
        int sockfd = createConnection(prev_hop.ip, prev_hop.port);
        Receipt receipt{packet.id, "", node_id, prev_node, payload_size};
        signReceipt(receipt, pvt_signing);
        string receipt_str = convertReceipt(receipt) + '\n';
        sendWrapper(receipt_str, sockfd);
        close(sockfd);
    }

    auto [next_hop_id, payload] = getOnionDecrypted(pub_keys[node_id], pvt_encryption, packet.payload);
    if(next_hop_id == INT_MIN){
        cout << "\ndecryption failed for packet " + packet.id << '\n';
        return;
    }
    else if(next_hop_id == -1){
        cout << "\npacket reached destination: " + packet.id + ' ' + payload << '\n';
        return;
    }
    HostType next_hop_type = HostType::Node; 
    if(!nw_config.count(next_hop_id) && !acct_config.count(next_hop_id))
        throw runtime_error("invalid next hop");\
    else if(acct_config.count(next_hop_id))
        next_hop_type = HostType::Acct;

    if(host_type == HostType::Acct){
        NodeState prev_node_state = getNodeState(prev_node);
        if(!prev_node_state.allowed)
            return;
        prev_node_state.allowed = false;
        prev_node_state.used += payload_size;
        writeNodeState(prev_node_state, prev_node);
    }

    string b64_payload = getBase64Encoded((unsigned char*) payload.data(), payload.size());
    Node next_hop;
    if(next_hop_type == HostType::Node)
        next_hop = nw_config[next_hop_id];
    else
        next_hop = acct_config[next_hop_id];
    int sockfd = createConnection(next_hop.ip, next_hop.port);
    
    string message = packet.id + ' ' + b64_payload + '\n';
    sendWrapper(message, sockfd);
    close(sockfd);
}

Proof parseProof(string proof_str){
    stringstream proof_ss(proof_str);
    string pref, receipt_str;
    Proof proof;

    while(getline(proof_ss, receipt_str, RECEIPT_DELIM)){
        if(receipt_str.size() <= 1)
            continue;
        Receipt receipt = parseReceipt(receipt_str);
        proof.receipts.push_back(receipt);
    }
    return proof;
}

bool canSend(Proof proof, unordered_map<int, PubKey> &pub_keys, int node){
    NodeState node_state = getNodeState(node);
    for(Receipt r : proof.receipts){
        if(node_state.receipt_ids.count(r.packet_id) || !isValidReceipt(r, pub_keys[r.generator]) || r.generator == node)
            continue;
        node_state.receipt_ids.insert(r.packet_id);
        node_state.forwarded += r.bytes;
    }

    int max_used = node_state.used + MAX_LEN, thresh = node_state.forwarded * 2 + INIT_ALLOWED;
    if(max_used <= thresh){
        node_state.forwarded = 0;
        node_state.used = 0;
        node_state.allowed = true;
    }
    writeNodeState(node_state, node);
    return node_state.allowed;
}

void processConnections(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
                        int sockfd, int node_id, HostType host_type){
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
            int prev_node = getNodeID(nw_config, acct_config, their_addr);
            cout << "\nreceived";
            if(prev_node != -1)
                cout << " from " << prev_node;
            cout << ": " << packet_str << '\n';
            
            if(packet_str.substr(0, RECEIPT_PREFIX.size()) == RECEIPT_PREFIX){
                if(host_type == HostType::Node){
                    Receipt receipt = parseReceipt(packet_str);
                    if(isValidReceipt(receipt, pub_keys[receipt.generator]))
                        storeReceipt(receipt);
                }
            }
            else if(packet_str.substr(0, PROOF_PREFIX.size()) == PROOF_PREFIX && host_type == HostType::Acct){
                string encrypted_proof_str = packet_str.substr(PROOF_PREFIX.size());
                Proof proof;

                try{
                    auto [next_hop, proof_str] = getOnionDecrypted(pub_keys[node_id], pvt_encryption, encrypted_proof_str);
                    proof = parseProof(proof_str);
                    cout << "\nsuccessfully decrypted proof:\n";
                    cout << "proof " << proof_str << '\n';
                } 
                catch(exception &e){
                    cout << "\nfound no receipts or invalid proof. defaulting to initial forwarded value.\n";
                }

                string acct_resp = ACCT_RESP_PREFIX;
                if(canSend(proof, pub_keys, prev_node))
                    acct_resp += ACK_STR;
                else{
                    acct_resp += NAK_STR;
                    cout << "\ndenied send for " << prev_node << '\n';
                }
                acct_resp += '\n';
                sendWrapper(acct_resp, new_fd);
            }
            else{
                int prev_node = getNodeID(nw_config, acct_config, their_addr);
                Packet packet = parsePacket(packet_str);
                processPacket(nw_config, acct_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, prev_node, host_type);
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
}

void init(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, 
          unsigned char* pvt_signing, unsigned char* pvt_encryption, string nw_config_path, string acct_config_path, int argc){
    if(argc != 4)
        throw runtime_error("usage: node <id> <nw_config_path> <acct_config_path>");
    if(sodium_init() == -1)
            throw runtime_error("sodium_init failed");

    nw_config = getConfig<unordered_map<int, Node>>(nw_config_path);
    acct_config = getConfig<map<int, Node>>(acct_config_path);
    pub_keys = getPubKeys(nw_config, acct_config);
    loadPvtKey(pvt_signing, pvt_encryption);
}
