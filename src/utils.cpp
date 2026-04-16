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

void sendWrapper(char *buf, int sockfd, uint16_t len){
	int bytes_left = len;
	while(bytes_left){
		int curr_wr = send(sockfd, buf, bytes_left, 0);
		if(!curr_wr)
			break;
		else if(curr_wr < 0){
			if(errno == EINTR)
				continue;
			else{
				perror("send");	
                throw runtime_error("send failed");
			}
		}
		buf += curr_wr;
		bytes_left -= curr_wr;
	}

	if(bytes_left)
		throw runtime_error("send incomplete: " + to_string(bytes_left) + " bytes pending");
}

void sendPacket(string packet_str, int sockfd){
    uint16_t packet_len = packet_str.size(), converted_len = htons(packet_len);
    sendWrapper((char*) &converted_len, sockfd, LEN_BYTES);
    sendWrapper(packet_str.data(), sockfd, packet_len);
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

string getBase64Encoded(unsigned char* data, int len){
    int b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_URLSAFE);
    char b64_encoded[b64_len];
    return sodium_bin2base64(b64_encoded, b64_len, data, len, sodium_base64_VARIANT_URLSAFE);                             
}

string getBase64Decoded(string encoded){
    string bin;
    bin.resize(encoded.size());
    size_t bin_len;
    if(sodium_base642bin((unsigned char*) bin.data(), bin.size(), encoded.c_str(), encoded.size(), NULL, &bin_len, NULL, sodium_base64_VARIANT_URLSAFE)){
        cout << "\nbase64 decoding failed for: " << encoded << '\n';
        return "";
    }
    bin.resize(bin_len);
    return bin;
}

bool isValidReceipt(Receipt receipt, PubKey pub_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    if(sodium_base642bin(signature, sizeof(signature), receipt.signature.c_str(), receipt.signature.size(), NULL, NULL, NULL, sodium_base64_VARIANT_URLSAFE))
        return false;

    bool valid = !crypto_sign_verify_detached(signature, (unsigned char*) payload.c_str(), payload.size(), pub_key.signing);
    return valid;
}

void recvWrapper(char *buf, int sockfd, uint16_t len){
	int bytes_left = len;
	while(bytes_left){
		int curr_rd = recv(sockfd, buf, bytes_left, 0);
		if(!curr_rd)
			break;
		else if(curr_rd < 0){
			if(errno == EINTR)
				continue;
			else{
                perror("recv");
                throw runtime_error("recv failed");
            }
		}
		buf += curr_rd;
		bytes_left -= curr_rd;
	}

	if(bytes_left)
		throw runtime_error("recv incomplete: " + to_string(bytes_left) + " bytes pending");
}

string getPacket(int sockfd){
    uint16_t len;
    recvWrapper((char*) &len, sockfd, LEN_BYTES);
    len = ntohs(len);
    string data(len, 0);
    recvWrapper(data.data(), sockfd, len);
    return data;
}

template<typename T>
T getConfig(string config_path){
    ifstream fp_config(config_path);
    T config;
    string str;
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

PubKey getPubKey(string ip){
    fs::path pub_path = fs::path(KEYS_DIR) / PUB / (ip + KEY_SUFFIX);
    ifstream fp(pub_path, ios::binary);
    PubKey curr;
    fp.read((char*) curr.signing, crypto_sign_ed25519_PUBLICKEYBYTES);
    crypto_sign_ed25519_pk_to_curve25519(curr.encryption, curr.signing);
    return curr;
}

unordered_map<int, PubKey> getPubKeys(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config){
    unordered_map<int, PubKey> pub_keys;
    for(auto [id, node] : nw_config)
        pub_keys[id] = getPubKey(node.ip);
    pub_keys[ACCT_COMMON_ID] = getPubKey(ACCT_COMMON);
    for(auto [id, node] : acct_config)
        pub_keys[id] = pub_keys[ACCT_COMMON_ID];
    return pub_keys;
}

void loadPvtKey(unsigned char* pvt_signing, unsigned char* pvt_encryption, HostType host_type){
    fs::path pvt_path = fs::path(KEYS_DIR) / PVT;
    if(host_type == HostType::Node)
        pvt_path /= PVT;
    else
       pvt_path /= ACCT_COMMON;
    pvt_path += KEY_SUFFIX;

    ifstream fp(pvt_path, ios::binary);
    if(!fp.is_open())
        throw runtime_error("unable to load private key");
    fp.read((char*) pvt_signing, crypto_sign_ed25519_SECRETKEYBYTES);

    crypto_sign_ed25519_sk_to_curve25519(pvt_encryption, pvt_signing);
}

void storeReceipt(Receipt receipt){
    fs::path file_path = fs::path(RECEIPTS_DIR) / (receipt.packet_id + TXT);
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

string getEncrypted(unsigned char *pub_key, string message){
    string encrypted;
    int encrypted_len = message.size() + crypto_box_SEALBYTES;
    encrypted.resize(encrypted_len);
    crypto_box_seal((unsigned char*) encrypted.data(), (unsigned char*) message.data(), message.size(), pub_key);
    return encrypted;
}

string getOnionEncrypted(unordered_map<int, PubKey> &pub_keys, deque<int> route, vector<string> salts, vector<string> signatures, string packet_id, string content){
    // next_hop for dest is -1
    int next_hop = -1, n = route.size(), node = route[n - 1];
    string curr = string((char*) &next_hop, 4) + packet_id, encrypted;
    bool has_salts = !salts.empty();
    if(has_salts)
        curr += salts[n - 1] + getBase64Decoded(signatures[n - 1]);
    curr += content;
    encrypted = getEncrypted(pub_keys[node].encryption, curr);

    for(int i = n - 2; i >= 0; i--){
        next_hop = htonl(route[i + 1]), node = route[i];
        curr = string((char*) &next_hop, 4) + packet_id;
        if(has_salts)
            curr += salts[i] + getBase64Decoded(signatures[i]);
        curr += encrypted;
        encrypted = getEncrypted(pub_keys[node].encryption, curr);
    }
    return getBase64Encoded((unsigned char*) encrypted.data(), encrypted.size());
}

Layer getOnionDecrypted(PubKey &node_pub, unsigned char *pvt_encryption, string encoded, bool skip_headers){
    string bin = getBase64Decoded(encoded), decoded;
    Layer layer;
    if(bin.empty()){
        layer.next_hop = INT_MIN;
        return layer;
    }
    size_t bin_len = bin.size();
    decoded.resize(bin_len - crypto_box_SEALBYTES);

    if(crypto_box_seal_open((unsigned char*) decoded.data(), (unsigned char*) bin.data(), bin_len, node_pub.encryption, pvt_encryption)){
        layer.next_hop = INT_MIN;
        return layer;
    }

    int next_hop;
    memcpy(&next_hop, decoded.data(), HOP_ID_LEN);
    next_hop = ntohl(next_hop);
    int id_start = HOP_ID_LEN, salt_start = id_start + PACKET_ID_B64_LEN, signature_start = salt_start + SALT_LEN, payload_start = signature_start + crypto_sign_BYTES;

    layer.next_hop = next_hop;
    if(skip_headers){
        layer.payload = decoded.substr(4);
        return layer;
    }

    layer.id = decoded.substr(id_start, PACKET_ID_B64_LEN);
    layer.salt = decoded.substr(salt_start, SALT_LEN);
    layer.signature = decoded.substr(signature_start, crypto_sign_BYTES);
    layer.payload = decoded.substr(payload_start);
    return layer;
}

void signReceipt(Receipt &receipt, unsigned char *pvt_key){
    string payload = getReceiptPayload(receipt);
    unsigned char signature[crypto_sign_BYTES];

    crypto_sign_detached(signature, NULL, (unsigned char*) payload.c_str(), payload.size(), pvt_key);
    receipt.signature = getBase64Encoded(signature, crypto_sign_BYTES);
}

NodeState getNodeState(int node){
    fs::path node_state_path = fs::path("state") / (to_string(node) + TXT);
    ifstream in(node_state_path);

    NodeState node_state{};
    in >> node_state.allowed >> node_state.forwarded >> node_state.used;
    string id;
    while(in >> id)
        node_state.receipt_ids.insert(id);
    return node_state;
}

void writeNodeState(NodeState node_state, int node){
    fs::path node_state_path = fs::path("state") / (to_string(node) + TXT);
    ofstream out(node_state_path);
    out << node_state.allowed << ' ' << node_state.forwarded << ' ' << node_state.used << ' ';
    for(string id : node_state.receipt_ids)
        out << id << ' ';
}

string getHash(string salt, int hop){
    string hash_in = salt + to_string(hop), hash_out(crypto_hash_sha256_BYTES, 0);
    crypto_hash_sha256((unsigned char*) hash_out.data(), (unsigned char*) hash_in.data(), hash_in.size());
    return hash_out;
}

void processPacket(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys, Packet packet, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
                   int node_id, int prev_node){
    int payload_size = packet.payload.size();
    Layer layer = getOnionDecrypted(pub_keys[node_id], pvt_encryption, packet.payload, false);

    int next_hop_id = layer.next_hop;
    if(next_hop_id == INT_MIN){
        cout << "\ndecryption failed for packet" << '\n';
        return;
    }
    string packet_id = layer.id;

    if(prev_node != -1 && nw_config.count(prev_node)){
        Node prev_hop = nw_config[prev_node];
        int sockfd = createConnection(prev_hop.ip, prev_hop.port);
        Receipt receipt{packet_id, "", node_id, prev_node, payload_size};
        signReceipt(receipt, pvt_signing);
        string encrypted_receipt = getOnionEncrypted(pub_keys, {prev_node}, {}, {}, "", getReceiptPayload(receipt) + ' ' + receipt.signature);
        string receipt_str = RECEIPT_PREFIX + encrypted_receipt;
        sendPacket(receipt_str, sockfd);
        close(sockfd);
    }
    
    string msg = packet_id + getHash(layer.salt, node_id), payload = layer.payload;
    auto acct_pub_key = pub_keys[ACCT_COMMON_ID];
    bool is_valid = !crypto_sign_verify_detached((unsigned char*) layer.signature.data(), (unsigned char*) msg.data(), msg.size(), acct_pub_key.signing);

    if(!is_valid){
        cout << "\nsignature verification failed for packet " + packet_id << ". dropping packet\n";
        return;
    }
    unordered_set<string> prev_pkts;
    string prev_pkt;
    fs::path prev_pkts_path = fs::path(STATE_DIR) / (PREV_IDS + TXT);
    ifstream prev_pkts_in(prev_pkts_path);
    while(prev_pkts_in >> prev_pkt)
        prev_pkts.insert(prev_pkt);

    if(prev_pkts.count(packet_id)){
        cout << "\n duplicate packet id: " << packet_id << ". dropping packet\n";
        return;
    }
    ofstream prev_pkts_out(prev_pkts_path, ios::app);
    prev_pkts_out << packet_id << '\n';

    if(next_hop_id == -1){
        cout << "\npacket reached destination: " + packet_id + ' ' + payload << '\n';
        return;
    }
    else if(!nw_config.count(next_hop_id))
        throw runtime_error("invalid next hop");

    string b64_payload = getBase64Encoded((unsigned char*) payload.data(), payload.size());
    Node next_hop = nw_config[next_hop_id];
    int sockfd = createConnection(next_hop.ip, next_hop.port);
    
    sendPacket(b64_payload, sockfd);
    close(sockfd);
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
        node_state.used += MAX_LEN;
        node_state.allowed = true;
    }
    writeNodeState(node_state, node);
    return node_state.allowed;
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

void setNAK(string &acct_resp, int prev_node){
    acct_resp += NAK_STR;
    cout << "\ndenied send for " << prev_node << '\n';        
}

void handleProof(unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, string packet_str, int new_fd, 
                 int node_id, int prev_node){
    stringstream ss(packet_str);
    string pref, encrypted_proof_str, receipts_str, commitments_str, packet_id, commitment;
    vector<string> commitments;
    Proof proof;
    ss >> pref >> encrypted_proof_str;

    try{
        Layer layer = getOnionDecrypted(pub_keys[node_id], pvt_encryption, encrypted_proof_str, true);
        string payload = layer.payload;
        int delim = payload.find(RECEIPT_COMMITMENT_DELIM);
        if(delim == string::npos)
            throw runtime_error("missing proof delim");

        cout << "\nsuccesfully decrypted proof\n";
        int receipts_len =  delim - PACKET_ID_B64_LEN;
        packet_id = payload.substr(0, PACKET_ID_B64_LEN);
        receipts_str = payload.substr(PACKET_ID_B64_LEN, receipts_len);
        commitments_str = payload.substr(delim + 1);

        if(!receipts_str.empty()){
            proof = parseProof(receipts_str);
            cout << "proof " << receipts_str << '\n';
        }
        else
            cout << "no receipts found in proof\n";

        string commitment;
        ss = stringstream(commitments_str);
        while(ss >> commitment)
            commitments.push_back(commitment);
    } 
    catch(exception &e){
        cout << "\nerror while decrypting proof:" << e.what() << "\ndefaulting to initial forwarded value.\n";
    }

    string acct_resp = ACCT_RESP_PREFIX;
    if(canSend(proof, pub_keys, prev_node)){
        for(string commitment : commitments){
            string decoded_commitment = getBase64Decoded(commitment);

            if(decoded_commitment.empty())
                setNAK(acct_resp, prev_node);
            else{
                string msg = packet_id + decoded_commitment;
                unsigned char signature[crypto_sign_BYTES];
                crypto_sign_detached(signature, NULL, (unsigned char*) msg.data(), msg.size(), pvt_signing);
                acct_resp += ' ' + getBase64Encoded(signature, crypto_sign_BYTES);
            }
        }
    }
    else
        setNAK(acct_resp, prev_node);
    string encrypted_resp = getOnionEncrypted(pub_keys, {prev_node}, {}, {}, "", acct_resp);
    sendPacket(encrypted_resp.data(), new_fd);
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
                    string encrypted_payload = packet_str.substr(RECEIPT_PREFIX.size());
                    Layer layer = getOnionDecrypted(pub_keys[node_id], pvt_encryption, encrypted_payload, true);
                    Receipt receipt = parseReceipt(RECEIPT_PREFIX + layer.payload);
                    if(isValidReceipt(receipt, pub_keys[receipt.generator]))
                        storeReceipt(receipt);
                }
            }
            else if(packet_str.substr(0, PROOF_PREFIX.size()) == PROOF_PREFIX && host_type == HostType::Acct)
                handleProof(pub_keys, pvt_signing, pvt_encryption, packet_str, new_fd, node_id, prev_node);
            else{
                int prev_node = getNodeID(nw_config, acct_config, their_addr);
                Packet packet;
                packet.payload = packet_str;
                processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, prev_node);
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
}

void init(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
          HostType host_type, string nw_config_path, string acct_config_path, int argc){
    if(argc != 4)
        throw runtime_error("usage: node <id> <nw_config_path> <acct_config_path>");
    if(sodium_init() == -1)
            throw runtime_error("sodium_init failed");

    nw_config = getConfig<unordered_map<int, Node>>(nw_config_path);
    acct_config = getConfig<map<int, Node>>(acct_config_path);
    pub_keys = getPubKeys(nw_config, acct_config);
    loadPvtKey(pvt_signing, pvt_encryption, host_type);
}
