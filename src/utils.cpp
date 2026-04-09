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

string convertReceipt(Receipt receipt){
    return receipt_prefix + ' ' + getReceiptPayload(receipt) + ' ' + receipt.signature  + '\n';
}

string getBase64Encoded(unsigned char* data, int len){
    int b64_len = sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL);
    char b64_encoded[b64_len];
    return sodium_bin2base64(b64_encoded, b64_len, data, len, sodium_base64_VARIANT_ORIGINAL);                             
}

string getReceiptPayload(Receipt receipt){
    return receipt.packet_id + ' ' + to_string(receipt.generator) + ' ' + to_string(receipt.receiver) + ' ' + to_string(receipt.bytes);
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

unordered_map<int, Node> getConfig(string config_path){
    ifstream fp_config(config_path);
    unordered_map<int, Node> config;
    string str;
    int id = 0;
    while(getline(fp_config, str)){
        stringstream ss(str);
        Node node;
        ss >> node.id >> node.port >> node.ip;
        config[node.id] = node;
    }
    return config;
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
