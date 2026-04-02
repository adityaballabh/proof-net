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
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <netdb.h>
#include <cstring>
using namespace std;

struct Node{
    int id, port;
    string ip;
};

struct Packet{
    string id, content;
    deque<int> route;
    int prev_node;
};

struct Receipt{
    string packet_id;
    int generator, bytes;
};

const int BACKLOG = 8, MAX_LEN = 1024;
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

string convertPacket(Packet packet){
    deque<int> route = packet.route;
    string msg = packet.id + ' ' + to_string(packet.prev_node) + ' ' + to_string(route[0]);
    int hops = route.size();
    for(int i = 1; i < hops; i++)
        msg += ',' + to_string(packet.route[i]);
    msg += ' ' + packet.content + '\n';
    return msg;
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

string convertReceipt(Receipt receipt){
    return receipt_prefix + receipt.packet_id + ' ' + to_string(receipt.generator) + ' ' + to_string(receipt.bytes) + '\n';
}

void storeReceipt(string receipt, int node_id){
    stringstream ss(receipt);
    string pref, packet_id;
    int generator, bytes;
    ss >> pref >> packet_id >> generator >> bytes;

    string file_path = "receipts/" + to_string(node_id) + '/' + packet_id + ".txt";
    ofstream out(file_path);
    out << packet_id << ' ' << generator << ' ' << bytes << '\n';
}

void processPacket(unordered_map<int, Node> &config, Packet packet, int node_id){
    deque<int> route = packet.route;
    if(route.empty() || route.front() != node_id)
        throw runtime_error("incorrectly routed packet");
    
    if(packet.prev_node != -1){
        Node prev_hop = config[packet.prev_node];
        int sockfd = createConnection(prev_hop.ip, prev_hop.port);

        Receipt receipt{packet.id, node_id, (int) packet.content.size()};
        string receipt_str = convertReceipt(receipt);
        sendWrapper(receipt_str, sockfd);
        close(sockfd);
    }

    route.pop_front();
    if(route.empty()){
        cout << node_id << " packet reached destination: " << packet.id << ' ' << packet.content << '\n';
        return;
    }
    int next_hop_id = route.front();
    if(!config.count(next_hop_id))
        throw runtime_error("invalid next hop");
    
    Node next_hop = config[next_hop_id];
    int sockfd = createConnection(next_hop.ip, next_hop.port);
    
    packet.route = route;
    packet.prev_node = node_id;
    string message = convertPacket(packet);
    sendWrapper(message, sockfd);
    close(sockfd);
}

// messages are always a single line
string getMessage(int sockfd){
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

Packet parseMessage(string message){
    stringstream ss_msg(message);
    Packet packet;
    string route, tok, content;
    ss_msg >> packet.id >> packet.prev_node >> route;
    getline(ss_msg, content);
    if(content.empty())
        throw runtime_error("no packet content found");
    packet.content = content.substr(1);

    stringstream ss_route(route);
    while(getline(ss_route, tok, ',')){
        int node = stoi(tok);
        packet.route.push_back(node);
    }
    return packet;
}

vector<Packet> loadMessages(int node_id){
    vector<Packet> packets;
    string path = "messages/" + to_string(node_id) + ".txt", line;
    ifstream fp(path);
    while(getline(fp, line)){
        cout << node_id << " sending: " << line << '\n';
        Packet packet = parseMessage(line);
        packets.push_back(packet);
    }
    return packets;
}

void processConnections(unordered_map<int, Node> &config, int sockfd, int node_id){
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
            string message = getMessage(new_fd);
            cout << node_id << " received: " << message << '\n';
            
            if(message.substr(0, receipt_prefix.size()) == receipt_prefix)
                storeReceipt(message, node_id);
            else{
                Packet packet = parseMessage(message);
                processPacket(config, packet, node_id);
            }
            close(new_fd);
            exit(0);
        }
        close(new_fd);
    }
}

int main(int argc, char **argv){
    try{
        if(argc != 3)
            throw runtime_error("usage: node <id> <config_path>");
        int node_id = stoi(argv[1]);
        string config_path = argv[2];
        unordered_map<int, Node> config = getConfig(config_path);
        if(config.empty())
            throw runtime_error("no config found at " + config_path);

        int sockfd = createServer(config[node_id].port);
        if(!fork()){
            sleep(2);
            close(sockfd);
            vector<Packet> packets = loadMessages(node_id);
            for(Packet packet : packets)
                processPacket(config, packet, node_id);
            exit(0);
        }
        processConnections(config, sockfd, node_id);
    } 
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
