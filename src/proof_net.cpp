#include <iostream>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <cstdlib>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
using namespace std;

struct Node{
    int id, port;
    string ip;
};

const int BACKLOG = 8, MAX_LEN = 1024;

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

void processConnections(int sockfd){
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
            cout << "received: " << message << '\n';
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
        processConnections(sockfd);
    } 
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
