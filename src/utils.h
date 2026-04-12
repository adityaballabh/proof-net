
#include <sodium.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
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
using namespace std;

const int BACKLOG = 8, MAX_LEN = 4096, INIT_ALLOWED = MAX_LEN * 10;
const string receipt_prefix = "receipt ", proof_prefix = "proof ", acct_resp_prefix = "acct_resp ";

struct Node{
    int id, port;
    string ip;
};

struct Receipt{
    string packet_id, signature;
    int generator, receiver, bytes;
};

struct PubKey{
    unsigned char signing[crypto_sign_ed25519_PUBLICKEYBYTES], encryption[crypto_box_PUBLICKEYBYTES];
};

enum class HostType{
    Node, Acct
};

struct Packet{
    string id, payload;
};

struct Proof{
    vector<Receipt> receipts;
};

struct NodeState{
    bool allowed;
    int forwarded, used;
    unordered_set<string> receipt_ids;
};

int createServer(int port);
int createConnection(string ip, int port);
void sendWrapper(string message, int sockfd);
string getBase64Encoded(unsigned char* data, int len);
string getPacket(int sockfd);
unordered_map<int, Node> getConfig(string config_path);
void processPacket(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, Packet packet, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
                   int node_id, int prev_node, HostType host_type);
void processConnections(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, 
                        int sockfd, int node_id, HostType host_type);
void init(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, unsigned char* pvt_signing, unsigned char* pvt_encryption, string nw_config_path);
 