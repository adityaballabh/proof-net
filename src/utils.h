
#include <sodium.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
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
using namespace std;

const int BACKLOG = 8, MAX_LEN = 4096;
const string receipt_prefix = "receipt ";

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

int createServer(int port);
void sigchld_handler(int s);
int createConnection(string ip, int port);
void sendWrapper(string message, int sockfd);
Receipt parseReceipt(string receipt_str);
string convertReceipt(Receipt receipt);
string getBase64Encoded(unsigned char* data, int len);
string getReceiptPayload(Receipt receipt);
bool isValidReceipt(Receipt receipt, PubKey pub_key);
string getPacket(int sockfd);
unordered_map<int, Node> getConfig(string config_path);
unordered_map<int, PubKey> getPubKeys(int node_cnt);
