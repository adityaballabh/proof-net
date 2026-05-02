
#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <queue>
#include <random>
#include <signal.h>
#include <sodium.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
using namespace std;
namespace fs = std::filesystem;

const int BACKLOG = 8, MAX_LEN = 256, INIT_ALLOWED = MAX_LEN * 2, HOP_ID_LEN = 4, PACKET_ID_LEN = 8, SALT_LEN = 16,
          ACCT_COMMON_ID = -1, LEN_BYTES = 2,
          PACKET_ID_B64_LEN = sodium_base64_encoded_len(PACKET_ID_LEN, sodium_base64_VARIANT_URLSAFE) - 1,
          MAX_RANDOM_HOP_CNT = 3, MAX_RETRY_CNT = 5, RETRY_SECS = 1;

const string RECEIPT_PREFIX = "receipt ", PROOF_PREFIX = "proof ", ACCT_RESP_PREFIX = "acct_resp ", ACK_STR = "ACK",
             NAK_STR = "NAK", ACCT_COMMON = "acct_common", INIT = "init", PREV_IDS = "prev_ids", KEYS_DIR = "keys",
             STATE_DIR = "state", RECEIPTS_DIR = "receipts", MESSAGES_DIR = "messages", PUB = "pub", PVT = "pvt",
             KEY_SUFFIX = ".key", TXT = ".txt", BOOTSTRAP_REQ_PREFIX = "bootstrap_req",
             BOOTSTRAP_RESP_PREFIX = "bootstrap_resp", NW_CONFIG_PATH = "nw_config.txt",
             ACCT_CONFIG_PATH = "acct_config.txt", TOPO_CONFIG_PATH = "topo.txt", BOOTSTRAP_CONFIG_PATH = "acct.txt";

const char RECEIPT_DELIM = ';', RECEIPT_COMMITMENT_DELIM = '|';

inline default_random_engine gen(random_device{}());

struct Node {
    int id, port;
    string ip;
};

struct Receipt {
    string packet_id, signature;
    int generator, receiver, bytes;
};

struct PubKey {
    unsigned char signing[crypto_sign_ed25519_PUBLICKEYBYTES], encryption[crypto_box_PUBLICKEYBYTES];
};

enum class HostType { Node, Acct };

struct Packet {
    string payload;
    vector<string> salts, commitments, signatures;
};

struct Proof {
    vector<Receipt> receipts;
};

struct NodeState {
    bool allowed;
    int forwarded, used;
    unordered_set<string> receipt_ids;
};

struct Layer {
    int next_hop;
    string id, salt, signature, payload;
};

int createServer(int port);
int createConnection(string ip, int port);
void sendPacket(string message, int sockfd);
string getBase64Encoded(unsigned char *data, int len);
string getBase64Decoded(string encoded);
string getReceiptPayload(Receipt receipt);
string getPacket(int sockfd);
string getOnionEncrypted(unordered_map<int, PubKey> &pub_keys, deque<int> route, vector<string> salts,
                         vector<string> signatures, string packet_id, string content);
unordered_map<int, Node> getConfig(string config_path);
Layer getOnionDecrypted(PubKey &node_pub, unsigned char *pvt_encryption, string encoded, bool skip_headers);
string getHash(string salt, int hop);
void signReceipt(Receipt &receipt, unsigned char *pvt_key);
void processPacket(unordered_map<int, Node> &nw_config, unordered_map<int, PubKey> &pub_keys, Packet packet,
                   unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, int prev_node);
void processConnections(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                        unordered_map<int, PubKey> &pub_keys, unordered_map<int, vector<int>> &edges,
                        unsigned char *pvt_signing, unsigned char *pvt_encryption, int sockfd, int node_id,
                        HostType host_type);
deque<int> computeRoute(unordered_map<int, vector<int>> &adj, int src, int dest);
Proof getProof();
bool canSendPacket(map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys, Proof proof, Packet &packet,
                   unsigned char *pvt_encryption, string packet_id, int node_id);
string generateId(int len);
void init(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config, unordered_map<int, PubKey> &pub_keys,
          unordered_map<int, vector<int>> &adj, unsigned char *pvt_signing, unsigned char *pvt_encryption,
          HostType host_type, string nw_config_path, string acct_config_path, int node_id, int argc);
