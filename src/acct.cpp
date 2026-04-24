#include "utils.h"

unordered_map<int, vector<int>> getTopology(string path){
    unordered_map<int, vector<int>> adj;
    ifstream in(path);
    int u, v;
    while(in >> u >> v){
        adj[u].push_back(v);
        adj[v].push_back(u);
    }
    if(adj.empty())
        throw runtime_error("missing topology in " + path);
    return adj;
}

int main(int argc, char **argv){
    map<int, Node> acct_config;
    unordered_map<int, Node> nw_config;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Acct;
    cout << unitbuf;
    
    try{
        int node_id = stoi(argv[1]), sockfd;
        unordered_map<int, vector<int>> adj = getTopology(TOPO_CONFIG_PATH);
        
        init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, host_type, NW_CONFIG_PATH, ACCT_CONFIG_PATH, node_id, argc);
        sockfd = createServer(acct_config[node_id].port);
        processConnections(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, sockfd, node_id, host_type);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
