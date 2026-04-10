#include "utils.h"

int main(int argc, char **argv){
    unordered_map<int, Node> nw_config, acct_config;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Acct;
        
    try{
        if(argc != 4)
            throw runtime_error("usage: acct <id> <nw_config_path> <acct_config_path>");
        
        init(nw_config, pub_keys, pvt_signing, pvt_encryption, argv[2]);
        acct_config = getConfig(argv[3]);
        int node_id = stoi(argv[1]), sockfd = createServer(acct_config[node_id].port);

        processConnections(nw_config, pub_keys, pvt_signing, pvt_encryption, sockfd, node_id, host_type);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
