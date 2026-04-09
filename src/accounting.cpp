#include "utils.h"

void processConnections(unordered_map<int, Node> &config, unordered_map<int, PubKey> &pub_keys, int sockfd, int node_id){

}

int main(int argc, char **argv){
     try{
        if(argc != 4)
            throw runtime_error("usage: acct <id> <nw_config_path> <acct_config_path>");
        if(sodium_init() == -1)
            throw runtime_error("sodium_init failed");

        int node_id = stoi(argv[1]);
        string nw_config_path = argv[2];
        unordered_map<int, Node> nw_config = getConfig(nw_config_path);
        if(nw_config.empty())
            throw runtime_error("no network config found at " + nw_config_path);
        
        int node_cnt = nw_config.size();
        unordered_map<int, PubKey> pub_keys = getPubKeys(node_cnt);

        string acct_config_path = argv[3];
        unordered_map<int, Node> acct_config = getConfig(acct_config_path);
        if(acct_config.empty())
            throw runtime_error("no accounting config found at " + acct_config_path);

        int sockfd = createServer(acct_config[node_id].port);
        processConnections(nw_config, pub_keys, sockfd, node_id);
    }
    catch(exception &e){
        cerr << e.what() << '\n';
        return 1;
    }
}
