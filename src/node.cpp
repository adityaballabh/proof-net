#include "utils.h"

struct Message {
    string id, content;
    deque<int> route;
    int dest, delay;
};

Message parseMessage(string message, int node_cnt) {
    stringstream ss_msg(message);
    Message msg{};
    string content;
    ss_msg >> ws;
    if (ss_msg.eof() || ss_msg.peek() == '#')
        return msg;
    ss_msg >> msg.id >> msg.delay >> msg.dest;
    if (!ss_msg) {
        cerr << "\nerror occurred while parsing " << message << ". ignoring message\n";
        return msg;
    }
    if (msg.dest < 0 || msg.dest >= node_cnt) {
        cerr << "\ninvalid dest: " << msg.dest << ". ignoring message\n";
        return msg;
    }
    if (msg.delay < 0) {
        cerr << "\ninvalid delay: " << msg.delay << ". ignoring message\n";
        return msg;
    }
    getline(ss_msg, content);
    if (content.empty())
        return msg;
    msg.content = content.substr(1);
    return msg;
}

vector<pair<Message, Packet>> loadMessages(unordered_map<int, vector<int>> &adj, vector<int> &delays, int node_id) {
    vector<pair<Message, Packet>> msg_pkt_pairs;
    string line, salt(SALT_LEN, 0), msg_id(PACKET_ID_LEN, 0);
    fs::path messages_path = fs::path(MESSAGES_DIR) / (INIT + TXT);
    ifstream in(messages_path);
    while (getline(in, line)) {
        Message message = parseMessage(line, adj.size());
        if (message.content.empty())
            continue;
        message.route = computeRoute(adj, node_id, message.dest);
        msg_id = generateId(PACKET_ID_LEN);
        stringstream ss_sched;
        ss_sched << "\nscheduled message. prev packet id: " << message.id << ", new packet id: " << msg_id << '\n';
        cout << ss_sched.str();
        message.id = msg_id;

        Packet packet;
        stringstream ss_route;
        ss_route << "computed route: ";
        for (int hop : message.route) {
            ss_route << hop << ' ';
            randombytes_buf(salt.data(), SALT_LEN);
            string hash_out = getHash(salt, hop);
            packet.salts.push_back(salt);

            string enc_hash = getBase64Encoded((unsigned char *)hash_out.data(), crypto_hash_sha256_BYTES);
            packet.commitments.push_back(enc_hash);
        }
        cout << ss_route.str();

        msg_pkt_pairs.push_back({message, packet});
        stringstream ss_delay;
        ss_delay << "\ndelay: " << message.delay << "s message: " << line << '\n';
        cout << ss_delay.str();
        delays.push_back(message.delay);
    }
    return msg_pkt_pairs;
}

void validateAndSendPacket(unordered_map<int, Node> &nw_config, map<int, Node> &acct_config,
                           unordered_map<int, PubKey> &pub_keys, Proof proof, Message message, Packet packet,
                           unsigned char *pvt_signing, unsigned char *pvt_encryption, int node_id, HostType host_type) {
    stringstream out;
    if (canSendPacket(acct_config, pub_keys, proof, packet, pvt_encryption, message.id, node_id)) {
        packet.payload =
            getOnionEncrypted(pub_keys, message.route, packet.salts, packet.signatures, message.id, message.content);

        int payload_len = message.content.size(), route_len = message.route.size(), onion_len = packet.payload.size();
        if (!payload_len)
            return;
        double ratio = (double)onion_len / payload_len;

        stringstream ss_metrics;
        ss_metrics << "\nmetrics for " << message.id << " route length: " << route_len
                   << " hops, payload size: " << payload_len << " B, onion size: " << onion_len
                   << " B, onion/payload: " << fixed << setprecision(1) << ratio << '\n';
        cout << ss_metrics.str();
        out << "\nsending packet " << message.id << '\n';
        cout << out.str();
        processPacket(nw_config, pub_keys, packet, pvt_signing, pvt_encryption, node_id, -1, host_type);
    } else {
        out << "\nsend was denied for packet " << message.id << '\n';
        cout << out.str();
    }
}

int main(int argc, char **argv) {
    map<int, Node> acct_config;
    unordered_map<int, Node> nw_config;
    unordered_map<int, vector<int>> adj;
    unordered_map<int, PubKey> pub_keys;
    unsigned char pvt_signing[crypto_sign_ed25519_SECRETKEYBYTES], pvt_encryption[crypto_box_SECRETKEYBYTES];
    HostType host_type = HostType::Node;
    cout << unitbuf;

    try {
        int node_id = stoi(argv[1]), sockfd;
        init(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, host_type, "", BOOTSTRAP_CONFIG_PATH,
             argc);
        sockfd = createServer(nw_config[node_id].port);

        if (!fork()) {
            sleep(DEFAULT_SLEEP_SEC);
            close(sockfd);
            vector<int> delays;
            vector<pair<Message, Packet>> msg_pkt_pairs = loadMessages(adj, delays, node_id);
            int packet_cnt = msg_pkt_pairs.size();
            time_t start_time = time(0);
            for (int i = 0; i < packet_cnt; i++) {
                auto [message, packet] = msg_pkt_pairs[i];
                int delay = delays[i] - (time(0) - start_time);
                sleep(delay);
                Proof proof = getProof();
                validateAndSendPacket(nw_config, acct_config, pub_keys, proof, message, packet, pvt_signing,
                                      pvt_encryption, node_id, host_type);
            }
            exit(0);
        }
        processConnections(nw_config, acct_config, pub_keys, adj, pvt_signing, pvt_encryption, sockfd, node_id,
                           host_type);
    } catch (exception &e) {
        cerr << e.what() << '\n';
        return 1;
    }
}
