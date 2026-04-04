#include <iostream>
#include <fstream>
#include <sodium.h>
using namespace std;

int main(int argc, char **argv){
    if(argc != 3){
        cerr << "usage: gen_key <pvt_path> <pub_path>\n";
        return 1;
    }
    if(sodium_init() == -1){
        cerr << "sodium_init failed";
        return 1;
    }

    unsigned char pvt[crypto_sign_ed25519_SECRETKEYBYTES], pub[crypto_sign_ed25519_PUBLICKEYBYTES];
    crypto_sign_keypair(pub, pvt);

    ofstream fp_pvt(argv[1], ios::binary), fp_pub(argv[2], ios::binary);
    fp_pvt.write((char*) pvt, crypto_sign_ed25519_SECRETKEYBYTES);
    fp_pub.write((char*) pub, crypto_sign_ed25519_PUBLICKEYBYTES);
}
