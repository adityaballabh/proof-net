#include <fstream>
#include <iostream>
#include <sodium.h>
using namespace std;

int main(int argc, char **argv) {
  if (argc != 3) {
    cerr << "usage: gen_key <pvt_path> <pub_path>\n";
    return 1;
  }
  if (sodium_init() == -1) {
    cerr << "sodium_init failed";
    return 1;
  }

  unsigned char pvt[crypto_sign_ed25519_SECRETKEYBYTES],
      pub[crypto_sign_ed25519_PUBLICKEYBYTES];
  crypto_sign_keypair(pub, pvt);

  ofstream pvt_out(argv[1], ios::binary), pub_out(argv[2], ios::binary);
  pvt_out.write((char *)pvt, crypto_sign_ed25519_SECRETKEYBYTES);
  pub_out.write((char *)pub, crypto_sign_ed25519_PUBLICKEYBYTES);
}
