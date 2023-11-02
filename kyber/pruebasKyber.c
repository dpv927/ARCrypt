#include <stdlib.h>
#include <kyber_api.h>
#include <stdint.h>

int main() {
    uint8_t pk[pqcrystals_kyber1024_PUBLICKEYBYTES];
    uint8_t sk[pqcrystals_kyber1024_SECRETKEYBYTES];
    unsigned char shared_secret[pqcrystals_kyber1024_BYTES];
    unsigned char ciphertext[pqcrystals_kyber512_ref_CIPHERTEXTBYTES];

    pqcrystals_kyber1024_ref_keypair(pk, sk);
    pqcrystals_kyber1024_ref_enc(ciphertext, shared_secret, pk);
    return 0;
}
