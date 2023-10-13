#include <stdint.h>

void initialize_aes_sbox(uint8_t sbox[256]);
void initialize_aes_inv_sbox(uint8_t inv_sbox[256]);
static void aes128_subBytes(uint8_t block[16]);
static void aes128_shiftRows(uint8_t block[16]);
static void mixColumns(uint8_t block[16]);
static void aes128_addRoundKey(uint8_t block[16], uint8_t key[16]);
static void aes128_expandKey(uint8_t block[16], uint8_t round);
static void aes128_g(uint8_t word[4], uint8_t round);
static void aes128_encrypt(uint8_t block[16], const uint8_t key[16]);
