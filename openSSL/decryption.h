#pragma once

#include <stdlib.h>
#include "params.h"

#define DEC_BUFF_SIZE     8192
#define DEC_CIPHER_SIZE   DEC_BUFF_SIZE

// --- Funcion principal
void decryptFile(const char* inputFile, const char* passwd, const char* keyFile);

// --- Desencriptar clave RSA con AES
int decryptRSAKey_withAES(const u_char* cipher_rsa_key, u_char* rsa_key, const size_t rsa_len, 
  const u_char aes_key[AES_KEY_BYTES], const u_char aes_key_iv[AES_IV_BYTES]);

// --- Desencriptar clave AES con RSA
// void decryptAESKey_withRSA(const u_char cipher_aes_key[RSA_KEY_BYTES], u_char aes_key[AES_KEY_BYTES],
//  unsigned char* rsa_skey, size_t rsa_keylen);

void decryptAESKey_withRSA(const u_char cipher_aesk[RSA_KEY_BYTES], u_char aesk[AES_KEY_BYTES],
  unsigned char* rsa_skey, size_t rsa_keylen);

  void decryptAESIV_withRSA(const u_char cipher_aesk_iv[RSA_KEY_BYTES], u_char aesk_iv[AES_IV_BYTES],
  unsigned char* rsa_skey, size_t rsa_keylen);