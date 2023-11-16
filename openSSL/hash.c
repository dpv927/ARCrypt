#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "params.h"

void calculateHash(const u_char* m, const size_t m_size, 
  unsigned char hash[SHA2_BYTES]) 
{
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, SHA2_ALGORITHM, NULL);
  EVP_DigestUpdate(mdctx, m, m_size);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
}