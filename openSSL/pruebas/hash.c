#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

/// 
/// @brief Calculates the hash value over a buffer.
/// 
/// @param m A message of any legth
/// @param hash Buffer where the hash value is going to be stored
///
void calculateHash(const char* m, unsigned char hash[256]) 
{
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, m, strlen(m));
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
}
