#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

typedef unsigned char u_char;
#define SHA_BYTES 32
#define SHA_NAME  "SHA256"

void calculateHash(const char* m, const int mlen, u_char* hash) 
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned int md_len;

  md = EVP_get_digestbyname(SHA_NAME);
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex2(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, m, mlen);
  EVP_DigestFinal_ex(mdctx, hash, &md_len);
  EVP_MD_CTX_free(mdctx);
}

int main(int argc, char *argv[])
{
  char buffer1[]    = "texto de prueba";
  char buffer2[100] = "texto de prueba";
  unsigned char hash[EVP_MAX_MD_SIZE];

  // Calcular el hash del buffer1
  calculateHash(buffer1, strlen(buffer1), hash);
  printf("\nSHA2-256(stdin)= ");
  for (int i = 0; i < SHA_BYTES; i++)
    printf("%02x", hash[i]);

  // Calcular el hash del buffer2
  // El resultado es diferente
  calculateHash(buffer2, 100, hash);
  printf("\nSHA2-256(stdin)= ");
  for (int i = 0; i < SHA_BYTES; i++)
    printf("%02x", hash[i]);
  return 0;

  return 0;
}


