#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include "decrypter.hpp"

#define DecryptError(message)\
  std::cout << message << std::endl;\
  abort();

namespace Decryption {
  
  int decryptStr(unsigned char *cipher, int cipher_len, unsigned char *key, unsigned char *text) {
    EVP_CIPHER_CTX *ctx;  
    int text_len = 0;
    int len = 0;

    // Crear contexto de cifrado
    if(!(ctx = EVP_CIPHER_CTX_new()))
      {DecryptError("EVP_CIPHER_CTX_new failed");}

    // Inicializar el contexto de cifrado
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
      {DecryptError("EVP_EncryptInit_ex failed");}
      
    // Cifrar los datos de entrada
    if (!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len))
      {DecryptError("EVP_EncryptUpdate failed");}
    text_len += len;

    // Finalizar la operación de cifrado (rellenar si es necesario)
    if (!EVP_DecryptFinal_ex(ctx, text + len, &len))
      {DecryptError("EVP_EncryptFinal_ex failed");}
    text_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return text_len;
  }
}
