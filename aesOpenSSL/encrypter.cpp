#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include "encrypter.hpp"

/* Error log */
#define EncryptError(message)\
  std::cout << message << std::endl;\
  abort();

namespace Encryption {

  int encryptStr(const unsigned char *text, const unsigned int text_len, const unsigned char *key, unsigned char *cipher) {
    EVP_CIPHER_CTX *ctx;  
    int cipher_len = 0;
    int len = 0;

    // Crear contexto de cifrado
    if(!(ctx = EVP_CIPHER_CTX_new()))
      {EncryptError("EVP_CIPHER_CTX_new failed");}

    // Inicializar el contexto de cifrado
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
      {EncryptError("EVP_EncryptInit_ex failed");}
      
    // Cifrar los datos de entrada
    if (!EVP_EncryptUpdate(ctx, cipher, &len, text, text_len))
      {EncryptError("EVP_EncryptUpdate failed");}
    cipher_len += len;

    // Finalizar la operación de cifrado (rellenar si es necesario)
    if (!EVP_EncryptFinal_ex(ctx, cipher + len, &len))
      {EncryptError("EVP_EncryptFinal_ex failed");}
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
  }

  int encryptFile(const unsigned char* path, unsigned char* key) {
    return 0;
  }
}
