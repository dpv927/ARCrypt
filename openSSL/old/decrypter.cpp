#include <algorithm>
#include <cstdlib>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include "decrypter.hpp"
#include "messages.hpp"
#include "params.hpp"

namespace Decryption {
  
  size_t decryptStr(const unsigned char *cipher, const unsigned int cipher_len, const unsigned char *key, unsigned char *text) {
    EVP_CIPHER_CTX *ctx;  
    size_t text_len = 0;
    int len = 0;
    
    // Crear contexto de cifrado
    if(!(ctx = EVP_CIPHER_CTX_new()))
      {Error("EVP_CIPHER_CTX_new failed")}

    // Inicializar el contexto de cifrado
    if (!EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, NULL)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_DecryptInit_ex failed")}
      
    // Cifrar los datos de entrada
    if (!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len)) {
      EVP_CIPHER_CTX_free(ctx);  
      Error("EVP_DecryptUpdate failed")}
    text_len += len;

    // Finalizar la operación de cifrado (rellenar si es necesario)
    if (!EVP_DecryptFinal_ex(ctx, text+len, &len)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_DecryptFinal_ex failed")}
    text_len += len;
    return text_len;
  }

  void decryptFile(const char* path, const unsigned char* key) {
    FILE* input;
    FILE* output;
    char file_name[strlen(path)+DEC_EXT_PADDING];

    unsigned char cipher[4096];
    int cipher_len;
    
    unsigned char decrypted[4096];
    int dec_len;

    size_t readBytes;
  
    // Abrir archivo a encriptar
    input = fopen(path, "rb");
    if(input == NULL) {
      Error("Error opening the input file")}
    
    // Crear el nombre del archivo encriptado
    strcpy(file_name, path);
    strcat(file_name, DEC_EXTENSION);

    // Abrir archivo donde guardar el encriptado
    output = fopen(file_name, "wb");
    if(output == NULL) {
      fclose(input);
      Error("Error opening the output file")}

    // Obtener 1024 bytes, desencriptarlos y escribirlos en output
    while ((readBytes = fread(cipher, DEC_EPER_BUFF, sizeof(cipher), input)) > 0) {
      dec_len = decryptStr(cipher, readBytes, key, decrypted);
      fwrite(decrypted, DEC_EPER_BUFF, dec_len, output);
    }
    
    fclose(input);
    fclose(output);
    //remove(path);
    //rename(decr_name, path);
  }
}
