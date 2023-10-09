#include <cstring>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <iostream>
#include "decrypter.hpp"
#include "messages.hpp"
#include "params.hpp"

namespace Decryption {
  
  int decryptStr(const unsigned char *cipher, const unsigned int cipher_len, const unsigned char *key, unsigned char *text) {
    EVP_CIPHER_CTX *ctx;  
    int text_len = 0;
    int len = 0;

    // Crear contexto de cifrado
    if(!(ctx = EVP_CIPHER_CTX_new()))
      {Error("EVP_CIPHER_CTX_new failed")}

    // Inicializar el contexto de cifrado
    if (!EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, NULL)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_EncryptInit_ex failed")}
      
    // Cifrar los datos de entrada
    if (!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len)) {
      EVP_CIPHER_CTX_free(ctx);  
      Error("EVP_EncryptUpdate failed")}
    text_len += len;

    // Finalizar la operación de cifrado (rellenar si es necesario)
    if (!EVP_DecryptFinal_ex(ctx, text+len, &len)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_EncryptFinal_ex failed")}
    text_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return text_len;
  }

  void decryptFile(const char* path, const unsigned char* key) {
    FILE* input;
    FILE* output;
    char decr_name[strlen(path)+DEC_EXT_PADDING];
    unsigned char cipher_buffer[DEC_BUFF_BYTES];
    unsigned char decr_buffer[DEC_BUFF_BYTES];
    size_t readBytes;
    int decr_len;
  
    // Abrir archivo a encriptar
    input = fopen(path, "r");
    if(input == NULL) {
      Error("Error opening the input file")}
    
    // Crear el nombre del archivo encriptado
    strcpy(decr_name, path);
    strcat(decr_name, DEC_EXTENSION);

    // Abrir archivo donde guardar el encriptado
    output = fopen(decr_name, "wb");
    if(output == NULL) {
      fclose(input);
      Error("Error opening the output file")}

    // Obtener 1024 bytes, encriptarlos y escribirlos en output
    while ((readBytes = fread(cipher_buffer, DEC_EPER_BUFF, sizeof(cipher_buffer), input)) > 0) {
      decr_len = decryptStr(cipher_buffer, readBytes, key, decr_buffer);
      fwrite(decr_buffer, DEC_EPER_BUFF, decr_len, output);
    }

    fclose(input);
    fclose(output);
    //remove(path);
    //rename(decr_name, path);
  }
}
