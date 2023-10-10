#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <cstddef>
#include <cstring>
#include <iostream>
#include "encrypter.hpp"
#include "messages.hpp"
#include "params.hpp"

namespace Encryption {

  size_t encryptStr(const unsigned char *text, const unsigned int text_len, const unsigned char *key, unsigned char *cipher) {
    EVP_CIPHER_CTX *ctx;  
    size_t cipher_len = 0;
    int len = 0;

    // Crear contexto de cifrado
    if(!(ctx = EVP_CIPHER_CTX_new())){
      Error("EVP_CIPHER_CTX_new failed");}
      
    // Inicializar el contexto de cifrado
    if (!EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, key, NULL)) {
      EVP_CIPHER_CTX_free(ctx); 
      Error("EVP_EncryptInit_ex failed")}
      
    // Cifrar los datos de entrada
    if (!EVP_EncryptUpdate(ctx, cipher, &len, text, text_len)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_EncryptUpdate failed")}
    cipher_len += len;

    // Finalizar la operación de cifrado (rellenar si es necesario)
    if (!EVP_EncryptFinal_ex(ctx, cipher+len, &len)) {
      EVP_CIPHER_CTX_free(ctx);
      Error("EVP_EncryptFinal_ex failed")}
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
  }

  void encryptFile(const char* path, const unsigned char* key) {
    FILE* input;
    FILE* output;
    char encr_name[strlen(path)+ENC_EXT_PADDING];
    unsigned char buffer[ENC_BUFF_BYTES];
    unsigned char cipher_buffer[ENC_CIPHER_BYTES];
    size_t readBytes;
    size_t cipher_len;
  
    // Abrir archivo a encriptar
    input = fopen(path, "r");
    if(input == NULL) {
      Error("Error opening the input file")}
    
    // Crear el nombre del archivo encriptado
    strcpy(encr_name, path);
    strcat(encr_name, ENC_EXTENSION);

    // Abrir archivo donde guardar el encriptado
    output = fopen(encr_name, "wb");
    if(output == NULL) {
      fclose(input);
      Error("Error opening the output file")}

    // Obtener 1024 bytes, encriptarlos y escribirlos en output
    while ((readBytes = fread(buffer, ENC_EPER_BUFF, sizeof(buffer), input)) > 0) {
      cipher_len = encryptStr(buffer, readBytes-ENC_EOF_STRING, key, cipher_buffer);

      std::cout<<"Encrypted: ";
      for(int i =0; i<cipher_len; i++)
        std::cout<<(int) cipher_buffer[i];

      std::cout<<"\nNormal   : ";
      for(int i =0; i<readBytes-ENC_EOF_STRING; i++)
        std::cout<<(int) buffer[i];

      fwrite(cipher_buffer, ENC_EPER_BUFF, cipher_len, output);
    }

    fclose(input);
    fclose(output);
    //remove(path);
    //rename(encr_name, path);
  }
}
