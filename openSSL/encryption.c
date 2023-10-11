#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include "params.h"
#include "encryption.h"

void encryptFile(const char* inputFile, const char* outputFile, const unsigned char* key, const unsigned char* iv) {
  EVP_CIPHER_CTX* ctx;
  unsigned char inBuf[ENC_BUFF_SIZE];
  unsigned char outBuf[ENC_CIPHER_SIZE];
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    perror("Error while opening the input file.");
    exit(1);
  };

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error while opening the output file.");
    exit(1);
  }
  
  /* Obtener ENC_BUFF_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  while ((bytesRead = fread(inBuf, ENC_ELEMENT_BYTES, ENC_BUFF_SIZE, input)) > 0) {
    EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, ENC_ELEMENT_BYTES, outLen, output);
  }
    
  /* Anadir relleno si es necesario */
  EVP_EncryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, ENC_ELEMENT_BYTES, outLen, output);
 
  /* Liberar */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);
}
