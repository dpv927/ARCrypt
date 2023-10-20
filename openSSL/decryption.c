#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "decryption.h"

void decryptFile(const char* inputFile, const char* keyFile, const unsigned char* iv) {
  EVP_CIPHER_CTX* ctx; 
  unsigned char inBuf[DEC_CIPHER_SIZE];
  unsigned char outBuf[DEC_BUFF_SIZE];
  unsigned char key[KEY_BYTES];
  char outputFile[FILE_PATH_BYTES+4];
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  /* Obtener la clave del archivo */
  if((input = fopen(keyFile, "rb")) == NULL){
    perror("Error al abrir el archivo de la clave.");
    exit(1);
  };

  fread(key, sizeof(unsigned char), KEY_BYTES, input);
  fclose(input);

  /* Iniciar contexto de desencriptacion */
  ctx = EVP_CIPHER_CTX_new();   
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    perror("Error al abrir el archivo encriptado.");
    exit(EXIT_FAILURE);
  };

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
    strcpy(outputFile, inputFile);  
    strcat(outputFile, ".enc");

  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error al crear el archivo de encriptacion temporal.");
    exit(EXIT_FAILURE);
  }
  
  /* Obtener DEC_CIPHER_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  while ((bytesRead = fread(inBuf, DEC_ELEMENT_BYTES, DEC_CIPHER_SIZE, input)) > 0) {
    EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  }
    
  /* Anadir relleno si es necesario */
  EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  
  /* Liberar */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);

  /* Sustituir */
  remove(inputFile);
  rename(outputFile, inputFile);
  remove(keyFile);
}
