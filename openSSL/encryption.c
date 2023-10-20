#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "params.h"
#include "encryption.h"

void encryptFile(const char* inputFile, const unsigned char* iv) {
  EVP_CIPHER_CTX* ctx;
  unsigned char inBuf[ENC_BUFF_SIZE];
  unsigned char outBuf[ENC_CIPHER_SIZE];
  unsigned char key[16];
  char outputFile[2048+3];
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  /* Generar la clave */
  if (RAND_bytes(key, sizeof(key)) != 1) {
    printf("Error al generar la clave AES.\n");
    exit(EXIT_FAILURE);
  }

    for (int i=0; i<16; i++) {
    printf("%d ", (int)key[i]);
    }


  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    perror("Error al abrir el archivo a encriptar.");
    exit(EXIT_FAILURE);
  };

  strcpy(outputFile, inputFile);
  strcat(outputFile, ".enc");

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error al crear el archivo de encriptacion temporal.");
    exit(EXIT_FAILURE);
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
 
  /* Sustituir */
  remove(inputFile);
  rename(outputFile, inputFile);

  /* Crear archivo con la clave */
  char *dname = dirname((char*) inputFile);
  strcpy(outputFile, dname);

  if(!strcmp(outputFile, "."))
    strcat(outputFile, "/key.txt");
  else strcat(outputFile, "key.txt");

  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error al crear el archivo de la clave.");
    exit(EXIT_FAILURE);
  }

  fwrite(key, sizeof(unsigned char), 16, output);
  fclose(output);
}
