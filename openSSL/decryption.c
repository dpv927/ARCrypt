#include <openssl/evp.h>
#include <openssl/aes.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
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
  struct stat inode_info;
  char* dir_name;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  /* Comprobar informacion basica */
  if(stat(inputFile, &inode_info)) {
    perror("Error: No se puede acceder o no existe el fichero.");
    exit(EXIT_FAILURE);
  } if((inode_info.st_mode & S_IFMT) == S_IFDIR) {
    perror("Error: La encriptacion de carpetas no esta soportada. "\
    "Comprime dicha carpeta para asi obtener un archivo.");
    exit(EXIT_FAILURE);
  }

  /* Ver si el usuario tiene permisos de lectura/escritura sobre el directorio en
  * el que se encuentra el archivo a encriptar. */
  dir_name = dirname((char*) inputFile);
  if (access(dir_name, W_OK | X_OK | R_OK)) {
    perror("Error: No tienes los permisos de lectura/escritura necesarios.");
    exit(EXIT_FAILURE);
  }

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
