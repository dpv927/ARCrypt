#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>
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

  /* Generar la clave */
  if (RAND_bytes(key, sizeof(key)) != 1) {
    printf("Error: No se pudo generar la clave AES.\n");
    exit(EXIT_FAILURE);
  }

  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);

  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    perror("Error: No se pudo abrir el archivo a encriptar.");
    exit(EXIT_FAILURE);
  };

  strcpy(outputFile, inputFile);
  strcat(outputFile, ".enc");

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error: No se pudo crear el archivo de encriptacion temporal.");
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
 
  /* Liberar Streams */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);
 
  /* Sustituir por el archivo original por el generado */
  remove(inputFile);
  rename(outputFile, inputFile);

  /* Crear archivo con la clave */
  strcpy(outputFile, dir_name);
  if(!strcmp(outputFile, "."))
    strcat(outputFile, "/"); 
  
  strcat(outputFile,basename((char*)inputFile));
  strcat(outputFile, ".key");

  /* Generar el archivo con la clave */
  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error: No se pudo crear el archivo de la clave.");
    exit(EXIT_FAILURE);
  }

  fwrite(key, sizeof(unsigned char), KEY_BYTES, output);
  fclose(output);
}
