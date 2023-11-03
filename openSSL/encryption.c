#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include "params.h"
#include "encryption.h"
#include "../utils/messages.h"
#ifdef GTK_GUI
#include "../gtk/dialogs.h"
#endif

void encryptFile(const char* inputFile, const unsigned char* iv) {
  unsigned char inBuf[ENC_BUFF_SIZE];
  unsigned char outBuf[ENC_CIPHER_SIZE];
  unsigned char key[KEY_BYTES];
  char input_file_cpy[FILE_PATH_BYTES];
  char outputFile[FILE_PATH_BYTES+4];
  struct stat inode_info;
  EVP_CIPHER_CTX* ctx;
  char* dir_name;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  /* Comprobar informacion basica */
  if(stat(inputFile, &inode_info)) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puede acceder o no existe el fichero");
    exit(EXIT_FAILURE);
  } if((inode_info.st_mode & S_IFMT) == S_IFDIR) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("La encriptacion de carpetas no esta soportada. "\
    "Comprime dicha carpeta para asi obtener un archivo");
    exit(EXIT_FAILURE);
  }

  /* Ver si el usuario tiene permisos de lectura/escritura sobre el directorio en
  * el que se encuentra el archivo a encriptar. */
  strcpy(input_file_cpy, inputFile);
  dir_name = dirname((char*) input_file_cpy);
  if (access(dir_name, W_OK | X_OK | R_OK)) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No tienes los permisos de lectura/escritura necesarios");
    exit(EXIT_FAILURE);
  }

  /* Generar la clave */
  p_info("Generando la clave AES");
  if (RAND_bytes(key, sizeof(key)) != 1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error: No se pudo generar la clave AES");
    exit(EXIT_FAILURE);
  }

  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);

  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo abrir el archivo a encriptar");
    exit(EXIT_FAILURE);
  };

  strcpy(outputFile, inputFile);
  strcat(outputFile, ".enc");

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion temporal");
    exit(EXIT_FAILURE);
  }
  
  /* Obtener ENC_BUFF_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  p_infoString("Encriptando", inputFile)
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

  /* Generar el nombre del archivo con la clave */
  strcpy(outputFile, dir_name);
  strcat(outputFile, "/");
  strcat(outputFile, basename((char*)inputFile));
  strcat(outputFile, ".key");

  // Encriptar la clave AES y guardarla en el archivo .key
  // en el mismo directorio que el archivo encriptado.
  encryptKey(outputFile, key);
}

void encryptKey(const char* AESkeyFile, unsigned char AESKey[KEY_BYTES]){
  char rsa_path[FILE_PATH_BYTES+8];
  unsigned char* raw_aes_key;
  int cipher_len;
  FILE* aes_stream;
  FILE* rsa_stream;
  RSA* rsa_key;
  
  /* Generar el par de claves RSA */
  p_info("Generando el par de claves RSA");
  rsa_key = RSA_generate_key(RSA_KEY_BITS, RSA_F4, NULL, NULL);
  if (rsa_key == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error al crear el par de claves RSA");
    exit(EXIT_FAILURE);
  }

  /* Escribir la clave privada RSA en un archivo */
  strcpy(rsa_path, AESkeyFile);
  strcat(rsa_path, ".rsa");

  p_infoString("Guardando la clave privada RSA en", rsa_path);
  if((rsa_stream = fopen(rsa_path, "w")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error al crear el archivo de la clave privada RSA");
    exit(EXIT_FAILURE);
  }
  
  PEM_write_RSAPrivateKey(rsa_stream, rsa_key, NULL, NULL, 0, NULL, NULL);
  fclose(rsa_stream);

  /* Encriptar la clave AES con la clave publica de RSA. En el metodo de desencriptacion
  * de la clave AES, se debera utilizar la clave privada RSA. */
  raw_aes_key = (unsigned char *) malloc(RSA_size(rsa_key));
  cipher_len = RSA_public_encrypt(KEY_BYTES, AESKey, raw_aes_key, rsa_key, RSA_PKCS1_PADDING);
  RSA_free(rsa_key);

  /* Guardar en un archivo la clave AES encriptada */
  p_infoString("Guardando la clave AES encriptada en", AESkeyFile);
  if((aes_stream = fopen(AESkeyFile, "w")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    perror("Error al crear el archivo de la clave AES.");
    free(raw_aes_key);
    remove(rsa_path);
    exit(EXIT_FAILURE);
  }

  fwrite(raw_aes_key, ENC_ELEMENT_BYTES, cipher_len, aes_stream);
  fclose(aes_stream);
  free(raw_aes_key);
}