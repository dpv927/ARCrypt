#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "decryption.h"
#include "../utils/messages.h"

void decryptFile(const char* inputFile, const char* keyFile, const unsigned char* iv) {
  unsigned char inBuf[DEC_CIPHER_SIZE];
  unsigned char outBuf[DEC_BUFF_SIZE];
  unsigned char key[KEY_BYTES];
  char outputFile[FILE_PATH_BYTES+4];
  char input_file_cpy[FILE_PATH_BYTES];
  char rsa_key_file[FILE_PATH_BYTES+8];
  EVP_CIPHER_CTX* ctx; 
  struct stat inode_info;
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
    p_error("No se puede acceder o no existe el fichero.")
    exit(EXIT_FAILURE);
  } if((inode_info.st_mode & S_IFMT) == S_IFDIR) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("La encriptacion de carpetas no esta soportada. "\
    "Comprime dicha carpeta para asi obtener un archivo.")
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
    p_error("No tienes los permisos de lectura/escritura necesarios.")
    exit(EXIT_FAILURE);
  }

  /* Desencriptar la clave AES. En primer lugar, deberemos obtener el nombre
  * del archivo de la clave privada RSA (que se supone que se encuentra en el
  * mismo direcrorio que la clave y su mismo nommbre pero con la extension .rsa).
  * 
  * Despues llamamos a la funcion decryptKey, de manera que desencriptamos la clave
  * AES con la privada RSA, dando sus rutas y un buffer donde guardar la clave. */
  p_infoString("Desencriptando la clave AES", keyFile)
  strcpy(rsa_key_file, keyFile);
  strcat(rsa_key_file, ".rsa");
  decryptKey(keyFile, rsa_key_file, key);

  /* Obtener la clave del archivo */
  //p_infoString("Obteniendo la clave AES desencriptada", keyFile)
  //if((input = fopen(keyFile, "rb")) == NULL){
  //  #ifdef GTK_GUI
  //  create_error_dialog();
  //  #endif
  //  p_error("No se puede abrir el archivo con la clave AES")
  //  exit(EXIT_FAILURE);
  //};

  //fread(key, sizeof(unsigned char), KEY_BYTES, input);
  //fclose(input);

  /* Iniciar contexto de desencriptacion. 
  * OpenSSL requiere que se inicie un contexto (estructura de datos) de modo que
  * establezcamos metodo del algoritmo (ECB, CBC, etc), junto a la clave e iv para que 
  * futuras funciones solo tomen buffers con datos a descrifrar y no otros datos
  * repetidos como claves, modos, etc. */
  ctx = EVP_CIPHER_CTX_new();   
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puede abrir el archivo encriptado")
    exit(EXIT_FAILURE);
  };

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  strcpy(outputFile, inputFile);  
  strcat(outputFile, ".enc");

  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion temporal")
    exit(EXIT_FAILURE);
  }
  
  /* Obtener DEC_CIPHER_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  p_infoString("Desencriptando el archivo", inputFile)
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

  /* S:wustituir */
  remove(inputFile);
  rename(outputFile, inputFile);
  //remove(keyFile);
}

void decryptKey(const char* AESkeyFile, const char* RSAkeyFile, unsigned char AESkey [KEY_BYTES]) {
  unsigned char raw_aes_key[RSA_KEY_BITS>>3];
  FILE* aes_stream;
  FILE* rsa_stream;
  RSA* rsa_key;

  p_infoString("Recuperando la clave AES encriptada", AESkeyFile)
  if((aes_stream = fopen(AESkeyFile, "r")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo abrir el archivo de la clave encriptada AES")
    exit(EXIT_FAILURE);
  }

  // Obtener la clave AES encriptada
  fread(raw_aes_key, sizeof(unsigned char), RSA_KEY_BITS>>3, aes_stream);
  fclose(aes_stream);
  
  // Obtener la clave RSA
  p_infoString("Recuperando la clave RSA privada", RSAkeyFile)
  if((rsa_stream = fopen(RSAkeyFile, "r")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error al abrir el archivo de la clave RSA")
    exit(EXIT_FAILURE);
  }

  rsa_key = PEM_read_RSAPrivateKey(rsa_stream, NULL, NULL, NULL);
  fclose(rsa_stream);

  // Desencriptar la clave aes
  p_info("Desencriptando la clave AES");
  RSA_private_decrypt(RSA_KEY_BITS>>3, raw_aes_key, AESkey, rsa_key, RSA_PKCS1_PADDING);
  RSA_free(rsa_key);
  
  remove(RSAkeyFile);
  remove(AESkeyFile);
}