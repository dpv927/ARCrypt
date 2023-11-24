#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <linux/limits.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "files.h"
#include "params.h"
#include "superkey.h"
#include "encryption.h"
#include "sign.h"
#include "../utils/messages.h"
#ifdef GTK_GUI
#include "../gtk/dialogs.h"
#endif

void encryptFile(const char* inputFile, char passwd[AES_KEY_BYTES]) 
{
  /* Todas las claves utilizadas */
  struct SuperKey superkey;
  u_char aes_key[AES_KEY_BYTES];
  u_char* rsa_key;
  
  /* Buffers temporales y demas */
  u_char sig[256+AES_KEY_BYTES];
  u_char inBuf[ENC_BUFF_SIZE];
  u_char outBuf[ENC_CIPHER_SIZE];
  char outputFile[PATH_MAX];
  char signatureFile[PATH_MAX];
  EVP_CIPHER_CTX* ctx;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;
  int tmpLen;

  /*  Comprobar si el archivo existe y si es asi, ver si
   *  el usuario tiene permisos de escritura y lectura
   *  sobre el directorio padre y el archivo. */
  int val = check_file(inputFile);
  if(val != FileIsGood) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error(FC_ERRORS[val])
    exit(EXIT_FAILURE);
  }

  /* Generar la clave AES.
  * Guardamos en aesk una secuencia de bytes aleatorios */
  p_info("Generando la clave AES");
  if (RAND_bytes(aes_key, AES_KEY_BYTES) != 1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error: No se pudo generar la clave AES");
    exit(EXIT_FAILURE);
  }

  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, aes_key, NULL);

  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo abrir el archivo a encriptar");
    exit(EXIT_FAILURE);
  };

  /* Generar el nombre del archivo de encriptado temporal.
  * Tendra el mismo nombre que el original pero con la extension ".enc". Se 
  * encontrara en el mismo directorio que el archivo a encriptar.  */
  strcpy(outputFile, inputFile);
  strcat(outputFile, ".enc");

  // ==========================================
  // ||            Crear la firma            ||
  // ==========================================

  p_info("Creando la firma");
  bytesRead = fread(inBuf, sizeof(u_char), ENC_BUFF_SIZE, input);
  int real = (bytesRead<256)? bytesRead : 256;

  memcpy(sig, inBuf, real);
  memcpy(sig+real, aes_key, AES_KEY_BYTES);
  
  // Hacer la firma
  strcpy(signatureFile, inputFile);
  strcat(signatureFile, ".sig");
  val = sign_buff(sig, real+AES_KEY_BYTES, signatureFile);
  
  if(val == S_Error) {
    /* No se pudo generar la firma */
    fclose(input);
    EVP_CIPHER_CTX_free(ctx);
    exit(EXIT_FAILURE); 
  }

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion");
    fclose(input);
    EVP_CIPHER_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  // ==========================================
  // ||     Encriptar el archivo objetivo    ||
  // ==========================================

  p_infoString("Encriptando", inputFile)
  EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
  fwrite(outBuf, sizeof(u_char), outLen, output);

  if(bytesRead == ENC_BUFF_SIZE) {
    /* El archivo puede contener mas de 8kb. Encriptar de 8kb en 8kb */
    while ((bytesRead = fread(inBuf, sizeof(u_char), ENC_BUFF_SIZE, input)) > 0) {
      EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
      fwrite(outBuf, sizeof(u_char), outLen, output);
    }
  }

  /* Anadir relleno si es necesario */
  EVP_EncryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, sizeof(u_char), outLen, output);
 
  /* Liberar Streams */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);
 
  /* Sustituir por el archivo original por el generado */
  remove(inputFile);
  rename(outputFile, inputFile);

  // ==========================================
  // ||        Encriptar AES con RSA         ||
  // ==========================================
  p_info("Encriptando la clave AES con RSA")
  EVP_PKEY *rsa_keypair = NULL;
  EVP_PKEY_CTX *rsa_ctx;
  BIO* rsa_bio;
  size_t outlen;

  rsa_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(rsa_ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(rsa_ctx, 2048);
  EVP_PKEY_keygen(rsa_ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(rsa_ctx);

  rsa_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_encrypt_init(rsa_ctx);
  EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_encrypt(rsa_ctx, superkey.aes, &outlen, aes_key, 256>>3);
  EVP_PKEY_CTX_free(rsa_ctx);

  rsa_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(rsa_bio, rsa_keypair, NULL, NULL, 0, 0, NULL);
  superkey.rsa_len = BIO_pending(rsa_bio);
  rsa_key = OPENSSL_malloc(superkey.rsa_len);
  BIO_read(rsa_bio, rsa_key, superkey.rsa_len);
  BIO_free(rsa_bio);
  EVP_PKEY_free(rsa_keypair);

  // ==========================================
  // ||   Encriptar RSA con AES del usuario  ||
  // ==========================================
  p_info("Encriptando RSA con la clave AES pesonal")
  EVP_CIPHER_CTX* c_ctx;
  int len;

  int passwd_len = strlen(passwd);
  for (int i=passwd_len; i<AES_KEY_BYTES; i++) {
    // Rellenar con 0s la clave del usuario
    passwd[i] = 0x0;
  }

  c_ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(c_ctx, EVP_aes_256_cbc(), NULL, (u_char*) passwd, NULL);
  superkey.rsa = OPENSSL_malloc(superkey.rsa_len*2);
  EVP_EncryptUpdate(c_ctx, superkey.rsa, &len, rsa_key, superkey.rsa_len);
  superkey.cipher_rsa_len = len;
  EVP_EncryptFinal_ex(c_ctx, superkey.rsa+len, &len);
  superkey.cipher_rsa_len += len;
  EVP_CIPHER_CTX_free(c_ctx);
  OPENSSL_free(rsa_key);

  // ==========================================
  // ||      Calcular Hash del password      ||
  // ==========================================
  p_info("Calculando el hash (resumen) de la contrasena")
  calculateHash(
    passwd,
    passwd_len,
    superkey.phash
  );

  // ==========================================
  // ||      Generar la Superclave           ||
  // ==========================================
  p_info("Generando la Superclave")
  strcpy((char*) outBuf, inputFile);
  strcpy(outputFile, dirname((char*)outBuf));
  strcat(outputFile, "/");
  strcat(outputFile, basename((char*)inputFile));
  strcat(outputFile, ".key");

  val = write_superkey(outputFile, &superkey);
  if(val == SKError) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puedo escribir la superclave.");
  } OPENSSL_free(superkey.rsa);
}
