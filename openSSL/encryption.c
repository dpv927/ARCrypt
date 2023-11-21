#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "files.h"
#include "params.h"
#include "iv_kdf.h"
#include "superkey.h"
#include "encryption.h"
#include "../utils/messages.h"
#ifdef GTK_GUI
#include "../gtk/dialogs.h"
#endif

void encryptFile(const char* inputFile, char passwd[AES_KEY_BYTES]) 
{
  /* Todas las claves utilizadas */
  struct SuperKey superkey;
  u_char gen_aes_key[AES_KEY_BYTES];
  u_char usr_iv[AES_IV_BYTES];
  u_char* gen_rsa_pem;
  size_t rsa_pem_len;
  int passwd_len;
  
  /* Buffers temporales y demas */
  u_char inBuf[ENC_BUFF_SIZE];
  u_char outBuf[ENC_CIPHER_SIZE];
  char outputFile[FILE_PATH_BYTES+4];
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
  if (RAND_bytes(gen_aes_key, AES_KEY_BYTES) != 1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error: No se pudo generar la clave AES");
    exit(EXIT_FAILURE);
  }
  
  /* Iniciar el contexto de encriptacion */
  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, gen_aes_key, NULL);

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

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion");
    exit(EXIT_FAILURE);
  }
  
  // ------------------------------------------
  // ||     Encriptar el archivo objetivo    ||
  // ------------------------------------------
  p_infoString("Encriptando", inputFile)
  /* Encriptar de 8kb en 8kb */
  while ((bytesRead = fread(inBuf, sizeof(u_char), ENC_BUFF_SIZE, input)) > 0) {
    EVP_EncryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, sizeof(u_char), outLen, output);
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

  // ------------------------------------------
  // || Encriptar clave AES generada con RSA ||
  // ------------------------------------------
  p_info("Encriptando la clave AES con RSA")
  gen_rsa_pem = encryptAESKey_withRSA(
    gen_aes_key,
    superkey.aes,
    &rsa_pem_len
  );

  // ------------------------------------------
  // || Encriptar clave RSA con AES personal ||
  // ------------------------------------------
  p_info("Encriptando la clave RSA con AES personal")
  //derive_AES_key((u_char*) passwd, usr_iv);

  superkey.rsa = malloc(rsa_pem_len+128);
  if(!superkey.rsa) {
    free(gen_rsa_pem);
    p_error("No se puedo reservar la memoria a la clave RSA.")
    exit(EXIT_FAILURE);
  }

  passwd_len = strlen(passwd);
  for (int i=passwd_len; i<AES_KEY_BYTES; i++) {
    // Rellenar con 0s las posiciones no usadas del vector
    // de la contrasena por si algun valor no es 0.
    passwd[i] = (char) 0x00;
  }

  val = encryptRSAKey_withAES(
    gen_rsa_pem,
    rsa_pem_len,
    superkey.rsa,
    (u_char*) passwd
  );

  if(val == -1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    free(gen_rsa_pem);
    free(superkey.rsa);
    p_error("No se pudo encriptar la clave AES con RSA")
    exit(EXIT_FAILURE);
  } else superkey.rsa_len = val;
  

  // ------------------------------------------
  // ||      Calcular Hash del password      ||
  // ------------------------------------------
  p_info("Calculando el hash (resumen) de la contrasena")
  calculateHash(passwd, passwd_len, superkey.phash);

  // ------------------------------------------
  // ||      Generar la Superclave           ||
  // ------------------------------------------
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
  }

  // Liberar
  free(gen_rsa_pem);
  free(superkey.rsa);
}

unsigned char* encryptAESKey_withRSA(const unsigned char* aes_key, 
  unsigned char* cipher_aes_key, size_t* rsa_len)
{
  EVP_PKEY *rsa_keypair = NULL;
  EVP_PKEY_CTX *ctx;
  unsigned char* rsa_skey;
  BIO* rsa_bio;
  size_t outlen;
  size_t pending;

  // Create a new RSA Keypair
  p_info_tabbed("Generando el par de claves RSA")
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(ctx);

  // Encrypt AES key with RSA 
  p_info_tabbed("Finalizando encriptacion")
  ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_encrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  //EVP_PKEY_encrypt(ctx, cipher_aes_key, &outlen, aes_key, AES_KEY_BYTES);

  for (size_t offset = 0; offset < AES_KEY_BYTES; offset += RSA_KEY_BYTES) {
    EVP_PKEY_encrypt(ctx, cipher_aes_key + offset, rsa_len,
      aes_key + offset, AES_KEY_BYTES - offset);
  }

  // Write RSA private key to mem 
  rsa_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(rsa_bio, rsa_keypair, NULL, NULL, 0, 0, NULL);
  pending = BIO_pending(rsa_bio);
  rsa_skey = OPENSSL_malloc(pending);
  BIO_read(rsa_bio, rsa_skey, pending);
  *rsa_len = pending;

  // Free all that stuff!
  BIO_free(rsa_bio);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(rsa_keypair);
  return rsa_skey;
}

int encryptRSAKey_withAES(u_char* rsa, size_t rsa_len, 
	u_char* cipher_rsa, u_char* aes_key) 
{
  EVP_CIPHER_CTX* ctx;
  int cipher_len;
  int len;
 
 p_info_tabbed("Iniciando encriptacion")
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, NULL);
  EVP_EncryptUpdate(ctx, cipher_rsa, &len, rsa, rsa_len);
  cipher_len = len;
  EVP_EncryptFinal_ex(ctx, cipher_rsa+len, &len);
  cipher_len += len;
  EVP_CIPHER_CTX_free(ctx);
  p_info_tabbed("Encriptacion finalizada")
  return cipher_len;
}