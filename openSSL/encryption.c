#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <libgen.h>
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

void encryptFile(const char* inputFile, const char passwd[AES_KEY_BYTES]) 
{
  /* Todas las claves utilizadas */
  struct SuperKey session_sk;
  u_char aesk[AES_KEY_BYTES];
  u_char aesk_iv[AES_IV_BYTES];
  u_char* rsak_pem;
  
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
  if (RAND_bytes(aesk, AES_KEY_BYTES) != 1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error: No se pudo generar la clave AES");
    exit(EXIT_FAILURE);
  }
  
  /* Generar el IV de la clave AES.
  * Guardamos en aesk_iv una secuencia de bytes aleatorios */
  p_info("Generando el IV de la clave AES");
  if (RAND_bytes(aesk_iv, AES_KEY_BYTES) != 1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error: No se pudo generar la clave AES");
    exit(EXIT_FAILURE);
  }
  
  /* Iniciar el contexto de encriptacion */
  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, aesk, aesk_iv);

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
  
  /* Obtener ENC_BUFF_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  p_infoString("Encriptando", inputFile)
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

  // Encriptar la clave AES y guardarla en session_sk.aesk.
  // La clave privada RSA se guardara en session_sk.rsak_pem
  p_info("Encriptando la clave AES con RSA")
  rsak_pem = encryptAES_withRSA(
    aesk,
    session_sk.aesk,
    aesk_iv,
    session_sk.aes_iv,
    &session_sk.rsak_pem_l
  );

  // Encriptar la clave RSA con AES. La clave AES en esta ocasion 
  // sera la contrasena del usuario y el IV una derivacion de esta.
  p_info("Encriptando la clave RSA con AES personal")
  derive_AES_key((u_char*) passwd, aesk_iv);

  session_sk.rsak_pem = malloc(session_sk.rsak_pem_l+128);
  if(!session_sk.rsak_pem) {
    p_error("No se puedo reservar la memoria a la clave RSA.")
    exit(EXIT_FAILURE);
  }

  val = encryptRSAKey_withAES(
    rsak_pem,
    session_sk.rsak_pem,
    session_sk.rsak_pem_l,
    (u_char*) passwd,
    aesk_iv
  );

  if(val == -1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo encriptar la clave AES con RSA")
    exit(EXIT_FAILURE);
  } else session_sk.rsak_pem_l = val;
  
  // Calcular el hash de la contrasena
  // El valor del hash (resumen se guardara en session_sk.phash)
  p_info("Calculando el hash (resumen) de la contrasena")
  calculateHash((const u_char*) passwd, AES_KEY_BYTES, session_sk.phash);

  /* Generar el nombre del archivo con la superclave. 
  * Tendra el mismo nombre que el archivo a encriptar pero con 
  * la extension ".key". */
  p_info("Generando la Superclave")
  strcpy((char*) outBuf, inputFile);
  strcpy(outputFile, dirname((char*)outBuf));
  strcat(outputFile, "/");
  strcat(outputFile, basename((char*)inputFile));
  strcat(outputFile, ".key");

  val = write_superkey(outputFile, &session_sk);
  if(val == SKError) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puedo escribir la superclave.");
    exit(EXIT_FAILURE);
  }

  // TODO Calcular el hash de la superclave?
  // 
  //
}

u_char* encryptAES_withRSA(const u_char aesk[AES_KEY_BYTES], u_char cipher_aesk[RSA_KEY_BYTES],
  u_char aesk_iv[AES_IV_BYTES], u_char cipher_aesk_iv[RSA_KEY_BYTES], size_t* RSA_PEM_len)
{
  EVP_PKEY *rsa_keypair = NULL;
  EVP_PKEY_CTX *ctx;
  u_char* rsa_skey;
  BIO* rsa_bio;
  size_t outlen;
  size_t pending;

  // Create a new RSA Keypair
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(ctx);

  // Encrypt AES key with RSA 
  ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_encrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_encrypt(ctx, cipher_aesk, &outlen, aesk, AES_KEY_BYTES);
  //EVP_PKEY_CTX_free(ctx);

  // Encrypt AES IV with RSA 
  EVP_PKEY_encrypt(ctx, cipher_aesk_iv, &outlen, aesk_iv, AES_IV_BYTES);
  EVP_PKEY_CTX_free(ctx);
  
  // Write RSA private key to mem 
  rsa_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(rsa_bio, rsa_keypair, NULL, NULL, 0, 0, NULL);
  pending = BIO_pending(rsa_bio);
  rsa_skey = (u_char*) malloc(pending);
  BIO_read(rsa_bio, rsa_skey, pending);
  *RSA_PEM_len = pending;

  // Free all that stuff!
  BIO_free(rsa_bio);
  EVP_PKEY_free(rsa_keypair);
  return rsa_skey;
}

int encryptRSAKey_withAES(const u_char* rsa_key, u_char* cipher_rsa_key, const size_t rsa_len, 
  const u_char aes_key[AES_KEY_BYTES], const u_char aes_key_iv[AES_IV_BYTES]) 
{
  EVP_CIPHER_CTX* ctx;
  int cipher_len;
  int len;
 
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, aes_key, aes_key_iv);
  EVP_EncryptUpdate(ctx, cipher_rsa_key, &len, rsa_key, rsa_len);
  cipher_len = len;
  EVP_EncryptFinal_ex(ctx, cipher_rsa_key+len, &len);
  cipher_len += len;
  EVP_CIPHER_CTX_free(ctx);

  //u_char cipher1[rsa_len];
  //u_char cipher2[rsa_len];
  //int cipher_len;
  //int pad_len;
  //int total_len;

  /*
  ctx = EVP_CIPHER_CTX_new();  
  EVP_EncryptInit_ex(ctx, AES_ALGORITHM, NULL, aes_key, aes_key_iv);
  EVP_EncryptUpdate(ctx, cipher1, &cipher_len, rsa_key, rsa_len);
  memcpy(cipher2, cipher1, cipher_len);
*/
  /* Quizas hay que anadir un padding */
  /*EVP_EncryptFinal_ex(ctx, cipher1, &pad_len);
  EVP_CIPHER_CTX_free(ctx);
  */
  /* Hay que redimensionar la clave al nuevo tamano de la clave */
/*  rsa_key = (u_char*) realloc(rsa_key, total_len = cipher_len+pad_len);
  if(rsa_key == NULL) {
    return -1;
  }
*/
  // La clave encriptada sera cipher2+cipher1
  // Por culpa de openssl no se pude hacer en solo 1 paso.
  //memcpy(rsa_key, cipher2, cipher_len);
  //memcpy(rsa_key+cipher_len, cipher1, pad_len);
  //return total_len;
  //
  return cipher_len;
}
