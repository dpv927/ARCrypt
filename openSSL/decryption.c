#include <openssl/evp.h>
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
#include "decryption.h"
#include "sign.h"
#include "../utils/messages.h"

void decryptFile(const char* inputFile, char* passwd,
  const char* keyFile, const char* signatureFile, int signature) 
{
  /* Todas las claves utilizadas */
  struct SuperKey superkey;
  u_char phash[SHA2_BYTES];
  u_char* aes_key;
  u_char* rsa_key;
  size_t rsa_len;
  int passwd_len;

  // Otros buffers y datos
  u_char sig[64+AES_KEY_BYTES];
  u_char inBuf[DEC_BUFF_SIZE];
  u_char outBuf[DEC_CIPHER_SIZE];
  char outputFile[PATH_MAX];
  EVP_CIPHER_CTX* ctx;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;
  int val;
  
  /* Comprobar permisos sobre el archivo objetivo 
   * y el archivo de la clave.
   * * *  */
  p_info("Comprobando permisos sobre el archivo")
  val = check_file(inputFile);
  if(val != FileIsGood) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error(FC_ERRORS[val])
    exit(EXIT_FAILURE);
  }

  p_info("Comprobando permisos sobre la clave")
  val = check_file(keyFile);
  if(val != FileIsGood) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error(FC_ERRORS[val])
    exit(EXIT_FAILURE);
  }

  // Recuperar del archivo de la clave la superclave, 
  // de forma que obtenemos todas las claves protegidas y 
  // el hash de la contrasenacon la que se encripto el archivo.
  p_info("Recuperando la superclave")
  val = get_superkey(keyFile, &superkey);
  if(val == SKError) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    if(!superkey.rsa) 
      OPENSSL_free(superkey.rsa);
    exit(EXIT_FAILURE);
  }

  // ==========================================
  // ||      Comprobar password con hash     ||
  // ==========================================
  p_info("Comprobando si la contrasena es correcta.")
  p_info_tabbed("Calculando el hash del password")

  passwd_len = strlen(passwd);
  for (int i=passwd_len; i<AES_KEY_BYTES; i++) {
    // En este momento no hace falta pero nos servira
    // Rellenar con 0s la parte del vector no utilizado
    // de la clave del usuario
    passwd[i] = 0;
  }
  calculateHash(passwd, passwd_len, phash);

  p_info_tabbed("Comprobando si las claves coinciden")
  if(memcmp(superkey.phash, phash, SHA2_BYTES)){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("La contrasena es incorrecta.");
    OPENSSL_free(superkey.rsa);
    exit(EXIT_FAILURE);
  }
  
  // ==========================================
  // ||  Desencriptar la clave RSA con AES   ||
  // ==========================================
  EVP_CIPHER_CTX* c_ctx;
  int len;

  c_ctx = EVP_CIPHER_CTX_new();
  rsa_key = OPENSSL_malloc(superkey.rsa_len);
  EVP_DecryptInit_ex(c_ctx, EVP_aes_256_cbc(), NULL, (u_char*) passwd, NULL);
  EVP_DecryptUpdate(c_ctx, rsa_key, &len, superkey.rsa, superkey.cipher_rsa_len);
  rsa_len = len;
  EVP_DecryptFinal_ex(c_ctx, rsa_key+len, &len);
  rsa_len += len;
  EVP_CIPHER_CTX_free(c_ctx);
  OPENSSL_free(superkey.rsa);

  // ==========================================
  // ||  Desencriptar la clave AES con RSA   ||
  // ==========================================
  EVP_PKEY *rsa_keypair = NULL;
  EVP_PKEY_CTX *rsa_ctx;
  BIO* rsa_bio;
  size_t outlen;

  rsa_bio = BIO_new(BIO_s_mem());
  BIO_write(rsa_bio, rsa_key, rsa_len);
  rsa_keypair = PEM_read_bio_PrivateKey_ex(rsa_bio, NULL, NULL, NULL, NULL, NULL);
  BIO_free(rsa_bio); 

  rsa_ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_decrypt_init(rsa_ctx);
  EVP_PKEY_CTX_set_rsa_padding(rsa_ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_decrypt(rsa_ctx, NULL, &outlen, superkey.aes, 2048>>3);

  u_char* AES = calloc(outlen, sizeof(unsigned char));
  EVP_PKEY_decrypt(rsa_ctx, AES, &outlen, superkey.aes, 2048>>3);
  EVP_PKEY_CTX_free(rsa_ctx);
  EVP_PKEY_free(rsa_keypair);
  OPENSSL_free(rsa_key);

  // ==========================================
  // ||   Desencriptar el fichero objetivo   ||
  // ==========================================

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, AES, NULL);
    
  // Abrir stream en el archivo a desencriptar.
  if((input = fopen(inputFile, "rb")) == NULL){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puede abrir el archivo encriptado")
    exit(EXIT_FAILURE);
  };

  /* Generar el nombre del el archivo de desencriptado y guardarlo en outputFile.
  * Tendra el mismo nombre que el original pero con la extension temporal ".enc".*/
  strcpy(outputFile, inputFile);  
  strcat(outputFile, ".enc");

  // Obtener la firma y verificar que es valida
  // en caso de que el usuario lo decida
  bytesRead = fread(inBuf, sizeof(u_char), DEC_CIPHER_SIZE, input);
  EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
  int real = (bytesRead<64)? bytesRead : 64;

  if(!signature) { // (signature == 0) -> Validar firma
    p_infoString("Validando la firma", signatureFile);
    memcpy(sig, outBuf, real);
    memcpy(sig+real, AES, AES_KEY_BYTES);

    val = verify_buff_sign(sig, real+AES_KEY_BYTES, signatureFile);
    if(val == S_Error) {
      p_error("La firma no es valida")
      free(AES);
      fclose(input);
      EVP_CIPHER_CTX_free(ctx);
      exit(EXIT_FAILURE);
    }
  }

  // Abrir stream para escribir en el archivo temporal 
  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion temporal")
    exit(EXIT_FAILURE);
  }
    
  p_infoString("Desencriptando el archivo", inputFile)
  fwrite(outBuf, sizeof(u_char), outLen, output);

  if(bytesRead == DEC_BUFF_SIZE) {
    /* El archivo puede contener mas de 8kb. Encriptar de 8kb en 8kb */
    while ((bytesRead = fread(inBuf, sizeof(u_char), DEC_CIPHER_SIZE, input)) > 0) {
    EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, sizeof(u_char), outLen, output);
    }
  }
   
  // Quitar relleno si es necesario 
  EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, sizeof(u_char), outLen, output);
  
  // Liberar memoria y streams 
  EVP_CIPHER_CTX_free(ctx);
  free(AES);
  fclose(input);
  fclose(output);

  // Sustituir 
  remove(inputFile);
  rename(outputFile, inputFile);
  remove(keyFile);
  remove(signatureFile);
}
