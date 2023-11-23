#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "sign.h"
#include "../utils/messages.h"
#include "params.h"

int sign_buff(const unsigned char* m, size_t m_len, 
  char* path) 
{
  EVP_PKEY* rsa_keypair = NULL;
  unsigned char hash[SHA2_BYTES];
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  u_char* sig;
  size_t siglen;
  int write;

  // Generar un par de claves RSA  
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS);
  EVP_PKEY_keygen(ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(ctx);

  // Obtener el hash del buffer
  calculateHash((char*) m, m_len, hash);

  // Obtener firma - Al fin y al cabo consiste en encriptar 
  // el hash del mensaje con la clave privada RSA
  ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_sign_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
  EVP_PKEY_CTX_set_signature_md(ctx, SHA2_ALGORITHM);
  EVP_PKEY_sign(ctx, NULL, &siglen, hash, SHA2_BYTES);
  
  if ((sig = OPENSSL_malloc(siglen)) == NULL) {
    p_error("Error al reservar memoria para el certificado")
    exit(EXIT_FAILURE);
  }

  // Crear el signature
  EVP_PKEY_sign(ctx, sig, &siglen, hash, SHA2_BYTES);
  
  // Escribir todo en un archivo
  FILE* stream = fopen(path, "w");
  if(stream == NULL) 
    return S_Error;

  write = fwrite(SIGNATURE_HEADER, sizeof(u_char), SIG_HEADER_BYTES, stream);
  if(write < SIG_HEADER_BYTES) 
    return S_Error;

  write = fwrite(&siglen, sizeof(size_t), 1, stream);
  if(write < 1) 
    return S_Error;

  fwrite(sig, sizeof(u_char), siglen, stream);
  if(write < siglen) 
    return S_Error;

  PEM_write_PUBKEY(stream, rsa_keypair);
  EVP_PKEY_free(rsa_keypair);
  fclose(stream);
  return S_Valid;
}

int verify_buff_sign(const unsigned char* m, size_t m_len, 
  char* path) 
{
  EVP_PKEY* rsa_pkey = NULL;
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  u_char hash[32];
  u_char header[256];
  u_char* sig;
  size_t siglen;
  int read;

  FILE* stream = fopen("publica", "r");
  if(stream == NULL) {
    p_error("No se pudo abrir el archivo de la firma")
    return S_Error;
  }

  read = fread(header, sizeof(u_char), SIG_HEADER_BYTES, stream);
  if(read < SIG_HEADER_BYTES || memcmp(SIGNATURE_HEADER, header, SIG_HEADER_BYTES)) { 
    p_error("No es una firma digital. No contiene la cabecera")
    return S_Error;
  }
      
  read = fread(&siglen, sizeof(size_t), 1, stream);
  if(read < 1) {
    p_error("No es una firma digital. No contiene la longitud de la firma")
    return S_Error;
  }

  if(!(sig = OPENSSL_malloc(siglen))) {
    p_error("No se pudo reservar memoria para la firma.")
    return S_Error;
  }
  
  read = fread(sig, sizeof(u_char), siglen, stream);
  if(read < siglen) {
    p_error("No es una firma digital. No contiene la firma.")
    return S_Error;
  }

  rsa_pkey = PEM_read_PUBKEY(stream, NULL, NULL, NULL);
  fclose(stream);

  // Calcular el hash del buffer
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, SHA2_ALGORITHM, NULL);
  EVP_DigestUpdate(mdctx, m, m_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  // Verificar la firma
  ctx = EVP_PKEY_CTX_new(rsa_pkey, NULL);
  EVP_PKEY_verify_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
  EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
  int ret = EVP_PKEY_verify(ctx, sig, siglen, hash, 32);
  EVP_PKEY_CTX_free(ctx);
  return ret? S_Valid : S_Error;
}
