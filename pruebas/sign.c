#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Signature {
  unsigned char sign[256];
  unsigned char* rpk;
  size_t rpk_len;
};

void sign_buff(const unsigned char* m, size_t m_len,
  struct Signature* s) 
{
  EVP_PKEY* rsa_keypair = NULL;
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  unsigned char hash[32];
  size_t siglen;
  BIO* rsa_bio;

  // Generar un par de claves RSA  
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(ctx);

  // Obtener el hash del buffer
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, m, m_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  // Obtener firma - Al fin y al cabo consiste en encriptar 
  // el hash del mensaje con la clave privada RSA
  ctx =  EVP_PKEY_CTX_new(rsa_keypair, NULL);
  EVP_PKEY_sign_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
  EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
  EVP_PKEY_sign(ctx, s->sign, &siglen, hash, 32);
  EVP_PKEY_CTX_free(ctx);

  // Guardar la clave publica RSA en memoria
  rsa_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PUBKEY(rsa_bio, rsa_keypair);
  s->rpk_len = BIO_pending(rsa_bio);
  s->rpk = (u_char*) malloc(s->rpk_len);
  BIO_read(rsa_bio, s->rpk, s->rpk_len);
  BIO_free(rsa_bio);
}

int verify_buff_sign(const unsigned char* m, size_t m_len, 
  struct Signature* s) 
{
  EVP_PKEY* rsa_pkey = NULL;
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  unsigned char hash[32];
  BIO* rsa_bio;

  // Recuperar la clave publica RSA de memoria
  rsa_bio = BIO_new(BIO_s_mem());
  BIO_write(rsa_bio, s->rpk, s->rpk_len);
  rsa_pkey = PEM_read_bio_PUBKEY(rsa_bio, NULL, NULL, NULL);
  BIO_free(rsa_bio);

  // Calcular el hash del buffer
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, m, m_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  // Verificar la firma
  ctx = EVP_PKEY_CTX_new(rsa_pkey, NULL);
  EVP_PKEY_verify_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
  EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256());
  int ret = EVP_PKEY_verify(ctx, s->sign, 256, hash, 32);
  EVP_PKEY_CTX_free(ctx);
  return ret;
}

int main(void) {
  char* str = "hello";
  struct Signature s;

  // Firmar str y guardar la firma en 
  // la estructura 's'
  sign_buff((unsigned char*) str, strlen(str), &s);
  int ret = verify_buff_sign((unsigned char*) str, strlen(str), &s);

  printf("%d", ret);
}
