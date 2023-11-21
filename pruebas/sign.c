#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Signature {
  unsigned char* sig;
  size_t siglen;
  unsigned char* rpk;
  size_t rpklen;
};

void sign_buff(const unsigned char* m, size_t m_len,
  struct Signature* s) 
{
  EVP_PKEY* rsa_keypair = NULL;
  EVP_PKEY* rsa_skey = NULL;
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  unsigned char hash[32];
  size_t siglen;
  //BIO* rsa_bio;

  // Generar un par de claves RSA  
  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &rsa_keypair);
  EVP_PKEY_CTX_free(ctx);

  // Obtener la clave privada 
  FILE* p = fopen("privada", "w");
  PEM_write_PrivateKey(p, rsa_keypair, NULL, NULL, 0, NULL, NULL);
  fclose(p);

  p = fopen("privada", "r");
  rsa_skey = PEM_read_PrivateKey(p, NULL, NULL, NULL);
  fclose(p);
  
  // Obtener el hash del buffer
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, m, m_len);
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();

  // Obtener firma - Al fin y al cabo consiste en encriptar 
  // el hash del mensaje con la clave privada RSA
  //unsigned char* sig;
  ctx = EVP_PKEY_CTX_new(rsa_skey, NULL /* no engine */);
  if (!ctx)
    printf("contexto!");
  if (EVP_PKEY_sign_init(ctx) <= 0)
    printf("init");
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    printf("padding");
  if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    printf("sha");

  /* Determine buffer length */
  if (EVP_PKEY_sign(ctx, NULL, &(s->siglen), hash, 32) <= 0)
    printf("aja");

  s->sig = OPENSSL_malloc(s->siglen);
  printf("%zu ", s->siglen);
  if (!(s->sig))
    printf("malloc");

  if (EVP_PKEY_sign(ctx, s->sig, &(s->siglen), hash, 32) <= 0)
    printf("aja2");

  //for (int i =0; i<s->sign_len; i++) {
  //printf("%0x ", s->sign[i]);
  //}

  // Guardar la clave publica RSA en memoria
  //rsa_bio = BIO_new(BIO_s_mem());
  //PEM_write_bio_PUBKEY(rsa_bio, rsa_keypair);
  //s->rpk_len = BIO_pending(rsa_bio);
  //s->rpk = (unsigned char*) malloc(s->rpk_len);
  //BIO_read(rsa_bio, s->rpk, s->rpk_len);

  FILE* a = fopen("publica", "w");
  char pepe[4] = "pepe";
  fwrite(pepe, sizeof(unsigned char), strlen("pepe"), a);
  PEM_write_PUBKEY(p, rsa_keypair);
  fclose(a);

  // Free all!
  //BIO_free(rsa_bio);
  EVP_PKEY_free(rsa_keypair);
}

int verify_buff_sign(const unsigned char* m, size_t m_len, 
  struct Signature* s) 
{
  EVP_PKEY* rsa_pkey = NULL;
  EVP_PKEY_CTX* ctx;
  EVP_MD_CTX *mdctx;
  unsigned char hash[32];
  //BIO* rsa_bio;

  // Recuperar la clave publica RSA de memoria
  //rsa_bio = BIO_new(BIO_s_mem());
  //BIO_write(rsa_bio, s->rpk, s->rpk_len);
  //rsa_pkey = PEM_read_bio_PUBKEY(rsa_bio, NULL, NULL, NULL);
  //BIO_free(rsa_bio);
  
  FILE* p = fopen("publica", "r");
  rsa_pkey = PEM_read_PUBKEY(p, NULL, NULL, NULL);
  fclose(p);

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
  int ret = EVP_PKEY_verify(ctx, s->sig, s->siglen, hash, 32);
  EVP_PKEY_CTX_free(ctx);
  return ret;
}

int main(void) {
  char* str = "hello";
  struct Signature s;

  // Firmar str y guardar la firma en 
  // la estructura 's'
  sign_buff((unsigned char*) str, strlen(str), &s);
  //int ret = verify_buff_sign((unsigned char*) str, strlen(str), &s);
  //printf("%d", ret);
  //free(s.rpk);
}
