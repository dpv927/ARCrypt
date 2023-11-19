#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#define AES_KEY_BYTES 32
#define RSA_KEY_BYTES 256

/// 
/// @brief Encrypt an AES key with the public key of a generated RSA key pair.
/// 
/// @param aes_key AES key buffer.
/// @param cipher_aes_key Buffer where the encrypted AES key is going to be stored.
/// @param RSA_PEM_len legth of the private RSA key PEM.
/// 
/// @return Pointer to the allocated RSA private key
/// 
unsigned char* encryptAESKey_withRSA(const unsigned char aes_key[AES_KEY_BYTES], 
  unsigned char cipher_aes_key[RSA_KEY_BYTES], size_t* RSA_PEM_len)
{
  EVP_PKEY *rsa_keypair = NULL;
  EVP_PKEY_CTX *ctx;
  unsigned char* rsa_skey;
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
  EVP_PKEY_encrypt(ctx, cipher_aes_key, &outlen, aes_key, AES_KEY_BYTES);

  // Write RSA private key to mem 
  rsa_bio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(rsa_bio, rsa_keypair, NULL, NULL, 0, 0, NULL);
  pending = BIO_pending(rsa_bio);
  rsa_skey = OPENSSL_malloc(pending);
  BIO_read(rsa_bio, rsa_skey, pending);
  *RSA_PEM_len = pending;

  // Free all that stuff!
  BIO_free(rsa_bio);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(rsa_keypair);
  return rsa_skey;
}

/// 
/// @brief Decrypt an AES key with a private key of a RSA key pair.
/// 
/// @param cipher_aes_key Cipher AES key.
/// @param aes_key Buffer where the decrypted AES key is going to be stored.
/// @param rsa_skey RSA private key.
/// @param RSA_PEM_len legth of the private RSA key PEM.
///
void decryptAESKey_withRSA(const unsigned char* cipher_aes_key, 
  unsigned char* aes_key, unsigned char* rsa_skey, size_t rsa_keylen)
{
  EVP_PKEY* evp_rsa_key;
  EVP_PKEY_CTX* ctx;
  BIO* rsa_bio;
  size_t outlen;

  // Read RSA private key from mem
  rsa_bio = BIO_new(BIO_s_mem());
  BIO_write(rsa_bio, rsa_skey, rsa_keylen);
  evp_rsa_key = PEM_read_bio_PrivateKey_ex(rsa_bio, NULL, NULL, NULL, NULL, NULL);
  BIO_free(rsa_bio); 
  
  // Decrypt AES key with RSA 
  ctx = EVP_PKEY_CTX_new(evp_rsa_key, NULL);
  EVP_PKEY_decrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_decrypt(ctx, aes_key, &outlen, cipher_aes_key, RSA_KEY_BYTES);

  // Free all that stuff!
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(evp_rsa_key);
}

/// 
/// @brief Calculates the hash value over a buffer.
/// 
/// @param m A message of any legth
/// @param hash Buffer where the hash value is going to be stored
///
void calculateHash(const char* m, unsigned char hash[256]) 
{
  EVP_MD_CTX *mdctx;
  mdctx = EVP_MD_CTX_create();
  EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(mdctx, m, strlen(m));
  EVP_DigestFinal_ex(mdctx, hash, NULL);
  EVP_MD_CTX_destroy(mdctx);
  EVP_cleanup();
}
