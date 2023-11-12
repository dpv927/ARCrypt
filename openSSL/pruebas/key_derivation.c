#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>

static const unsigned char xcghash[32] = {
  0x14, 0xac, 0x44, 0x54, 0xa3, 0xce, 0x9e, 0xc4,
  0xd4, 0xf4, 0x78, 0xbe, 0xf3, 0x0d, 0xbb, 0xeb,
  0x73, 0x76, 0x6a, 0xe2, 0xd8, 0x07, 0x78, 0xb2,
  0x81, 0x3a, 0xf2, 0x15, 0xbb, 0xf6, 0xdb, 0x9b,
};

static const unsigned char sessid[32] = {
  0xff, 0x03, 0xe5, 0xcf, 0x83, 0x5c, 0x98, 0x72,
  0xa8, 0xb6, 0xec, 0x84, 0x90, 0x37, 0x99, 0x27,
  0x75, 0x35, 0x68, 0xcb, 0x8d, 0x55, 0x45, 0x5b,
  0x14, 0x8e, 0x27, 0x68, 0x1b, 0x49, 0x40, 0x01,
};

int main(void) {
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;

  char type = EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV;
  unsigned char key[32] = "passwd";
  unsigned char out[32];
  size_t outlen = sizeof(out);
  OSSL_PARAM params[6], *p = params;

  kdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  *p++ = OSSL_PARAM_construct_utf8_string("digest", "sha256", OSSL_PARAM_UNMODIFIED);
  *p++ = OSSL_PARAM_construct_octet_string("key", key, (size_t)32);
  *p++ = OSSL_PARAM_construct_octet_string("xcghash", (void*) xcghash, (size_t)32);
  *p++ = OSSL_PARAM_construct_octet_string("session_id", (void*)sessid, (size_t)32);
  *p++ = OSSL_PARAM_construct_utf8_string("type", &type, sizeof(type));
  *p   = OSSL_PARAM_construct_end();
  
  EVP_KDF_derive(kctx, out, outlen, params);
  EVP_KDF_CTX_free(kctx);
  return 0;
}
