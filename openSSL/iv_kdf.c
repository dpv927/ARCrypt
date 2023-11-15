#include <openssl/kdf.h>
#include <openssl/params.h>
#include <stdio.h>
#include <string.h>
#include "iv_kdf.h"
#include "params.h"

#if(SHA2_BITS==224)
  #define SHA2_NAME "sha224"
#elif(SHA2_BITS==256)
  #define SHA2_NAME "sha256"
#elif(SHA2_BITS==384)
  #define SHA2_NAME "sha384"
#elif(SHA2_BITS==512)
  #define SHA2_NAME "sha512"
#endif

void derive_AES_key(const u_char* key, u_char* iv)
{
  EVP_KDF *kdf;
  EVP_KDF_CTX *kctx;
  char type = EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV;
  kdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
  kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);

  OSSL_PARAM params[6] = {
    OSSL_PARAM_construct_utf8_string("digest", SHA2_NAME, OSSL_PARAM_UNMODIFIED),
    OSSL_PARAM_construct_octet_string("key", (void*) key, AES_KEY_BYTES),
    OSSL_PARAM_construct_octet_string("xcghash", (void*) xcghash, sizeof(xcghash)),
    OSSL_PARAM_construct_octet_string("session_id", (void*)sessid, sizeof(sessid)),
    OSSL_PARAM_construct_utf8_string("type", &type, sizeof(type)),
    OSSL_PARAM_construct_end()
  };

  EVP_KDF_derive(kctx, iv, AES_IV_BYTES, params);
  EVP_KDF_CTX_free(kctx);
}
