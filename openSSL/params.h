#pragma once

#define FILE_PATH_BYTES 2048
#define AES_MODE     1
#define AES_BITS     256
#define AES_IV_BYTES 16
#define RSA_BITS     2048
#define SHA2_BITS    512

/* Bytes de la clave AES */
#if(AES_BITS==128)
  #define AES_KEY_BYTES 16
#elif(AES_BITS==192)
  #define AES_KEY_BYTES 24
#elif(AES_BITS==256)
  #define AES_KEY_BYTES 32
#endif

/* Usar CBC como modo AES */
#if (AES_MODE==1)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_cbc()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_cbc()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_cbc()
#endif
/* Usar GCM como modo AES */
#elif (AES_MODE==2)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_gcm()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_gcm()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_gcm()
  #endif
#endif

/* Bytes de la clave RSA */
#if(RSA_BITS==1024)
  #define RSA_KEY_BYTES 128
#elif(RSA_BITS==1536)
  #define RSA_KEY_BYTES 192
#elif(RSA_BITS==2048)
  #define RSA_KEY_BYTES 256
#endif

/* Bytes del hash SHA2 */
#if(SHA2_BITS==224)
  #define SHA2_BYTES 28
  #define SHA_ALGORITHM SHA224()
#elif(SHA2_BITS==256)
  #define SHA2_BYTES 32
  #define SHA_ALGORITHM SHA256()
#elif(SHA2_BITS==384)
  #define SHA2_BYTES 48
  #define SHA_ALGORITHM SHA384()
#elif(SHA2_BITS==512)
  #define SHA2_BYTES 64
  #define SHA_ALGORITHM SHA512()
#endif

