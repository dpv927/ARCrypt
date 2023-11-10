#pragma once

#define FILE_PATH_BYTES 2048
#define AES_MODE  1
#define AES_BITS  256
#define SHA2_BITS 512

/* Bytes del hash SHA2 */
#if(SHA2_BITS==224)
  #define SHA2_BYTES 28
#elif(SHA2_BITS==256)
  #define SHA2_BYTES 32
#elif(SHA2_BITS==384)
  #define SHA2_BYTES 48
#elif(SHA2_BITS==512)
  #define SHA2_BYTES 64
#endif

/* Modo de SHA2 */
#if(SHA2_BITS==224)
  #define SHA_ALGORITHM SHA224()
#elif(SHA2_BITS==256)
  #define SHA_ALGORITHM SHA256()
#elif(SHA2_BITS==384)
  #define SHA_ALGORITHM SHA384()
#elif(SHA2_BITS==512)
  #define SHA_ALGORITHM SHA512()
#endif

/* Bytes de la clave */
#if(AES_BITS==128)
    #define AES_KEY_BYTES 16
    #define RSA_KEY_BITS  1024
#elif(AES_BITS==192)
    #define AES_KEY_BYTES 24
    #define RSA_KEY_BITS  1536
#elif(AES_BITS==256)
    #define AES_KEY_BYTES 32
    #define RSA_KEY_BITS  2048
#endif

/* Usar ECB como modo */
#if(AES_MODE==0)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_ecb()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_ecb()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_ecb()
#endif
/* Usar CBC como modo */
#elif (AES_MODE==1)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_cbc()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_cbc()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_cbc()
#endif
/* Usar CTR como modo */
#elif (AES_MODE==2)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_ctr()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_ctr()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_ctr()
#endif
/* Usar GCM como modo */
#elif (AES_MODE==3)
  #if (AES_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_gcm()
  #elif (AES_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_gcm()
  #elif (AES_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_gcm()
  #endif
#endif
