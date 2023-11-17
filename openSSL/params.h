#pragma once

#define FILE_PATH_BYTES 2048
#define MOD_NAME 1
#define MOD_BITS 256

/* Bytes de la clave */
#if(MOD_BITS==128)
    #define KEY_BYTES 16
    #define RSA_KEY_BITS 1024
#elif(MOD_BITS==192)
    #define KEY_BYTES 24
    #define RSA_KEY_BITS 1536
#elif(MOD_BITS==256)
    #define KEY_BYTES 32
    #define RSA_KEY_BITS 2048
#endif

/* Usar ECB como modo */
#if(MOD_NAME==0)
  #if (MOD_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_ecb()
  #elif (MOD_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_ecb()
  #elif (MOD_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_ecb()
#endif
/* Usar CBC como modo */
#elif (MOD_NAME==1)
  #if (MOD_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_cbc()
  #elif (MOD_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_cbc()
  #elif (MOD_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_cbc()
#endif
/* Usar CTR como modo */
#elif (MOD_NAME==2)
  #if (MOD_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_ctr()
  #elif (MOD_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_ctr()
  #elif (MOD_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_ctr()
#endif
/* Usar GCM como modo */
#elif (MOD_NAME==3)
  #if (MOD_BITS==128)
    #define AES_ALGORITHM EVP_aes_128_gcm()
  #elif (MOD_BITS==192)
    #define AES_ALGORITHM EVP_aes_192_gcm()
  #elif (MOD_BITS==256)
    #define AES_ALGORITHM EVP_aes_256_gcm()
  #endif
#endif
