#pragma once

#define MOD_NAME 3
#define MOD_BITS 256

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
