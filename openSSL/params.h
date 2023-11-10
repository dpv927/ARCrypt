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
  #define RSA_KEY_BYTES 128

  static const unsigned char SUPERKEY_HEADER[AES_KEY_BYTES] = {
    0x20, 0xf1, 0x3e, 0x88,
    0x53, 0x3b, 0x22, 0x19,
    0xf6, 0xe0, 0xd0, 0x71,
    0x8d, 0x6a, 0x28, 0xf2,
  };
#elif(AES_BITS==192)
  #define AES_KEY_BYTES 24
  #define RSA_KEY_BITS  1536
  #define RSA_KEY_BYTES 192

  static const unsigned char SUPERKEY_HEADER[AES_KEY_BYTES] = {
    0x9f, 0x62, 0x42, 0xef,
    0xef, 0x1d, 0x0f, 0x5d,
    0x07, 0xd0, 0x64, 0x8b,
    0xe4, 0x16, 0x69, 0x91,
    0x57, 0x68, 0x4e, 0x61,
    0xfd, 0x6a, 0xff, 0xf8,
  };
#elif(AES_BITS==256)
  #define AES_KEY_BYTES 32
  #define RSA_KEY_BITS  2048
  #define RSA_KEY_BYTES 256

  static const unsigned char SUPERKEY_HEADER[AES_KEY_BYTES] = {
    0x23, 0x07, 0xe7, 0xc0,
    0x3b, 0x5a, 0x11, 0xb1,
    0xc3, 0xf4, 0x4c, 0x39,
    0x36, 0x11, 0x0c, 0x57,
    0x7e, 0x8c, 0x22, 0xb1,
    0x28, 0x63, 0x90, 0x6f,
    0x4e, 0x42, 0xfe, 0x7c,
    0xd7, 0xe6, 0xac, 0x34,
  };
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