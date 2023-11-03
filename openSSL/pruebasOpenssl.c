#include "encryption.h"
#include "decryption.h"
#include "params.h"

/* Si quieres probar a desencriptar, cambia
 * el modo a 1. */
#define TEST_MODE 0

#if(MOD_NAME!=0)
/* A 128 bit IV */
static const unsigned char iv[] = { 
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
}; 
#else
/* No auth IV */
static const unsigned char iv[] = NULL;
#endif

/* File paths */
#define processed_file  "testfile.txt"
#define key_file        "key.txt" 

int main(void) {
  #if(TEST_MODE==0)
  //encryptFile(processed_file, iv);
  encryptKey("i.png.key");
  //decryptKey("i.png.key", "NoToquesPorQueTocas");
  #elif(TEST_MODE==1)
  decryptFile(processed_file, key_file, iv);
  #endif
  return 0;
}
