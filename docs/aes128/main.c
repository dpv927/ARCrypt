#include "aes128.h"
#include <stdint.h>

int main(void) {
 
  const uint8_t key[16] = "Thats my Kung Fu";
  uint8_t data[] = "Two One Nine Two";

  aes128_encrypt(data,key);
  return 0;
}
