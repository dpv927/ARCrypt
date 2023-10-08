#pragma once

namespace Decryption {
  
  /* Encripts a string */
  int decryptStr(unsigned char* cipher, int cipher_len, unsigned char* key, unsigned char* text);
}
