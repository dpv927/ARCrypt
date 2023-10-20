#pragma once

#define ENC_BUFF_SIZE     8192 /* Tamano en bytes del buffer temporal de encriptado */
#define ENC_CIPHER_SIZE   ENC_BUFF_SIZE+EVP_MAX_BLOCK_LENGTH /* Tamano en bytes del buffer de datos cifrados */
#define ENC_ELEMENT_BYTES 1 /* Tamano en bytes por elemento a leer del archivo a encriptar */

void encryptFile(const char* inputFile, const unsigned char* iv);
