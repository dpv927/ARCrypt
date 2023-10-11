#pragma once

#define DEC_BUFF_SIZE     8192 /* Tamano en bytes del buffer temporal de datos encriptados */
#define DEC_CIPHER_SIZE   DEC_BUFF_SIZE /* Tamano en bytes del buffer de datos descifrados */
#define DEC_ELEMENT_BYTES 1 /* Tamano en bytes por elemento a leer del archivo a desencriptar */

void decryptFile(const char* inputFile, const char* outputFile, const unsigned char* key, const unsigned char* iv);
