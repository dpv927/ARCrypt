#pragma once

#define DEC_BUFF_SIZE     8192 /* Tamano en bytes del buffer temporal de datos encriptados */
#define DEC_CIPHER_SIZE   DEC_BUFF_SIZE /* Tamano en bytes del buffer de datos descifrados */
#define DEC_ELEMENT_BYTES sizeof(unsigned char) /* Tamano en bytes por elemento a leer */

void decryptFile(const char* inputFile, const char* keyFile, const unsigned char* iv);

void decryptKey(const char* AESkeyFile, const char* RSAkeyFile);