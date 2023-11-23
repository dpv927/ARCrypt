#pragma once

#include <stdlib.h>
#include "params.h"

#define ENC_BUFF_SIZE     8192
#define ENC_CIPHER_SIZE   ENC_BUFF_SIZE+EVP_MAX_BLOCK_LENGTH

///
/// @brief Encripta un archivo con una clave AES generada aleatoriamente. La funcion realiza una
/// llamada a la funcion @encryptKey para la clave generada AES con una clave publica RSA.
/// 
/// @param inputFile Ruta del archivo a encriptar.
/// @param contrasena que el usuario va a utilizar para proteger el archivo encriptado
///
void encryptFile(const char* inputFile, char passwd[AES_KEY_BYTES]);