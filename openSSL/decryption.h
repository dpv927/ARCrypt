#pragma once

#include <stdlib.h>
#include "params.h"

#define DEC_BUFF_SIZE     8192
#define DEC_CIPHER_SIZE   DEC_BUFF_SIZE

///
/// @brief Desencripta un archivo dada una superclave con
/// el que se encripto.
/// 
/// @param inputFile Ruta del archivo a encriptar
/// @param passwd Contrasena con la que el usuario encripto el archivo
/// @param keyFile Ruta de la superclave
///
void decryptFile(const char* inputFile, char* passwd, const char* keyFile);