#pragma once

#include <stdlib.h>
#include "params.h"

///
/// @brief Calcula el hash (resumen) de un buffer. 
///
/// @param m Buffer a procesar.
/// @param m_size Tamaño del buffer a procesar.
/// @param hash Buffer donde guardar el hash.
///
void calculateHash(const u_char* m, const size_t m_size, 
  unsigned char hash[SHA2_BYTES]);
