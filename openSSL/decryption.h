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

///
/// @brief Desencripta una clave privada RSA con AES, dada una clave y su IV. 
/// Tener en cuenta que la clave sera la password del usuario y el IV una
/// derivacion de dicha password.
/// 
/// @param cipher_rsa_key Buffer donde esta almacenada la clave privada RSA 
/// que fue encriptada con AES.
/// @param rsa_key Buffer donde se va a guardar la clave privada RSA desencriptada
/// @param rsa_len Longitud del buffer de la clave RSA encriptada.
/// @param aes_key Clave AES.
/// @param aes_key_iv IV de AES.
///
int decryptRSAKey_withAES(const u_char* cipher_rsa, const size_t cipher_rsa_len,
	u_char* rsa, const u_char* aes);

///
/// @brief Desencripta una clave AES con la que se encripto el archivo en un principio,
/// dada la clave privada RSA necesaria para desencriptarla.
/// 
/// @param cipher_aes_key Buffer con la clave AES a desencriptar.
/// @param aesk Buffer donde guardar la clave AES desencriptada.
/// @param rsa_skey Buffer con la clave privada RSA.
/// @param rsa_keylen Longitud de la clave privada RSA.
///
void decryptAESKey_withRSA(const unsigned char* cipher_aes_key, 
  unsigned char* aes_key, unsigned char* rsa_skey, size_t rsa_keylen);