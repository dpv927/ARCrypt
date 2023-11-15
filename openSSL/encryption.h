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
void encryptFile(const char* inputFile, const char passwd[AES_KEY_BYTES]);

///
/// @brief Encripta un buffer en el que se almacena una clave AES. La funcion genera un par de claves
/// RSA, encripta la clave AES con la clave publica, guarda en el buffer cipher_aes_key la clave encriptada
/// de longitud RSA_KEY_BYTES, y devuelve un puntero a la clave privada RSA creada.
///
/// Nota: Tener en cuenta que el puntero que se devuelve no es la clave RSA en sí, sino el PEM (un texto plano
/// que tiene un cierto formato para OpenSSL) de la clave privada RSA, lo que resulta en un buffer de una 
/// longitud mayor a RSA_KEY_BYTES (y que, además, es incierta, pese a que suele rondar alrededor de 1704 bytes).
/// 
/// @param aes_key Buffer de la clave AES a encriptar.
/// @param cipher_aes_key Buffer donde guardar la clave AES encriptada.
/// @param aesk_iv Buffer que contiene la clave IV de AES
/// @param cipher_aesk_iv Buffer donde guardar el IV encriptado 
/// @param RSA_PEM_len Puntero a una variable donde se guardará la longitud de la clave RSA.
///
/// @return Puntero a la clave privada RSA reservada con malloc. 
///
u_char* encryptAES_withRSA(const u_char aesk[AES_KEY_BYTES], u_char cipher_aesk[RSA_KEY_BYTES],
  u_char aesk_iv[AES_IV_BYTES], u_char cipher_aesk_iv[RSA_KEY_BYTES], size_t* RSA_PEM_len);

///
/// @brief Encripta un buffer que contiene la clave privada RSA con AES, utilizando como clave la contraseña  
/// que el usuario ha proporcionado al programa.
///
/// Nota: Tener en cuenta que la clave encriptada RSA se guardará de nuevo en el buffer rsa_len que 
/// se pasa como parámetro.
///
/// @param rsa_key Buffer con la clave privada (en realidad el PEM) RSA.
/// @param rsa_len Longitud del buffer de la clave privada RSA.
/// @param aes_key Buffer con la clave AES. Sera la contraseña del usuario.
/// @param aes_key_iv Buffer con el IV generado a partir de la clave AES.
///
/// @return Devuelve el nuevo tamaño de la clave encriptada RSA. Si hay un error, devuelve -1.
///
int encryptRSAKey_withAES(const u_char* rsa_key, u_char* cipher_rsa_key, const size_t rsa_len, 
  const u_char aes_key[AES_KEY_BYTES], const u_char aes_key_iv[AES_IV_BYTES]);
