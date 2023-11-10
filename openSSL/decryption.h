#pragma once

#include "params.h"

#define DEC_BUFF_SIZE     8192
#define DEC_CIPHER_SIZE   DEC_BUFF_SIZE
#define DEC_ELEMENT_BYTES sizeof(unsigned char)

/* @brief Desencripta un archivo dada una clave AES. La funcion supone que existe un archivo
* con el mismo nombre que la clave con la extension ".rsa", que contiene la clave privada RSA
* para poder desencriptar la clave AES. 
* 
* @param inputFile Ruta del archivo a desencriptar.
* @param keyFile Ruta del archivo que contiene la clave encriptada.
* @param iv Vector de inicializacion (Normalmente NULL).
* * * */
void decryptFile_withAES(const char* inputFile, const char* keyFile);

/* @brief Desencripta un archivo que contiene una clave AES dada la ruta de la clave privada
* RSA que se necesita para desencriptar dicha clave AES.
* 
* @param AESkeyFile Ruta del archivo de la clave AES a desencriptar.
* @param RSAkeyFile Ruta del archivo de la clave privada RSA.
* @param AESkey Buffer de longitud KEY_BYTES donde se va a guardar la clave desencriptada.
* * * */
void decryptAESKey_withRSA(const char* AESkeyFile, const char* RSAkeyFile, unsigned char AESkey[AES_KEY_BYTES]);