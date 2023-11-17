#pragma once

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
void decryptFile(const char* inputFile, const char* keyFile, const unsigned char* iv);

/* @brief Desencripta un archivo que contiene una clave AES dada la ruta de la clave privada
* RSA que se necesita para desencriptar dicha clave AES.
* 
* @param AESkeyFile Ruta del archivo de la clave AES a desencriptar.
* @param RSAkeyFile Ruta del archivo de la clave privada RSA.
* * * */
void decryptKey(const char* AESkeyFile, const char* RSAkeyFile);