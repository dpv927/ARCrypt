#pragma once

#define ENC_BUFF_SIZE     8192
#define ENC_CIPHER_SIZE   ENC_BUFF_SIZE+EVP_MAX_BLOCK_LENGTH
#define ENC_ELEMENT_BYTES sizeof(unsigned char)

/* @brief Encripta un archivo con una clave AES generada aleatoriamente. La funcion realiza una
* llamada a la funcion @encryptKey para la clave generada AES con una clave publica RSA.
* 
* @param inputFile Ruta del archivo a encriptar.
* @param iv Vector de inicializacion (Normalmente NULL).
* * * */
void encryptFile(const char* inputFile, const unsigned char* iv);

/* @brief Encripta un archivo en la que se almacena una AES. La funcion genera un par de claves
* RSA, encripta la clave AES con la clave publica y guarda en un archivo la clave privada RSA para
* un posterior uso en caso de querer desencriptar el archivo.
* 
* @param AESkeyFile Ruta de la clave AES a encriptar.
* * * */
void encryptKey(const char* AESkeyFile);