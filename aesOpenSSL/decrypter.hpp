#pragma once

namespace Decryption {
  
  #define DEC_BUFF_BYTES  1024    /* Bytes del buffer de encriptado */
  #define DEC_EPER_BUFF   1       /* Bytes por elemento a encriptar */
  #define DEC_EXTENSION   ".dec"  /* Extension temporal del archivo encriptado */
  #define DEC_EXT_PADDING 5       /* Diferencia de chars entre el nombre del archivo y el encriptado */

  /* Desencripta un string (cadena de caracteres)
   * 
   * @param cipher: Texto a desencriptar.
   * @param cipher_len: Longitud del texto en caracteres.
   * @param key: Clave simetrica a utilizar.
   * @param text: Puntero al array donde guardar el texto descifrado.
   *
   * @returns Devuelve la longitud del texto descifrado. 
   * * */
  int decryptStr(const unsigned char *cipher, const unsigned int cipher_len, const unsigned char *key, unsigned char *text);

   /* Desencripta un archivo
   * 
   * @param path: Ruta del archivo a desencriptar.
   * @param key: Clave simetrica a utilizar. 
   * * */ 
  void decryptFile(const char* path, const unsigned char* key);
}
