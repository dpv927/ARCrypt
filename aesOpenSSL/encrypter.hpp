#pragma once

namespace Encryption {
  
  #define ENC_BUFF_BYTES  1024    /* Bytes del buffer de encriptado */
  #define ENC_EPER_BUFF   1       /* Bytes por elemento a encriptar */
  #define ENC_EXTENSION   ".enc"  /* Extension temporal del archivo encriptado */
  #define ENC_EXT_PADDING 5       /* Diferencia de chars entre el nombre del archivo y el encriptado */

  /* Encripta un string (cadena de caracteres)
   * 
   * @param text: Texto a encriptar.
   * @param text_len: Longitud del texto en caracteres.
   * @param key: Clave simetrica a utilizar.
   * @param cipher: Puntero al array donde guardar el texto cifrado.
   *
   * @returns Devuelve la longitud del texto cifrado.
   * * */
  int encryptStr(const unsigned char* text, const unsigned int text_len, const unsigned char* key, unsigned char* cipher);

  /* Encripta un archivo
   * 
   * @param path: Ruta del archivo a encriptar.
   * @param key: Clave simetrica a utilizar.
   * * */
  void encryptFile(const char* path, const unsigned char* key);
}
