#pragma once
#include <cstddef>

namespace Encryption {
   
  #define ENC_EPER_BUFF     1       /* Bytes por elemento a encriptar */
  #define ENC_EXTENSION     ".enc"  /* Extension temporal del archivo encriptado */
  #define ENC_EXT_PADDING   4       /* Diferencia de chars entre el nombre del archivo y el encriptado */
  #define ENC_BUFF_BYTES    1024    /* Bytes del buffer de encriptado temporal */
  #define ENC_CIPHER_BYTES  ENC_BUFF_BYTES+(ENC_BUFF_BYTES>>1) /* Bytes del buffer de datos cifrados */

  /* Encripta un string (cadena de caracteres)
   * 
   * @param text: Texto a encriptar.
   * @param text_len: Longitud del texto en caracteres.
   * @param key: Clave simetrica a utilizar.
   * @param cipher: Puntero al array donde guardar el texto cifrado.
   *
   * @returns Devuelve la longitud del texto cifrado.
   * * */
  size_t encryptStr(const unsigned char* text, const unsigned int text_len, const unsigned char* key, unsigned char* cipher);

  /* Encripta un archivo
   * 
   * @param path: Ruta del archivo a encriptar.
   * @param key: Clave simetrica a utilizar.
   * * */
  void encryptFile(const char* path, const unsigned char* key);

  void readfileBin(const char* path);
}
