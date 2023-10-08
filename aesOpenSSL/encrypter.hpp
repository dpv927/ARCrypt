namespace Encryption {
  
  /* Encripta un string (cadena de caracteres)
   * 
   * @param text: Texto a encriptar.
   * @param text_len: Longitud del texto en caracteres.
   * @param key: Clave simetrica a utilizar.
   * @param cipher: Puntero al array donde guardar el texto cifrado.
   *
   * @returns Devuelve la longitud del texto cifrado.
   * */
  int encryptStr(const unsigned char* text, const int text_len, const unsigned char* key, unsigned char* cipher);

  /* Encripta un archivo
   * 
   * @param path: Ruta del archivo a encriptar.
   * @param key: Clave simetrica a utilizar.
   *
   * @returns Devuelve 0 si la operacion se ha realizado correctamente 
   * y 1 en caso contrario.
   * */
  int encryptFile(const unsigned char* path, unsigned char* key);
}
