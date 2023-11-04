#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "params.h"
#include "decryption.h"
#include "../utils/messages.h"

void decryptFile(const char* inputFile, const char* keyFile, const unsigned char* iv) {
  unsigned char inBuf[DEC_CIPHER_SIZE];
  unsigned char outBuf[DEC_BUFF_SIZE];
  unsigned char key[KEY_BYTES];
  char outputFile[FILE_PATH_BYTES+4];
  char input_file_cpy[FILE_PATH_BYTES];
  char rsa_key_file[FILE_PATH_BYTES+8];
  EVP_CIPHER_CTX* ctx; 
  struct stat inode_info;
  char* dir_name;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  /* Comprobar informacion basica sobre la ruta del fichero objetivo.
  * Hay que comprobar si el usuario esta queriendo acceder an archivo al que no tiene
  * acceso, no existe o es una carpeta. 
  *
  * La encriptacion de carpetas no esta soportada ya que no se trata de un fichero
  * regular, es decir, no podemos leer los bytes en bruto de la carpeta porque 
  * la carpeta no es mas que una 'estructura' en la cual los archivos que contiene
  * 'apuntan' a esta. Por lo tanto, leer los bytes de dicha carpeta no seria lo mismo
  * que leer los bytes de cada uno de los archivos que contiene.
  * 
  * Para solucionar esto, se podria aplicar una funcion de encriptacion recursiva a 
  * cada uno de los archivos de dicho directorio, o mas sencillo aun, comprimir dicha
  * carpeta en cualquier formato y encriptarla ya que en este ultimo caso si se trataria
  * de un fichero regular. */
  if(stat(inputFile, &inode_info)) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puede acceder o no existe el fichero.")
    exit(EXIT_FAILURE);
  } if((inode_info.st_mode & S_IFMT) == S_IFDIR) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("La encriptacion de carpetas no esta soportada. "\
    "Comprime dicha carpeta para asi obtener un archivo.")
    exit(EXIT_FAILURE);
  }

  /* Ver si el usuario tiene permisos de lectura/escritura y acceso sobre el 
  * directorio en el que se encuentra el archivo a encriptar.
  *
  * Es importante verificar esto ya que el usuario puede tener permisos de lectura
  *  en el directorio objetivo, pero no de escritura, y eso es muy importante a la 
  * hora de generar y eliminar los archivos en operaciones posteriores. */
  strcpy(input_file_cpy, inputFile);
  dir_name = dirname((char*) input_file_cpy);
  if (access(dir_name, W_OK | X_OK | R_OK)) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No tienes los permisos de lectura/escritura necesarios.")
    exit(EXIT_FAILURE);
  }

  /* Desencriptar la clave AES. En primer lugar, deberemos obtener el nombre
  * del archivo de la clave privada RSA (que se supone que se encuentra en el
  * mismo direcrorio que la clave y su mismo nommbre pero con la extension .rsa).
  * 
  * Despues llamamos a la funcion decryptKey, de manera que desencriptamos la clave
  * AES con la privada RSA, dando sus rutas y un buffer donde guardar la clave. */
  p_infoString("Desencriptando la clave AES", keyFile)
  strcpy(rsa_key_file, keyFile);
  strcat(rsa_key_file, ".rsa");
  decryptKey(keyFile, rsa_key_file, key);

  /* Iniciar contexto de desencriptacion. */
  ctx = EVP_CIPHER_CTX_new();   
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir stream en el archivo a desencriptar. */
  if((input = fopen(inputFile, "rb")) == NULL){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se puede abrir el archivo encriptado")
    exit(EXIT_FAILURE);
  };

  /* Generar el nombre del el archivo de desencriptado y guardarlo en outputFile.
  * Tendra el mismo nombre que el original pero con la extension temporal ".enc".*/
  strcpy(outputFile, inputFile);  
  strcat(outputFile, ".enc");

  /* Abrir stream para escribir en el archivo temporal */
  if((output = fopen(outputFile, "wb")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo crear el archivo de encriptacion temporal")
    exit(EXIT_FAILURE);
  }
  
  /* Este es el bucle principal del motor de desencriptacion. 
  * El funcionamiento basico es obtener DEC_CIPHER_SIZE (es una tamano cualquiera (p.e 8kb)) bytes del 
  * archivo a desencriptar, los guarda en el buffer inBuf y con ayuda de la funcion @EVP_DecryptUpdate,
  * descifra los datos de inBuf y los guarda en outBuf.
  * 
  * Por otro lado, necesitamos llevar cuenta de los bytes que leemos del archivo a desencriptar, ya que no
  * siempre vamos a poder leer DEC_CIPHER_SIZE bytes (p.e el archivo no tiene un multiplo de DEC_CIPHER_SIZE
  * bytes o simplemente es mas pequeno que DEC_CIPHER_SIZE). De esta manera, podemos escribir la informacion
  * descifrada en el archivo temporal (ni mas ni menos). */
  p_infoString("Desencriptando el archivo", inputFile)
  while ((bytesRead = fread(inBuf, DEC_ELEMENT_BYTES, DEC_CIPHER_SIZE, input)) > 0) {
    EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  }
  
  /* Quitar relleno si es necesario */
  EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  
  /* Liberar memoria y streams */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);

  /* S:wustituir */
  remove(inputFile);
  rename(outputFile, inputFile);
}

void decryptKey(const char* AESkeyFile, const char* RSAkeyFile, unsigned char AESkey [KEY_BYTES]) {
  unsigned char raw_aes_key[RSA_KEY_BITS>>3];
  FILE* aes_stream;
  FILE* rsa_stream;
  RSA* rsa_key;

  // Obtener la clave AES (abrir stream)
  p_infoString("Recuperando la clave AES encriptada", AESkeyFile)
  if((aes_stream = fopen(AESkeyFile, "r")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo abrir el archivo de la clave encriptada AES")
    exit(EXIT_FAILURE);
  }

  /* Obtener la clave AES encriptada.
  * La clave tendra como maximo un tamano de RSA_KEY_BITS>>3 (RSA_KEY_BITS/8),
  * que es el tamano maximo que puede tener un bloque cifrado (No puede ser mayor
  * que el tamano de la clave utilizada para encriptar). */
  fread(raw_aes_key, sizeof(unsigned char), RSA_KEY_BITS>>3, aes_stream);
  fclose(aes_stream);
  
  // Obtener la clave RSA (abrir stream)
  p_infoString("Recuperando la clave RSA privada", RSAkeyFile)
  if((rsa_stream = fopen(RSAkeyFile, "r")) == NULL) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("Error al abrir el archivo de la clave RSA")
    exit(EXIT_FAILURE);
  }

  /* Guardar en el objeto rsa_key la clave privada RSA recuperada con
  * @PEM_read_RSAPrivateKey.*/
  rsa_key = PEM_read_RSAPrivateKey(rsa_stream, NULL, NULL, NULL);
  fclose(rsa_stream);

  // Desencriptar la clave aes
  p_info("Desencriptando la clave AES");
  RSA_private_decrypt(RSA_KEY_BITS>>3, raw_aes_key, AESkey, rsa_key, RSA_PKCS1_PADDING);
  RSA_free(rsa_key);
  
  remove(RSAkeyFile);
  remove(AESkeyFile);
}