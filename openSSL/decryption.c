#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "files.h"
#include "params.h"
#include "iv_kdf.h"
#include "superkey.h"
#include "decryption.h"
#include "../utils/messages.h"

void decryptFile(const char* inputFile, const char* passwd,
  const char* keyFile) 
{
  /* Todas las claves utilizadas */
  struct SuperKey superkey;
  u_char phash[SHA2_BYTES];
  u_char usr_iv[AES_IV_BYTES];
  u_char aes[AES_KEY_BYTES];
  int rsa_len;

  // Otros buffers y datos
  u_char inBuf[DEC_BUFF_SIZE];
  u_char outBuf[DEC_CIPHER_SIZE];
  char outputFile[FILE_PATH_BYTES+4];
  EVP_CIPHER_CTX* ctx;
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;
  
  /*  Comprobar si el archivo existe y si es asi, ver si
   *  el usuario tiene permisos de escritura y lectura
   *  sobre el directorio padre y el archivo. */
  int val = check_file(inputFile);
  if(val != FileIsGood) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error(FC_ERRORS[val])
    exit(EXIT_FAILURE);
  }

  // TODO Comprobar Hash de la superclave?
  // // // 

  // Recuperar del archivo de la clave la superclave, 
  // de forma que obtenemos todas las claves protegidas y 
  // el hash de la contrasenacon la que se encripto el archivo.
  p_info("Recuperando la superclave")
  val = get_superkey(keyFile, &superkey);
  if(val == SKError) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    if(!superkey.rsa) 
      free(superkey.rsa);
    exit(EXIT_FAILURE);
  }

  // Calcular el hash de la contrasena que se ha pasado
  // y comprobar si es la que se utilizo para encriptar el archivo.
  p_info("Comprobando si la contrasena es correcta.")
  calculateHash((const u_char*) passwd, AES_KEY_BYTES, phash);
  if(memcmp(superkey.phash, phash, SHA2_BYTES)){
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("La contrasena es incorrecta.");
    free(superkey.rsa);
    exit(EXIT_FAILURE);
  }

  // Desencriptar la clave RSA con AES.
  // Antes que nada hay que generar el IV pertinente mediante la derivacion
  // de la clave AES (contrasena que el usuario eligio).
  p_info("Desencriptando la clave RSA con AES")
  derive_AES_key((u_char*) passwd, usr_iv);
  
  u_char rsa_key[superkey.rsa_len+128];
  rsa_len = decryptRSAKey_withAES(
    superkey.rsa,
    rsa_key,
    superkey.rsa_len,
    (u_char*) passwd,
    usr_iv
  );

  if(rsa_len == -1) {
    #ifdef GTK_GUI
    create_error_dialog();
    #endif
    p_error("No se pudo desencriptar la clave RSA con AES")
    free(superkey.rsa);
    exit(EXIT_FAILURE);
  } else superkey.rsa_len = val;
  free(superkey.rsa);

  // Desencriptar la clave AES y su IV con RSA
  p_info("Desencriptando la clave AES con RSA")
  decryptAESKey_withRSA(
    superkey.aes,
    aes,
    rsa_key,
    rsa_len
  );

  //u_char pepe[RSA_KEY_BYTES];
  //decryptAESIV_withRSA(
  //  pepe,
  //  aesk_iv,
  //  rsa_key,
  //  rsa_len
  //);

  /// ----------------------------------------- ///
  /// MOSTRAR LA CLAVE AES Y IV DESENCRIPTADAS  ///
  /// ----------------------------------------- ///

  printf("Clave AES desencriptada: \n");
  for (int i = 0, j = 1; i<AES_KEY_BYTES; i++, j++){
    printf("%02x ", aes[i]);
    if(j%16==0) printf("\n");
  }
  printf("\n\n");

  /// ----------------------------------------- ///
  /// MOSTRAR LA CLAVE AES Y IV DESENCRIPTADAS  ///
  /// ----------------------------------------- ///

  // Desencriptar el archivo
  // Iniciar contexto de desencriptacion.
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, aes, NULL);
    
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
  while ((bytesRead = fread(inBuf, sizeof(u_char), DEC_CIPHER_SIZE, input)) > 0) {
    EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, sizeof(u_char), outLen, output);
  }
  
  /* Quitar relleno si es necesario */
  EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, sizeof(u_char), outLen, output);
  
  /* Liberar memoria y streams */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);

  /* Sustituir */
  remove(inputFile);
  rename(outputFile, inputFile);
}

int decryptRSAKey_withAES(const u_char* cipher_rsa_key, u_char* rsa_key, const size_t rsa_len, 
  const u_char aes_key[AES_KEY_BYTES], const u_char aes_key_iv[AES_IV_BYTES]) 
{
  EVP_CIPHER_CTX *ctx;
  int plaintext_len;
  int len;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, aes_key, aes_key_iv);
  EVP_DecryptUpdate(ctx, rsa_key, &len, cipher_rsa_key, rsa_len);
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx, rsa_key+len, &len);
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

void decryptAESKey_withRSA(const unsigned char* cipher_aes_key, 
  unsigned char* aes_key, unsigned char* rsa_skey, size_t rsa_keylen)
{
  EVP_PKEY* evp_rsa_key = NULL;
  EVP_PKEY_CTX* ctx;
  BIO* rsa_bio;
  size_t outlen;

  // Read RSA private key from mem
  rsa_bio = BIO_new(BIO_s_mem());
  BIO_write(rsa_bio, rsa_skey, rsa_keylen);
  evp_rsa_key = PEM_read_bio_PrivateKey_ex(rsa_bio, NULL, NULL, NULL, NULL, NULL);
  BIO_free(rsa_bio); 
  
  // Decrypt AES key with RSA 
  ctx = EVP_PKEY_CTX_new(evp_rsa_key, NULL);
  EVP_PKEY_decrypt_init(ctx);
  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
  EVP_PKEY_decrypt(ctx, aes_key, &outlen, cipher_aes_key, RSA_KEY_BYTES);

  // Free all that stuff!
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(evp_rsa_key);
}
