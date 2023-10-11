#include <openssl/evp.h>
#include <openssl/aes.h>
#include "params.h"
#include "decryption.h"

void decryptFile(const char* inputFile, const char* outputFile, const unsigned char* key, const unsigned char* iv) {
  EVP_CIPHER_CTX* ctx; 
  unsigned char inBuf[DEC_CIPHER_SIZE];
  unsigned char outBuf[DEC_BUFF_SIZE];
  FILE* input;
  FILE* output;
  int bytesRead;
  int outLen;

  ctx = EVP_CIPHER_CTX_new();   
  EVP_DecryptInit_ex(ctx, AES_ALGORITHM, NULL, key, iv);
    
  /* Abrir el archivo a encriptar en modo lectura */
  if((input = fopen(inputFile, "rb")) == NULL){
    perror("Error while opening the input file.");
    exit(1);
  };

  /* Abrir el archivo de encriptado (destino) en 
   * modo escritura. */
  if((output = fopen(outputFile, "wb")) == NULL) {
    perror("Error while opening the output file.");
    exit(1);
  }
  
  /* Obtener DEC_CIPHER_SIZE bytes del archivo a encriptar, encriptarlos
   * y escribirlos en el archivo de encriptado destino. */
  while ((bytesRead = fread(inBuf, DEC_ELEMENT_BYTES, DEC_CIPHER_SIZE, input)) > 0) {
    EVP_DecryptUpdate(ctx, outBuf, &outLen, inBuf, bytesRead);
    fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  }
    
  /* Anadir relleno si es necesario */
  EVP_DecryptFinal_ex(ctx, outBuf, &outLen);
  fwrite(outBuf, DEC_ELEMENT_BYTES, outLen, output);
  
  /* Liberar */
  EVP_CIPHER_CTX_free(ctx);
  fclose(input);
  fclose(output);
}
