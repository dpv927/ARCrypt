#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "superkey.h"
#include "../utils/messages.h"

int write_superkey(const char* path, const struct SuperKey* skey) 
{
  FILE* stream;
  if(!(stream = fopen(path, "wb"))) {
    p_error("Error creating the SuperKey.");
    return SKError;
  }
  
  fwrite(SUPERKEY_HEADER, sizeof(u_char), HEADER_BYTES, stream);
  fwrite(skey->aesk, sizeof(u_char), AES_KEY_BYTES, stream);
  fwrite(skey->aes_iv, sizeof(u_char), AES_KEY_BYTES, stream);
  fwrite(&skey->rsak_pem_l, sizeof(size_t), 1, stream);
  fwrite(&skey->rsak_pem, sizeof(u_char), skey->rsak_pem_l, stream);
  fwrite(skey->phash, sizeof(u_char), SHA2_BYTES, stream);
  fclose(stream);
  return SKValid;
}

int get_superkey(const char* path, struct SuperKey* skey) 
{
  FILE* stream;
  u_char buffer[HEADER_BYTES];
  int read;
  
  if(!(stream = fopen(path, "rb"))) {
    p_error("Error reading the SuperKey (stream).");
    return SKError;
  }
  
  // Check and read the file header
  fread(buffer, sizeof(u_char), HEADER_BYTES, stream);
  
  if(memcmp(SUPERKEY_HEADER, buffer, HEADER_BYTES)) {
    p_error("La clave no es valida: Falso encabezado.");
    fclose(stream);
    return SKError;
  }

  // Recover the AES key
  read = fread(skey->aesk, sizeof(u_char), AES_KEY_BYTES, stream);
  if(read < AES_KEY_BYTES){
    p_error("La clave no es valida: No se encuentra la clave AES");
    fclose(stream);
    return SKError;
  }
  
  // Recover the AES key IV 
  read = fread(skey->aes_iv, sizeof(u_char), AES_KEY_BYTES, stream);
  if(read < AES_KEY_BYTES){
    p_error("La clave no es valida: No se encuentra el IV de la clave AES");
    fclose(stream);
    return SKError;
  }

  // Recover the RSA PEM length
  read = fread(&skey->rsak_pem_l, sizeof(size_t), 1, stream);
  if(read < 1){
    p_error("La clave no es valida: No se encuentra la longitud RSA");
    fclose(stream);
    return SKError;
  }

  // Recover the RSA private key PEM 
  skey->rsak_pem = malloc(skey->rsak_pem_l);
  if(skey->rsak_pem == NULL){
    p_error("No se pudo reservar la memoria suficiente para la clave RSA.");
    fclose(stream);
    return SKError;
  }

  read = fread(skey->rsak_pem, sizeof(u_char), skey->rsak_pem_l, stream);
  if(read < skey->rsak_pem_l){
    p_error("La clave no es valida: No se encuentra la clave RSA");
    fclose(stream);
    return SKError;
  }

  // Recover the password hash
  read = fread(skey->phash, sizeof(u_char), SHA2_BYTES, stream);
  if(read < SHA2_BYTES){
    p_error("La clave no es valida: No se encuentra el hash de la contrasena");
    fclose(stream);
    return SKError;
  }
  fclose(stream);
  return SKValid;
}
