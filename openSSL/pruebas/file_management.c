#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define AES_KEY_BYTES 32
#define HEADER_BYTES  AES_KEY_BYTES
#define SHA_BYTES 32

enum { SKValid, SKError };
enum { FileNotExists, FileIsAFolder, FileNotReadPermission,
  DirNotReadPermission, DirNotWritePermission, FileIsGood };

static const char* FC_ERRORS[] = {
          [FileNotExists] = "La ruta no existe.",
          [FileIsAFolder] = "La ruta es una carpeta.",
  [FileNotReadPermission] = "No tienes permisos de lectura sobre el archivo.",
   [DirNotReadPermission] = "No tienes permisos de lectura sobre el directorio padre.",
  [DirNotWritePermission] = "No tienes permisos de escritura sobre el directorio padre."
};

static const unsigned char SUPERKEY_HEADER[32] = {
    0x23, 0x07, 0xe7, 0xc0, 0x3b, 0x5a, 0x11, 0xb1,
    0xc3, 0xf4, 0x4c, 0x39, 0x36, 0x11, 0x0c, 0x57,
    0x7e, 0x8c, 0x22, 0xb1, 0x28, 0x63, 0x90, 0x6f,
    0x4e, 0x42, 0xfe, 0x7c, 0xd7, 0xe6, 0xac, 0x34,
};

struct SuperKey {
  u_char* aesk;
  u_char* aes_iv;
  u_char* rsak_pem;
  size_t rsak_pem_l;
  u_char* phash;
};

int check_file(const char* path) 
{
  struct stat f_inode;
  struct stat d_inode;
  char* parent;

  /* Check file details */
  if(!stat(path, &f_inode)) {
    if((f_inode.st_mode & S_IFMT) == S_IFDIR)
      return FileIsAFolder; 
    if(!(f_inode.st_mode & S_IRUSR))
      return FileNotReadPermission;
  } else { return FileNotExists; }

  /* Check parent folder details */
  parent = malloc(strlen(path)+3);
  snprintf(parent, sizeof(parent), "%s/..", path);
  stat(parent, &d_inode);
  free(parent);
        
  if(!(d_inode.st_mode & S_IRUSR))
    return DirNotReadPermission;
  if(!(d_inode.st_mode & S_IWUSR))
    return DirNotWritePermission;
  return FileIsGood;
}

int write_superkey(const char* path, struct SuperKey* skey) 
{
  FILE* stream;
  if(!(stream = fopen(path, "wb"))) {
    printf("Error creating the SuperKey.");
    return SKError;
  }
  
  fwrite(SUPERKEY_HEADER, sizeof(u_char), HEADER_BYTES, stream);
  fwrite(skey->aesk, sizeof(u_char), AES_KEY_BYTES, stream);
  fwrite(skey->aes_iv, sizeof(u_char), AES_KEY_BYTES, stream);
  fwrite(&skey->rsak_pem_l, sizeof(size_t), 1, stream);
  fwrite(skey->phash, sizeof(u_char), SHA_BYTES, stream);
  fclose(stream);
  return SKValid;
}

int get_superkey(const char* path, struct SuperKey* skey) 
{
  FILE* stream;
  u_char buffer[HEADER_BYTES];
  int read;

  if(!(stream = fopen(path, "rb"))) {
    printf("Error reading the SuperKey.");
    return SKError;
  }
  
  // Check and read the file header
  fread(buffer, sizeof(u_char), HEADER_BYTES, stream);
  if(memcmp(SUPERKEY_HEADER, buffer, HEADER_BYTES)) {
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }

  // Recover the AES key
  read = fread(skey->aesk, sizeof(u_char), AES_KEY_BYTES, stream);
  if(read < AES_KEY_BYTES){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }
  
  // Recover the AES key IV 
  read = fread(skey->aes_iv, sizeof(u_char), AES_KEY_BYTES, stream);
  if(read < AES_KEY_BYTES){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }

  // Recover the RSA PEM length
  read = fread(&skey->rsak_pem_l, sizeof(size_t), 1, stream);
  if(read < sizeof(size_t)){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }
  
  // Recover the RSA private key PEM 
  skey->rsak_pem = malloc(skey->rsak_pem_l);
  if(skey->rsak_pem == NULL){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }

  read = fread(skey->rsak_pem, sizeof(u_char), skey->rsak_pem_l, stream);
  if(read < skey->rsak_pem_l){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }

  // Recover the password hash
  read = fread(skey->phash, sizeof(u_char), SHA_BYTES, stream);
  if(read < SHA_BYTES){
    printf("Not a valid SuperKey.");
    fclose(stream);
    return SKError;
  }
  fclose(stream);
  return SKValid;
}
