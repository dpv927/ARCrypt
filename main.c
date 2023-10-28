#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openSSL/params.h"
#include "openSSL/encryption.h"
#include "openSSL/decryption.h"

/* Modos de la aplicacion */
#define ENCRYPTION_MODE 0
#define DECRYPTION_MODE 1

/* Datos necesarios */
typedef struct {
  uint8_t mode;
  char file_path[FILE_PATH_BYTES];
  char key_path[FILE_PATH_BYTES];
} OperationData;

/* Funciones de ontencion de datos */
void getAppMode(OperationData* d);
void getModeData(OperationData* d);

int main(void) {
  OperationData data;
  getAppMode(&data);
  getModeData(&data);
   
  switch (data.mode) {
    case ENCRYPTION_MODE:
      encryptFile(data.file_path, NULL);
      break;
    case DECRYPTION_MODE:
      decryptFile(data.file_path, data.key_path, NULL);
      break;
  }   
  return EXIT_SUCCESS;
}

void getAppMode(OperationData* d) {
  char input[100];
  char* endptr;
  int mode;
    
  printf("Elige el modo de operacion [0/1]: \n" \
    "0] Encriptar archivo\n1] Desencriptar archivo.\n>> ");
  scanf("%s", input);
  strtol(input, &endptr, 10);

  if(*endptr == '\0') {
    mode = atoi(input);
        
    if(mode != ENCRYPTION_MODE && mode != DECRYPTION_MODE) {
      printf("'%s': No es un modo valido!\n", input);
      exit(EXIT_FAILURE);
    }   
    d->mode = (uint8_t) mode;
  } else {
    printf("'%s': No es un modo valido!\n", input);
    exit(EXIT_FAILURE);
  }
}

void getModeData(OperationData* d) {
  char input[2048];

  switch (d->mode) {
    case ENCRYPTION_MODE:    
      printf("\nIntroduce la ruta del archivo a encriptar:\n"\
        ">> ");
      scanf("%s", input);
      strcpy(d->file_path, input);
      break;

    case DECRYPTION_MODE:
      printf("\nIntroduce la ruta del archivo a desencriptar:\n"\
        ">> ");
      scanf("%s", input);
      strcpy(d->file_path, input);
      printf("\nIntroduce la ruta de la clave:\n"\
        ">> ");
      scanf("%s", input);
      strcpy(d->key_path, input);
      break;
    }
}
