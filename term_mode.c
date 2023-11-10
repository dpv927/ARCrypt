#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "term_mode.h"
#include "utils/messages.h"
#include "openSSL/encryption.h"
#include "openSSL/decryption.h"

void init_term(void) {
  OperationData data;

  /* Mostar el logo */
  system("clear");
  FILE* ptr = fopen("extra/logo.txt", "r");
  if(ptr == NULL) {
    perror("No se encuentra el archivo de inicio.");
  }
  char buff[100];

  while (fgets(buff, sizeof(buff), ptr) != NULL)
    printf("%s", buff);
  printf("\n");
  fclose(ptr);

  /* Obtener el modo */
  getAppMode(&data);
  getModeData(&data);
   
  switch (data.mode) {
    case ENCRYPTION_MODE:
      encryptFile_withAES(data.file_path);
      break;
    case DECRYPTION_MODE:
      decryptFile_withAES(data.file_path, data.key_path);
      break;
  }
}

void getAppMode(OperationData* d) {
  char input[100];
  char* endptr;
  int mode;
  
  print_title("Modos")
  print_option(0, "Encriptar archivo")
  print_option(1, "Desencriptar archivo")
  user_input("Elige un modo valido", "%s", input);
  strtol(input, &endptr, 10);

  if(*endptr == '\0') {
    mode = atoi(input);
        
    if(mode != ENCRYPTION_MODE && mode != DECRYPTION_MODE) {
      printf("\nError: '%s': No es un modo valido!\n", input);
      exit(EXIT_FAILURE);
    }   
    d->mode = (uint8_t) mode;
  } else {
    printf("\nError: '%s': No es un modo valido!\n", input);
    exit(EXIT_FAILURE);
  }
}

void getModeData(OperationData* d) {
  char input[2048];

  switch (d->mode) {
    case ENCRYPTION_MODE:    
      next_line()
      print_title("Encriptacion")
      user_input("Ruta del archivo a encriptar", "%s", input)
      next_line()

      strcpy(d->file_path, input);
      break;

    case DECRYPTION_MODE:
      next_line()
      print_title("Desencriptacion")
      user_input("Ruta del archivo a desencriptar", "%s", input)
      strcpy(d->file_path, input);

      user_input("Ruta de la clave", "%s", input)
      strcpy(d->key_path, input);
      next_line()
      break;
    }
}
