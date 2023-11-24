#include <linux/limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "term_mode.h"
#include "utils/messages.h"
#include "openSSL/encryption.h"
#include "openSSL/decryption.h"

void init_term(void) {
  OperationData data;

  /* Mostrar el logo */
  system("clear");
  FILE* ptr = fopen("extra/logo.txt", "r");
  if(ptr == NULL)
    p_error("No se encuentra el archivo de inicio.");
  char buff[100];

  while (fgets(buff, sizeof(buff), ptr) != NULL)
    printf("\033[1m%s", buff);
  printf("\033[0m\n");
  fclose(ptr);

  /* Obtener el modo */
  getAppMode(&data);
  getModeData(&data);

  switch (data.mode) {
    case ENCRYPTION_MODE:
      encryptFile(
        data.file_path,
        data.passwd
      );
      break;
    case DECRYPTION_MODE:
      decryptFile(
        data.file_path,
        data.passwd,
        data.key_path,
        data.sig_path,
        data.sig
      );
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
  char* endptr;
  char input[PATH_MAX];
  int mode;

  switch (d->mode) {
    case ENCRYPTION_MODE:    
      next_line()
      print_title("Encriptacion")
      user_input("Ruta del archivo a encriptar", "%s", input)
      strcpy(d->file_path, input);

      user_input("Password", "%s", input)
      strcpy(d->passwd, input);
      next_line()
      
    break;

    case DECRYPTION_MODE:
      next_line()
      print_title("Desencriptacion")
      user_input("Ruta del archivo a desencriptar", "%s", d->file_path)
      user_input("Ruta de la clave", "%s", d->key_path)
      user_input("Password", "%s", d->passwd)
      next_line()

      print_title("Firma Digital")
      print_option(0, "Verificar con firma")
      print_option(1, "No verificar")
      user_input("Elige una opcion valida", "%s", input);
      strtol(input, &endptr, 10);

      if(*endptr == '\0') {
        mode = atoi(input);
        
        if(mode != 0 && mode != 1) {
          printf("\nError: '%s': No es una opcion valida!\n", input);
          exit(EXIT_FAILURE);
        }   
        d->sig = (uint8_t) mode;
      } else {
        printf("\nError: '%s': No es una opcion valida!\n", input);
        exit(EXIT_FAILURE);
      }

      if(!mode) { /* Generar certificado */ 
        user_input("Ruta de la firma", "%s", d->sig_path);
      }
      break;
    }
}
