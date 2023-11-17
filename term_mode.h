#include <linux/limits.h>
#include <stdint.h>
#include "openSSL/params.h"

/* Modos de la aplicacion */
#define ENCRYPTION_MODE 0
#define DECRYPTION_MODE 1

/* Datos necesarios */
typedef struct {
  uint8_t mode;
  char file_path[PATH_MAX];
  char key_path[PATH_MAX];
  char passwd[AES_KEY_BYTES];
} OperationData;

/* @brief Inicia la aplicacion en modo terminal. 
* Solo salida grafica por consola. */
void init_term(void);

/* Obtiene el modo de operacion deseado por el usuario.
* @param OperationData Datos a obtener del usuario.
* * */
void getAppMode(OperationData* d);

/* Obtiene los datos necesarios para el modo seleccionado en la
* funcion @getAppMode.
* @param OperationData Datos a obtener del usuario.
* * */
void getModeData(OperationData* d);
