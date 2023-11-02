#include <stdint.h>
#include "openSSL/params.h"

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
void init_term(void);
void getAppMode(OperationData* d);
void getModeData(OperationData* d);
