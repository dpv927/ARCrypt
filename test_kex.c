#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "kex.h"

/* Renombrar macros */
#define BYTES_CPUBLICA CRYPTO_PUBLICKEYBYTES  /* Bytes de la clave publica */
#define BYTES_CSECRETA CRYPTO_SECRETKEYBYTES  /* Bytes de la clave secreta */
#define BYTES_ENVIO_A  KEX_UAKE_SENDABYTES    /* Bytes de datos a enviar por Alice (Usuario1)*/
#define BYTES_ENVIO_B  KEX_UAKE_SENDBBYTES    /* Bytes de datos a enviar por Bob (Usuario2) */ 

/* Objeto usuario */
typedef struct {
  uint8_t clave_p[BYTES_CPUBLICA]; // Clave publica del usuario
  uint8_t clave_s[BYTES_CSECRETA]; // Clave secreta del usuario
} Usuario;

/* Objeto de para guardar datos del 
 * intercambio de claves entre Usuarios */
typedef struct {
  uint8_t datos_a[BYTES_ENVIO_A];   // Datos que va a enviar Alice (Usuario1)
  uint8_t datos_b[BYTES_ENVIO_B];   // Datos que va a enviar Bob (Usuario2)  
} Intercambio;

typedef struct {
  uint8_t compartida[KEX_SSBYTES];      // Clave compartida entre los usuarios
  uint8_t encriptada_a[BYTES_CSECRETA]; // Clave encriptada de Alice
} Claves;

int main(void) {
  
  /* Usuarios que van a intercambiar sus claves 
   * y van a mandar informacion entre si. */
  Usuario Alice;
  Usuario Bob;

  /* Objeto para almacenar los datos 
   * usados en el intercambio de claves */
  Intercambio IDatos;

  /* Objeto para almacenar las claves generadas
   * y usuadas durante el intercambio */
  Claves ClavesGen;

  /* Temporales */
  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  //uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];

  uint8_t zero[KEX_SSBYTES];
  for(int i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  // Generar las claves estaticas
  crypto_kem_keypair(Bob.clave_p, Bob.clave_s);     // Generar claves de Bob
  crypto_kem_keypair(Alice.clave_p, Alice.clave_s); // Generar claves de Alice

  /* -- Codigo para el intercambio de claves unilateral -- */
  // Alice inicia el intercambio
  kex_uake_initA(IDatos.datos_a, ClavesGen.compartida, ClavesGen.encriptada_a, Bob.clave_p);
  
  // Bob comparte su clave publica 
  kex_uake_sharedB(IDatos.datos_b, kb, IDatos.datos_a, Bob.clave_s); // Run by Bob
  kex_uake_sharedA(ka, IDatos.datos_b, ClavesGen.compartida, ClavesGen.encriptada_a); // Run by Alice
   
  if(memcmp(ka,kb,KEX_SSBYTES))
    printf("Error in UAKE\n");

  if(!memcmp(ka,zero,KEX_SSBYTES))
    printf("Error: UAKE produces zero key\n");

  // Perform mutually authenticated key exchange

  kex_ake_initA(ake_senda, ClavesGen.compartida, ClavesGen.encriptada_a, Bob.clave_p); // Run by Alice
  kex_ake_sharedB(ake_sendb, kb, ake_senda, Bob.clave_s, Alice.clave_p); // Run by Bob
  kex_ake_sharedA(ka, ake_sendb, ClavesGen.compartida, ClavesGen.encriptada_a, Alice.clave_s); // Run by Alice

  if(memcmp(ka,kb,KEX_SSBYTES))
    printf("Error in AKE\n");

  if(!memcmp(ka,zero,KEX_SSBYTES))
    printf("Error: AKE produces zero key\n");

  /*
  printf("KEX_UAKE_SENDABYTES: %d\n",KEX_UAKE_SENDABYTES);
  printf("KEX_UAKE_SENDBBYTES: %d\n",KEX_UAKE_SENDBBYTES);

  printf("KEX_AKE_SENDABYTES: %d\n",KEX_AKE_SENDABYTES);
  printf("KEX_AKE_SENDBBYTES: %d\n",KEX_AKE_SENDBBYTES);
  */
  return 0;
}
