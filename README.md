# Biblioteca &lt;kex.h&gt;

## Introduccion
La bilioteca *kex* recibe su nombre por *key exchange*, debido a que implementa diferentes funciones que permiten la comunicacion e intercambio de claves entre dos partes de una comunicacion privadas.

Esta biblioteca hace referencia en sus notaciones a los nombres 'Alice' y 'Bob' como las dos partes que se quieren comunicar entre si, siendo Alice la que empieza el protocolo y Bob como el receptor de esa peticion. Esto es necesario tenerlo en cuenta debido a que algunas funciones incluyen las iniciales de estos nombres a varibles, parametros y funciones.

A la hora de realizar un intercambio de claves, el procedimiento se puede realizar de dos formas diferentes: con el protocolo UAKE o AKE. Los dos protocolos tienen usos bastante diferentes, pero no obstante, la implementacion a la hora de llamar a las funciones de la libreria son bastante parecidas.

<br>

## El protocolo UAKE

El protocolo UAKE (Unilaterally Authenticated Key Exchange) es un protocolo de intercambio de claves que se utiliza para establecer una clave compartida entre dos partes (Alice y Bob. La característica distintiva de UAKE es que proporciona autenticación unilateral, lo que significa que solo una de las partes, generalmente Alice, se autentica ante la otra parte, Bob, durante el proceso de intercambio de claves. Bob no necesita autenticarse ante Alice en este protocolo.

El propósito principal del protocolo UAKE es permitir a Alice y Bob acordar una clave compartida de manera segura y autenticar a Alice ante Bob. Esto puede ser útil en situaciones donde Alice necesita probar su identidad ante Bob, pero Bob no necesita demostrar su identidad a Alice. 

<div class="UAKE protocol scheme" align="center">
  <img src="https://github.com/dpv927/kayberc/assets/113710742/5df304b0-04ea-4494-8fcf-3be4ceb6a36f">
</div>

<br>

## El protocolo AKE

El protocolo AKE (Authenticated Key Exchange) es un protocolo criptográfico que permite a dos partes, generalmente llamadas Alice y Bob, establecer una clave compartida de manera segura y autenticarse mutuamente durante el proceso. A diferencia de los protocolos de intercambio de claves sin autenticación, como Diffie-Hellman, donde solo se acuerda una clave compartida, en AKE, ambas partes pueden verificar la identidad de la otra.

En resumen, el protocolo AKE consta de varias fases y operaciones, y su objetivo principal es garantizar que ambas partes obtengan la misma clave compartida y estén seguras de la identidad de la otra parte. 

<div class="UAKE protocol scheme" align="center">
  <img src="https://github.com/dpv927/kayberc/assets/113710742/cb24f03f-f98a-4e51-a57d-29b962eeb134">
</div>

<br>

## Constantes

### De la propia libreria 
- ``KEX_UAKE_SENDABYTES``: Maximo de bytes de datos a enviar por Alice en UAKE.
- ``KEX_UAKE_SENDBBYTES``: Maximo de bytes de datos a envia por Bob en UAKE.
- ``KEX_AKE_SENDABYTES``: Maximo de bytes de datos a enviar por Alice en AKE.
- ``KEX_AKE_SENDBBYTES``: Maximo de bytes de datos a envia por Bob en AKE.
- ``KEX_SSBYTES``: Numero de bytes de una clave secreta compartida.

### Referenciadas de &lt;kem.h&gt;
- ``CRYPTO_SECRETKEYBYTES``: Numero de bytes que componen una clave secreta.
- ``CRYPTO_PUBLICKEYBYTES``: Numero de bytes que componen una clave publica.
- ``CRYPTO_CIPHERTEXTBYTES``: Numero de bytes que componen un mensaje cifrado.

<br>

## Funciones

### Intercambio de claves unilateral (UAKE)

```c
void kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb);
```

Se utiliza para que 'Alice' inicie un proceso UAKE. Genera un par de claves: una publica que se guarda directamente en `send` y otra privada que se guarda en `sk`. Despues se encripta la clave temporal `tk` con la clave publica de Bob y se guarda tambien en `send`. Con ello obtenemos que en ``send[0]`` hasta ``send[CRYPTO_PUBLICKEYBYTES-1]``
se almacene la clave publica generada y desde `send[send+CRYPTO_PUBLICKEYBYTES]` la clave secreta temporal cifrada.

- `send`: Puntero/array contenedor de datos para enviar a Bob.
- `tk`: Clave temporal para encriptar `send`.
- `sk`: Clave secreta de Alice.
- `pkb`: Clave publica de Bob.

---

```c
void kex_uake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb);
```

Se utiliza para que 'Bob' complete el proceso UAKE despues de recibir los datos enviados por 'Alice'.

- `send`: Puntero/array contenedor de datos para enviar a Alice.
- `k`: Clave compartida entre Alice y Bob.
- `recv`: Puntero/array de datos enviado por 'Alice' en el inicio del proceso UAKE.
- `skb`: Clave secreta de Bob.

--- 

```c
void kex_uake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk);
```

Se utiliza para que 'Alice' complete el proceso UAKE despues de recibir los datos enviados por 'Bob'.

- `k`: Clave compartida entre Alice y Bob.
- `recv`: Puntero/array de datos enviado por 'Bob' en `kex_uake_sharedB`.
- `tk`: Clave secreta de Alice.
- `sk`: Clave secreta de Alice.

<!--
### Intercambio de claves bilateral (AKE)


```c
void kex_ake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb);
```
Se utiliza para que 'Alice' inicie un proceso AKE. 
- `send`: 
- `tk`: 
- `sk`:
- `pkb`:

---

```c
void kex_ake_sharedB(uint8_t *send, uint8_t *k, const uint8_t *recv, const uint8_t *skb, const uint8_t *pka);
```

Se utiliza para que 'Bob' complete el proceso UAKE despues de recibir los datos enviados por 'Alice'.
- `send`:
- `k`:
- `recv`:
- `skb`:
- `pka`:

--- 

```c
void kex_ake_sharedA(uint8_t *k, const uint8_t *recv, const uint8_t *tk, const uint8_t *sk, const uint8_t *ska);
```

Se utiliza para que 'Alice' complete el proceso UAKE despues de recibir los datos enviados por 'Bob'.
- `k`:
- `recv`:
- `tk`:
- `sk`:
- `ska`:
-->

## Ejemplos

### Intercambio de claves con UAKE

Este el siguiente codigo que se va a mostrar se puede encontrar en la ruta <a href="src/test_kex.c">src/test_kex.c</a> y se puede obtener 
en su version compilada (para ejecutar) tras correr el comando `make`:

```c
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
  uint8_t datos_a[BYTES_ENVIO_A]; // Datos que va a enviar Alice (Usuario1)
  uint8_t datos_b[BYTES_ENVIO_B]; // Datos que va a enviar Bob (Usuario2)  
} Intercambio;

typedef struct {
  /* Claves del proceso */
  uint8_t temporal[KEX_SSBYTES];     // Clave temporal para la derivacion de claves
  uint8_t encript_a[BYTES_CSECRETA]; // Clave de Alice para encriptar 'temporal'
  uint8_t alice[KEX_SSBYTES];        // Clave compartida de Alice (Obejetivo final)
  uint8_t bob[KEX_SSBYTES];          // Clave compartida de Bob (Objetivo final)
} Claves_Generadas;

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
  Claves_Generadas Claves;

  /* Literalmente un array con todo ceros para 
  * comprobar si las claves generadas son nulas.
  * Si las claves son nulas, evidentemente no son validas */ 
  uint8_t zero[KEX_SSBYTES];
  for(int i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;

  // Generar las claves estaticas
  crypto_kem_keypair(Bob.clave_p, Bob.clave_s);     // Generar claves de Bob
  crypto_kem_keypair(Alice.clave_p, Alice.clave_s); // Generar claves de Alice

  // --------------------------------------------------------- //
  // ---- Codigo para el intercambio de claves unilateral ---- //
  // --------------------------------------------------------- //

  // Alice inicia el intercambio
  /* Se generan un par de claves: una clave pubica que se almacena en 'datos_a' (send),
   * y una clave privada para Alice en 'encriptada_a' (sk). Ademas cifra la clave
   * 'temporal' (tk) con la clave publica de Bob. 
  *
  * Con ello, tenemos que send contenga tanto la clave publica de Alice como la 
  * clave secreta temporal cifrada esten almacenadas en 'datos_a' (send).
  *  */
  kex_uake_initA(IDatos.datos_a, Claves.temporal, Claves.encript_a, Bob.clave_p);
  
  // Bob completa su parte del proceso UAKE 
  /* El objetivo de esta llamada es descifrar los datos enviados por Alice 'datos_a' (recv),
   * cacular la clave compartida 'bob' (kb) (clave compartida de Bob) y proporcionar autenticacion
   * a Alice, ya que esta lo ha solicitado al iniciar el protocolo.
   *
   * Para ello, Bob utiliza su clave secreta 'clave_s' (sbk) y la clave publica de Alice (que se
   * encuentra en 'datos_a') para descifrar la clave 'temporal' (tk) que tambien se encontraba en 'datos_a'.  
   *
   * Por ultimo calcula la clave compartida secreta mediante los datos desencriptados del buffer
   * datos_a, consiguiendo asi autenticacion.
   * */
  kex_uake_sharedB(IDatos.datos_b, Claves.bob, IDatos.datos_a, Bob.clave_s);

  // Alice completa el proceso UAKE  
  /* Esta llamada se intentan descifrar los datos que ha enviado Bob en datos_b (recv) y calcular 
   * su clave compartida secreta 'alice' (ka).
   *
   * Para ello, va a desencriptar el buffer 'datos_b' enviado por Bob, haciendo uso de la clave
   * 'encript_a' y guardandolo en un buffer temporal. Tras ello, se copia la clave temporal (tk)
   * a la segunda mitad del buffer temporal (la primera parte ya esta ocupada con los datos desencriptados
   * anteriones).
   *
   * Finalmente se produce una derivacion de claves con las almacenadas en este buffer temporal obteniendo
   * asi la clave de alice.
   * */
  kex_uake_sharedA(Claves.alice, IDatos.datos_b, Claves.temporal, Claves.encript_a);
   
  // Comprobar si las claves son validas
  if(memcmp(Claves.alice, Claves.bob, KEX_SSBYTES))
    printf("Error in UAKE");

  if(!memcmp(Claves.alice, zero, KEX_SSBYTES))
    printf("Error: UAKE produces zero key");
  return 0;
}
```
