# Biblioteca &lt;kex.h&gt;

## Introduccion
La bilioteca *kex* recibe su nombre por *key exchange*, debido a que implementa diferentes funciones que permiten la comunicacion e intercambio de claves entre dos partes de una comunicacion privadas.

Esta biblioteca hace referencia en sus notaciones a los nombres 'Alice' y 'Bob' como las dos partes que se quieren comunicar entre si, siendo Alice la que empieza el protocolo y Bob como el receptor de esa peticion. Esto es necesario tenerlo en cuenta debido a que algunas funciones incluyen las iniciales de estos nombres a varibles, parametros y funciones.

A la hora de realizar un intercambio de claves, el procedimiento se puede realizar de dos formas diferentes: con el protocolo UAKE o AKE. Los dos protocolos tienen usos bastante diferentes, pero no obstante, la implementacion a la hora de llamar a las funciones de la libreria son bastante parecidas.

## El protocolo UAKE

El protocolo UAKE (Unilaterally Authenticated Key Exchange) es un protocolo de intercambio de claves que se utiliza para establecer una clave compartida entre dos partes (Alice y Bob. La característica distintiva de UAKE es que proporciona autenticación unilateral, lo que significa que solo una de las partes, generalmente Alice, se autentica ante la otra parte, Bob, durante el proceso de intercambio de claves. Bob no necesita autenticarse ante Alice en este protocolo.

El propósito principal del protocolo UAKE es permitir a Alice y Bob acordar una clave compartida de manera segura y autenticar a Alice ante Bob. Esto puede ser útil en situaciones donde Alice necesita probar su identidad ante Bob, pero Bob no necesita demostrar su identidad a Alice. 

## El protocolo AKE

El protocolo AKE (Authenticated Key Exchange) es un protocolo criptográfico que permite a dos partes, generalmente llamadas Alice y Bob, establecer una clave compartida de manera segura y autenticarse mutuamente durante el proceso. A diferencia de los protocolos de intercambio de claves sin autenticación, como Diffie-Hellman, donde solo se acuerda una clave compartida, en AKE, ambas partes pueden verificar la identidad de la otra.

En resumen, el protocolo AKE consta de varias fases y operaciones, y su objetivo principal es garantizar que ambas partes obtengan la misma clave compartida y estén seguras de la identidad de la otra parte. 

## Funciones

### Intercambio de claves unilateral

```c
void kex_uake_initA(uint8_t *send, uint8_t *tk, uint8_t *sk, const uint8_t *pkb);
```

Se utiliza para que 'Alice' inicie un proceso UAKE. 
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
- `sk`: Clave secreta de Alice

### Intercambio de claves bilateral
