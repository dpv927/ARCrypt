## AES128

Este codigo corresponde a mi implementacion de AES128, el cual usa claves de 128 bits para cifrar bloques de informacion de 128 bits, al igual que las demas variaviones de AES (191,256).
Solo esta implementada la funcion de encriptacion, debido a que la desencriptacion es el mismo proceso pero en sentido contrario.

> [!WARNING]
> El codigo es una simple demostracion y no se debe utilizar para otros usos mas alla de la demostracion, ya que carece de un relleno o padding para las claves o para el bloque de datos,
> lo que podria suponer una amenaza de seguridad.

## Pruebas

No es que sea muy importante hacerle pruebas a este codigo ya que es simplemente un ejemplo, pero si estas interesado en saber si funciona correctamente, puedes compilar y correr el programa:
```bash
make && ./aes128
```

Los resultados esperados de las pruebas se encuentran en <a href="https://www.kavaliro.com/wp-content/uploads/2014/03/AES.pdf">este documento</a>.

## Debug
Puedes activar/desactivar el modo debug si cambias el valor del macro `DEBUG` de la linea 6 de `aes128.c`:
```c
#define DEBUG 1 /* Debug activado */
#define DEBUG 0 /* Debug desactivado */
```

Despues debes compilar el codigo:
```bash
make && ./aes128
```
