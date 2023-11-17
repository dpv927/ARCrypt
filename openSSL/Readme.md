# Encriptacion de archivos con AES (OpenSSL)

## Informacion

En este directorio encontrarás una implementación de un algoritmo capaz de encriptar y desencriptar archivos utilizando el algoritmo de cifrado AES de clave simétrica implementado en las bibliotecas de OpenSSL.

<br>

## Pruebas por defecto

Para probar el programa, debes compilarlo y ejecutarlo de la siguiente manera:
```c
make && ./aes
```
> [!NOTE]
> El ejecutable generado se llamará "aes". Este programa puede encriptar y desencriptar el archivo de texto "testfile.txt",
> el cual se encuentra en el mismo directorio de las pruebas, generando "key.txt" y el propio "testfile.txt" modifocado.

<br>

## Pruebas personalizadas

Para encriptar archivos personalizados, debes modificar las definiciones de los macros que se encuentran en la siguiente sección de "main.c":
```c
#define processed_file  "testfile.txt"
#define key_file        "encrypted.txt" # No modificar! 
```

El significado de los archivo generados es:
- **processed_file**: Archivo a encriptar.
- **key_file**: Archivo donde se va a guardar la clave generada.

> [!NOTE]
> Se recomienda encriptar y desencriptar imágenes de cualquier tipo para comprobar que el resultado de la desencriptación sea satisfactorio. Esto se debe a que incluso un cambio mínimo en el binario de una imagen puede corromperla y esto es fácil de comprobar.

<br>

## Pruebas con archivos grandes

Esta prueba se recomienda debido a problemas potenciales de manejo de archivos de gran tamaño que ocurrieron en las primeras versiones de la implementación del programa. En un principio, ningún archivo, sin importar su tamaño, debería generar errores al encriptar o desencriptar. Sin embargo, en las primeras versiones, se encontraron problemas de acceso a la memoria al procesar archivos de gran tamaño.

Para comprobar que efectivamente no hay errores, ejecuta los siguientes comandos para borrar el archivo "testfile.txt" y generar una versión de este mucho más pesada:
```bash
rm testfile.txt
fallocate -l 50M testfile.txt
```

> [!NOTE]
> Este comando generará el archivo "testfile.txt" con un peso de 50Mb.
