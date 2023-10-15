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
> El ejecutable generado se llamará "aes". Este programa encriptará y desencriptará el archivo de texto "testfile.txt", el cual se encuentra en el mismo directorio de las pruebas, generando los archivos "encrypted.txt" y "decrypted.txt".

<br>

## Pruebas personalizadas

Para encriptar archivos personalizados, debes modificar las definiciones de los macros que se encuentran en la siguiente sección de "main.c":
```c
#define processed_file  "testfile.txt"
#define encrypted_file  "encrypted.txt" 
#define decrypted_file  "decrypted.txt"
```

El significado de los archivos generados es:
- **processed_file**: Archivo a encriptar.
- **encrypted_file**: Archivo con el contenido encriptado de 'processed_file'.
- **decrypted_file**: Archivo con el contenido desencriptado de 'encrypted_file'.

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
