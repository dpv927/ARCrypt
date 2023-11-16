#pragma once

#include <stdlib.h>
#include "params.h"
#define HEADER_BYTES 32

///
/// Estructura de una SuperKey (Clave de claves):
///
/// La idea es guardar en un mismo archivo todas las
/// claves utilizadas durante el proceso de encriptacion
/// (al menos las necesarias) protegidas para no tener
/// multiples archivos dispersos por el sistema.
///
/// Ademas de las claves, al principio del archivo se
/// pone una cabecera preestablecida (es la misma para todas
/// los archivos de superclaves) que ha sido generada 
/// con bytes aleatorios.
///
/// La idea de la cabecera es tener los primeros 32 bytes 
/// (256 bits) del archivo aleatorios, de forma que sea
/// casi imposible que los primeros 32 bytes de un archivo
/// regular sean exactamente bit a bit iguales que el de
/// una superclave.
///
/// Al tener 256 bits de cabecera, aprobechamos que hay 2^256
/// posibles combinaciones para el comienzo de un archivo, de
/// forma que la probabilidad de que un archivo tenga la misma
/// cabecera que una superclave es de
/// 8.6361685550944446253863518628003995711160003644362813850237 × 10^-78
///  
/// Suponiendo que RSA_KEY_BYTES=256, HEADER_BYTES=32, SHA2_BYTES=32
/// (siendo el tamano de la clave RSA de 2048 bits y un SHA de 256 bits),
/// tendriamos el siguiente esquema para una superclave:
/// 
/// +--------------------------------+ 
/// |    Cabecera (Preestablecida)   | 
/// |            32 bytes            | 
/// +--------------------------------+ 
/// |    AES Key encriptada con RSA  | 
/// |            256 bytes           | 
/// +--------------------------------+ 
/// |      Longitud del RSA PEM      | 
/// |         (sizeof size_t)        | 
/// +--------------------------------+
/// |     PEM de RSA private key     |
/// |       encriptada con AES       |
/// |  (La clave AES de esta es una  |
/// |    contrasena del usuario)     |
/// |          ~1704 bytes           |
/// +--------------------------------+
/// |      Hash de la contrasena     |
/// |            32 bytes            |
/// +--------------------------------+
/// 
/// Tener en cuenta que el campo PEM de RSA no es realmente la clave privada RSA
/// en plano, sino la clave con un formato especifico que OpenSSL genera para luego
/// poder recuperarla, por eso no sabemos exactamente el tamano.
///

struct SuperKey {
  ///
  /// @brief aes: Clave AES utilizada para encriptar
  /// el archivo objetivo. Al final del proceso debe
  /// estar encriptada con una clave publica RSA. 
  /// 
  /// La clave en texto plano se almacenará en otro buffer
  /// de longitud AES_KEY_BYTES, hasta que se encripte
  /// con RSA y se guarde en este campo con una longitud
  /// máxima de RSA_KEY_BYTES.
  ///
  u_char aes[RSA_KEY_BYTES];
  
  ///
  /// @brief rsa: Buffer que contiene el PEM de la clave
  /// privada RSA con la que se deberá posteriormente desencriptar
  /// la clave AES @aesk y su IV @aes_iv. Dependiendo del punto
  /// del programa, puede que este encriptada con AES o
  /// en texto plano.
  ///
  u_char* rsa;
  
  ///
  /// @brief rsa_len: Longitud en bytes del PEM de la clave
  /// privada RSA.
  ///
  size_t rsa_len;

  ///
  /// @brief phash: Buffer de longitud SHA2_BYTES que contiene 
  /// el hash de la contraseña que se ha utilizado para encriptar 
  /// la clave privada RSA @rsak_pem.
  ///
  u_char phash[SHA2_BYTES];
};

static const u_char SUPERKEY_HEADER[HEADER_BYTES] = {
  0x23, 0x07, 0xe7, 0xc0, 0x3b, 0x5a, 0x11, 0xb1,
  0xc3, 0xf4, 0x4c, 0x39, 0x36, 0x11, 0x0c, 0x57,
  0x7e, 0x8c, 0x22, 0xb1, 0x28, 0x63, 0x90, 0x6f,
  0x4e, 0x42, 0xfe, 0x7c, 0xd7, 0xe6, 0xac, 0x34,
};

enum { SKValid, SKError };

///
/// @brief Escribe en un archivo una superclave, tal y como se indica en el esquema
/// que se explica en este archivo.
///
/// @param path Ruta del archivo donde se va a guardar la superclave.
/// @param skey Superclave.
/// @return Entero el cual se puede usar como código de error.
///
int write_superkey(const char* path, const struct SuperKey* skey); 

///
/// @brief Lee de un archivo una superclave, tal y como se indica en el esquema
/// que se explica en este archivo.
///
/// @param path Ruta del archivo donde está almacenada la superclave.
/// @param skey Objeto de Superclave donde se va a guardar la información obtenida.
/// @return Entero el cual se puede usar como código de error.
///
int get_superkey(const char* path, struct SuperKey* skey);

