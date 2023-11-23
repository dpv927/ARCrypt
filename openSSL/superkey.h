#pragma once

#include <stdlib.h>
#include "params.h"
#define HEADER_BYTES 256

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
/// |            256 bytes            | 
/// +--------------------------------+ 
/// |    AES Key encriptada con RSA  | 
/// |            256 bytes           | 
/// +--------------------------------+
/// |      Longitud del RSA PEM      | 
/// |         (sizeof size_t)        |
/// +--------------------------------+ 
/// |      Longitud del RSA PEM      |
///     encriptado (sizeof size_t)  | 
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
  /// @brief rsa_len: Longitud en bytes del PEM de la clave
  /// privada RSA encriptada.
  ///
  size_t cipher_rsa_len;

  ///
  /// @brief phash: Buffer de longitud SHA2_BYTES que contiene 
  /// el hash de la contraseña que se ha utilizado para encriptar 
  /// la clave privada RSA @rsak_pem.
  ///
  u_char phash[SHA2_BYTES];
};

static const u_char SUPERKEY_HEADER[HEADER_BYTES] = {
  0xfc, 0xd4, 0x92, 0x06, 0x62, 0x31, 0x94, 0xab,
  0x1c, 0x05, 0x89, 0x8f, 0xcc, 0x16, 0x9e, 0x82,
  0x01, 0x2a, 0x03, 0x0d, 0x2a, 0x1d, 0x32, 0x9f,
  0x04, 0x0b, 0xaf, 0xf5, 0xdc, 0x13, 0x30, 0x23,
  0x73, 0xe1, 0xd7, 0xc2, 0xb9, 0xab, 0xa0, 0x32,
  0x27, 0x1c, 0xa1, 0xda, 0x25, 0x68, 0x1b, 0x64,
  0xe7, 0x7c, 0xf0, 0xcf, 0x76, 0x06, 0x71, 0xcb,
  0xaf, 0x9b, 0x3e, 0x08, 0xac, 0x48, 0x10, 0x1d,
  0x75, 0x55, 0xfd, 0x6a, 0x5a, 0x2d, 0xa7, 0xb1,
  0xdd, 0x49, 0x5b, 0x20, 0xbc, 0x3d, 0x9d, 0x22,
  0xbd, 0x78, 0xc5, 0x49, 0x8c, 0x7b, 0xcb, 0x8e,
  0x44, 0x86, 0x3e, 0x3f, 0x45, 0xee, 0xf3, 0xc9,
  0x88, 0x1f, 0x0c, 0x93, 0xc1, 0x28, 0x6c, 0x9c,
  0x79, 0x30, 0x48, 0xc5, 0xc0, 0x83, 0xb8, 0x6e,
  0x27, 0x8f, 0xa7, 0xc5, 0x05, 0x8c, 0x89, 0x63,
  0x44, 0x74, 0xea, 0x1e, 0x3f, 0x5f, 0x19, 0x75,
  0xaf, 0x86, 0x43, 0x49, 0x1a, 0x91, 0x98, 0x42,
  0xe4, 0x6c, 0x1e, 0x07, 0x50, 0xad, 0x72, 0x48,
  0xad, 0x25, 0x37, 0x2f, 0x5d, 0xcc, 0x04, 0x6f,
  0xc6, 0xfa, 0x71, 0xcb, 0xc1, 0xa8, 0x69, 0xd1,
  0x04, 0x06, 0xf6, 0xe6, 0x21, 0xab, 0xe8, 0xef,
  0x79, 0x26, 0x62, 0xa4, 0x9e, 0x5a, 0x94, 0x22,
  0xd4, 0x5c, 0x5c, 0x85, 0xb6, 0x41, 0x40, 0xa5,
  0xc1, 0x10, 0x8a, 0x92, 0xc1, 0xad, 0x4c, 0x67,
  0x95, 0xf7, 0x64, 0x5c, 0x46, 0xef, 0x53, 0xc1,
  0x27, 0x21, 0xf0, 0xb5, 0xdb, 0x45, 0x3a, 0x33,
  0xe0, 0xbd, 0x53, 0x8a, 0x0b, 0xe3, 0xf9, 0x67,
  0xdf, 0x97, 0x2a, 0x1d, 0xf2, 0x62, 0x4f, 0x37,
  0x72, 0x85, 0xe1, 0xe0, 0x0a, 0x3a, 0x2c, 0x57,
  0x4e, 0xba, 0x19, 0x7e, 0x47, 0x3c, 0xf7, 0x9b,
  0x82, 0xb9, 0xcb, 0xf1, 0x2f, 0x22, 0x24, 0x45,
  0x7b, 0x71, 0xfd, 0x31, 0x6c, 0x59, 0xac, 0xfd
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

