#pragma once
#include <stdlib.h>
#define SIG_HEADER_BYTES 256

///
/// Estas funciones se encargan de generar y verificar firmas 
/// generadas por este programa. La firma se hara sobre un 
/// buffer (que supuestamente sera la clave AES con la que se
/// encripto en archivo y un fragmento del archivo).
///
/// Para ello, definimos un nuevo archivo donde guardar 'nuestra
/// nueva firma', que contendra los siguientes campos:
/// 
/// +----------------------+
/// |       Cabecera       |
/// |      (256 bytes)     |
/// +----------------------+
/// | Longitud de la firma |
/// |    sizeof size_t     | 
/// +----------------------+
/// |         Firma        |
/// |      (256 bytes)     |
/// +----------------------+
/// |   Clave publica RSA  |
/// |   PEM ~(1704 bytes)  |
/// +----------------------+
///
/// Al igual que hacemos con la superclave, ponemos en primer lugar
/// una cabecera para distinguir entre archivos comunes y un archivo que
/// contiene una firma.
///

static const unsigned char SIGNATURE_HEADER[SIG_HEADER_BYTES] = {
  0xee, 0xfa, 0x02, 0xb5, 0x40, 0x2b, 0x1a, 0xb8,
  0x4e, 0x5b, 0x68, 0x2e, 0x2d, 0x13, 0xde, 0xd2,
  0xfc, 0xa7, 0x2c, 0xbf, 0x0b, 0x67, 0x00, 0x90,
  0x4d, 0x80, 0x0a, 0x47, 0xa5, 0x40, 0x38, 0x8c,
  0x2d, 0x80, 0x38, 0x4a, 0x1a, 0x0c, 0x33, 0xff,
  0x20, 0xb7, 0x44, 0xd1, 0xbb, 0xc0, 0xe8, 0x8f,
  0xaa, 0xfb, 0xd7, 0xee, 0xc1, 0x93, 0x82, 0x8f,
  0xe0, 0x06, 0x89, 0x20, 0x3b, 0x03, 0x4f, 0x0a,
  0x21, 0x58, 0x80, 0x21, 0xb9, 0x46, 0xe5, 0xce,
  0xd8, 0x25, 0x4d, 0xe4, 0xbc, 0x65, 0x66, 0x6a,
  0x90, 0xfd, 0x8d, 0xf2, 0x63, 0x81, 0x4a, 0x9a,
  0x1b, 0x62, 0xd8, 0x81, 0x11, 0x65, 0x18, 0xb5,
  0xd3, 0xf8, 0x8c, 0xb9, 0x80, 0x43, 0x22, 0x80,
  0x0e, 0x13, 0xd4, 0x0a, 0xad, 0x7d, 0x5b, 0x67,
  0x27, 0xae, 0x45, 0xbb, 0xe6, 0x1a, 0x94, 0xe7,
  0x7c, 0x16, 0xf8, 0xfe, 0x26, 0x9c, 0x0b, 0x7e,
  0x1d, 0xd0, 0x2c, 0x85, 0x87, 0xcf, 0x36, 0x98,
  0xe0, 0xfa, 0xe2, 0x47, 0xae, 0x1b, 0xa1, 0xa0,
  0xdd, 0xc8, 0xa2, 0xf0, 0x07, 0x1f, 0x54, 0x36,
  0xfc, 0xdf, 0x19, 0xcc, 0x7b, 0xde, 0x9f, 0xcf,
  0x3e, 0xfd, 0x8b, 0xbd, 0x27, 0x91, 0x78, 0x49,
  0x8c, 0xdc, 0x06, 0x78, 0xc7, 0xbe, 0xcc, 0xb8,
  0x18, 0x1a, 0x46, 0x21, 0x13, 0x03, 0x13, 0x39,
  0xd8, 0xa5, 0xb9, 0x0f, 0xf3, 0x95, 0x3e, 0xa7,
  0xc1, 0xc9, 0xe9, 0xe1, 0xd1, 0xbc, 0x91, 0xe1,
  0xce, 0xed, 0x11, 0x0a, 0x56, 0x7a, 0x58, 0x16,
  0xc6, 0x6a, 0x16, 0xe7, 0x76, 0xe0, 0xc7, 0x4e,
  0x16, 0xfd, 0xaf, 0x48, 0x5d, 0x7b, 0xad, 0x45,
  0xe7, 0x13, 0x7d, 0xd4, 0x86, 0xa0, 0x26, 0xe2,
  0x16, 0xf4, 0xe8, 0x93, 0xea, 0x1e, 0xb7, 0x15,
  0x91, 0xaf, 0x29, 0xc9, 0x44, 0x1e, 0xdc, 0x3c,
  0xf0, 0x57, 0xe4, 0xf6, 0x02, 0xad, 0xd6, 0xc3
};

enum { S_Valid, S_Error };

///
/// @brief Genera la firma de un buffer de datos.
///
/// @param m Buffer a firmar
/// @param m_len Longitud en bytes del buffer a firmar
/// @param path Ruta donde se guardara la firma.
///
int sign_buff(const unsigned char* m, size_t m_len, char* path);

///
/// @brief Comprueba si la firma digital almacenada corresponde 
/// con los datos de un buffer.
///
/// @param m Buffer a verificar
/// @param m_len Longitud en bytes del buffer a verificar
/// @param path Ruta donde se encuentra la firma.
///
int verify_buff_sign(const unsigned char* m, size_t m_len, char* path);
