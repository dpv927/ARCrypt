#pragma once

#include "superkey.h"

enum { FileNotExists, FileIsAFolder, FileNotReadPermission,
  DirNotReadPermission, DirNotWritePermission, FileIsGood };

static const char* FC_ERRORS[] = {
          [FileNotExists] = "La ruta no existe.",
          [FileIsAFolder] = "La ruta es una carpeta.",
  [FileNotReadPermission] = "No tienes permisos de lectura sobre el archivo.",
   [DirNotReadPermission] = "No tienes permisos de lectura sobre el directorio padre.",
  [DirNotWritePermission] = "No tienes permisos de escritura sobre el directorio padre."
};

/// 
/// @brief Comprueba propiedades basicas de manipulacion de archivos.
/// En primer lugar, prueba que el archivo exista, que no sea una carpeta,
/// que el usuario tenga permisos de lectura sobre el archivo y que tenga
/// permisos de lectura y escritura en el directorio contenedor.
///
/// @param path Ruta del archivo a comprobar
/// @return Codigo de comprobacion. Si la operacion es correcta, se debe devolver
/// FileIsGood (5).
///
int check_file(const char* path);
