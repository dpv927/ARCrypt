#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "superkey.h"
#include "../utils/messages.h"



int write_superkey(const char* path, const struct SuperKey* skey) {
    FILE* file;
    if (!(file = fopen(path, "wb"))) {
        return SKError;
    }

    fwrite(SUPERKEY_HEADER, sizeof(u_char), HEADER_BYTES, file);
    fwrite(skey->aesk, sizeof(u_char), RSA_KEY_BYTES, file);
    fwrite(&(skey->rsak_pem_l), sizeof(size_t), 1, file);
    fwrite(skey->rsak_pem, sizeof(u_char), skey->rsak_pem_l, file);
    fwrite(skey->phash, sizeof(u_char), SHA2_BYTES, file);
    fclose(file);
    return SKValid;
}

int get_superkey(const char* path, struct SuperKey* skey) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return SKError; // Error al abrir el archivo
    }

    // Leer la cabecera y verificar que sea válida
    u_char header[HEADER_BYTES];
    fread(header, sizeof(u_char), HEADER_BYTES, file);
    if (memcmp(header, SUPERKEY_HEADER, HEADER_BYTES) != 0) {
        fclose(file);
        return SKError; // Cabecera no válida
    }

    // Leer los campos de la estructura SuperKey
    fread(skey->aesk, sizeof(u_char), RSA_KEY_BYTES, file);
    fread(&(skey->rsak_pem_l), sizeof(size_t), 1, file);

    // Reservar memoria para rsak_pem y leer el PEM de la clave privada RSA
    skey->rsak_pem = (u_char*)malloc(skey->rsak_pem_l);
    fread(skey->rsak_pem, sizeof(u_char), skey->rsak_pem_l, file);

    // Leer el hash de la contraseña
    fread(skey->phash, sizeof(u_char), SHA2_BYTES, file);

    fclose(file);
    return SKValid;
}