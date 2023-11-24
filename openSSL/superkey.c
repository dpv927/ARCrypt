 #include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "superkey.h"
#include "../utils/messages.h"

int write_superkey(const char* path, const struct SuperKey* skey) {
    FILE* file;
    int write_bytes;

    if (!(file = fopen(path, "wb"))) {
        p_error("No se pudo crear el archivo de la superclave")
        return SKError;
    }
    
    // Escribir la cabecera de la superclave
    write_bytes = fwrite(SUPERKEY_HEADER, sizeof(u_char), HEADER_BYTES, file);
    if (write_bytes < HEADER_BYTES) {
        p_error("No se pudo escribir la cabecera.")
        return SKError;
    }

    // Escribir la clave AES encriptada
    write_bytes = fwrite(skey->aes, sizeof(u_char), RSA_KEY_BYTES, file);
    if (write_bytes < RSA_KEY_BYTES) {
        p_error("No se pudo escribir la clave AES.")
        return SKError;
    }

    // Escribir la longitud del PEM de la clave privada RSA
    write_bytes = fwrite(&(skey->rsa_len), sizeof(size_t), 1, file);
    if (write_bytes < 1) {
        p_error("No se pudo escribir la longitud de RSA.")
        return SKError;
    }

    // Escribir la longitud del PEM encriptado de la clave privada RSA
    write_bytes = fwrite(&(skey->cipher_rsa_len), sizeof(size_t), 1, file);
    if (write_bytes < 1) {
        p_error("No se pudo escribir la longitud de RSA encriptado.")
        return SKError;
    }

    // Escribir el PEM de la clave privada RSA
    write_bytes = fwrite(skey->rsa, sizeof(u_char), skey->cipher_rsa_len, file);
    if (write_bytes < skey->cipher_rsa_len) {
        p_error("No se pudo escribir la clave RSA.")
        return SKError;
    }

    // Escribir el hash de la contrasena del usuario
    write_bytes = fwrite(skey->phash, sizeof(u_char), SHA2_BYTES, file);
    if (write_bytes < SHA2_BYTES) {
        p_error("No se pudo escribir el hash del passwd.")
        return SKError;
    }

    fclose(file);
    return SKValid;
}

int get_superkey(const char* path, struct SuperKey* skey) {
    FILE* file;
    int read_bytes;
    u_char buffer[HEADER_BYTES];

    if (!(file = fopen(path, "rb"))) {
        p_error("No se pudo abrir el archivo de la superclave")
        return SKError;
    }

    // Leer la cabecera y verificar que sea válida
    read_bytes = fread(buffer, sizeof(u_char), HEADER_BYTES, file);
    if (read_bytes < HEADER_BYTES || memcmp(buffer, SUPERKEY_HEADER, HEADER_BYTES) != 0) {
        p_error("No es una superclave: La cabecera no coincide")
        fclose(file);
        return SKError;
    }

    // Leer la clave AES encriptada
    read_bytes = fread(skey->aes, sizeof(u_char), RSA_KEY_BYTES, file);
    if (read_bytes < RSA_KEY_BYTES) {
        p_error("No es una superclave: No contiene una clave AES")
        fclose(file);
        return SKError;
    }

    // Leer la longitud del PEM de la clave privada RSA
    read_bytes = fread(&(skey->rsa_len), sizeof(size_t), 1, file);
    if (read_bytes < 1) {
        p_error("No es una superclave: No contiene la longitud de RSA")
        fclose(file);
        return SKError;
    }

    // Leer la longitud del PEM de la clave privada RSA
    read_bytes = fread(&(skey->cipher_rsa_len), sizeof(size_t), 1, file);
    if (read_bytes < 1) {
        p_error("No es una superclave: No contiene la longitud de RSA encriptado")
        fclose(file);
        return SKError;
    }

    // Reservar memoria para rsak_pem y leer el PEM de la clave privada RSA
    skey->rsa = (u_char*) OPENSSL_malloc(skey->cipher_rsa_len);
    if (!skey->rsa) { // skey->rsa == null
        p_error("No se pudo reservar memoria para la clave RSA")
        fclose(file);
        return SKError;
    }
    
    read_bytes = fread(skey->rsa, sizeof(u_char), skey->cipher_rsa_len, file);
    if (read_bytes < skey->cipher_rsa_len) {
        p_error("No es una superclave: No contiene una clave RSA")
        fclose(file);
        return SKError;
    }

    // Leer el hash de la contraseña
    read_bytes = fread(skey->phash, sizeof(u_char), SHA2_BYTES, file);
    if (read_bytes < SHA2_BYTES) {
        p_error("No es una superclave: No contiene el hash del password")
        fclose(file);
        return SKError;
    }

    fclose(file);
    return SKValid;
}
