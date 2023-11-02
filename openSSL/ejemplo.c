
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

int main() {
    OpenSSL_add_all_algorithms();

    // Genera un par de claves RSA (clave pública y privada)
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) {
        fprintf(stderr, "Error al generar el par de claves RSA\n");
        return 1;
    }

    // La cadena de texto que deseas cifrar (256 bytes)
    const char *plaintext = "Esta es una cadena de texto de 256 bytes para cifrar con RSA..."; // Asegúrate de que tenga exactamente 256 bytes

    // Tamaño del bloque cifrado (tamaño de la clave RSA en bytes)
    int rsa_key_size = RSA_size(rsa);

    // Almacena el texto cifrado
    unsigned char *ciphertext = (unsigned char *)malloc(rsa_key_size);
    if (!ciphertext) {
        fprintf(stderr, "Error al asignar memoria para el texto cifrado\n");
        return 1;
    }

    // Cifra el texto
    int ciphertext_len = RSA_public_encrypt(strlen(plaintext), (unsigned char *)plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
    if (ciphertext_len == -1) {
        fprintf(stderr, "Error al cifrar el texto\n");
        return 1;
    }

    // Muestra el texto cifrado
    printf("Texto cifrado:\n");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Almacena el texto descifrado
    unsigned char *deciphertext = (unsigned char *)malloc(rsa_key_size);
    if (!deciphertext) {
        fprintf(stderr, "Error al asignar memoria para el texto descifrado\n");
        return 1;
    }

    // Descifra el texto
    int deciphertext_len = RSA_private_decrypt(ciphertext_len, ciphertext, deciphertext, rsa, RSA_PKCS1_PADDING);
    if (deciphertext_len == -1) {
        fprintf(stderr, "Error al descifrar el texto\n");
        return 1;
    }

    // Muestra el texto descifrado
    printf("Texto descifrado:\n");
    printf("%s\n", deciphertext);

    // Limpia la memoria
    RSA_free(rsa);
    free(ciphertext);
    free(deciphertext);
    return 0;
}

