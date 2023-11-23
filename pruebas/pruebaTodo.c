#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Clave AES:


4c f2 ca 9f cb 46 42 b2 8e 2f 40 90 ae e6 1b 5e
9b c8 4b 43 92 b0 62 f1 b2 74 54 08 55 f4 ad c4


38 9d 7a 11 88 55 00 00 d5 76 7a 11 88 55 00 00
0a 00 00 00 00 00 00 00 a1 5a 8a 31 fd 7f 00 00


 *
 *
 *
 *
 *
 *
 *
 *
 *
 * */

void printblock(char*, unsigned char*, int);

/* Datos de AES para encriptar */
unsigned char aes_key[256>>3];
unsigned char cipher_aes_key[2048>>3];
unsigned char out_aes[256>>3];

/* Datos de RSA para encriptar */
unsigned char* rsa_key;
unsigned char* cipher_rsa_key;
int rsa_len;
int cipher_rsa_len;

/* Datos del usuario */
unsigned char password[256>>3] = "12345678";

int main(void) {
    /* Inicializar la clave AES y contrasena */
    for (int i = 0; i<256>>3; i++) {
        aes_key[i] = i; 
        /*password[i] = i+3;*/ }

   printblock("Clave AES", aes_key, 256>>3);
   //printblock("Password", password, 256>>3);

    /* Encriptar la clave AES con RSA (rsa se genera aqui) */
    EVP_PKEY *rsa_keypair = NULL;
    EVP_PKEY_CTX *ctx;
    BIO* rsa_bio;
    size_t outlen;
    int pending;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &rsa_keypair);
    EVP_PKEY_CTX_free(ctx);

    ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_encrypt(ctx, cipher_aes_key, &outlen, aes_key, 256>>3);
    EVP_PKEY_CTX_free(ctx);

    rsa_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(rsa_bio, rsa_keypair, NULL, NULL, 0, 0, NULL);
    pending = BIO_pending(rsa_bio);
    rsa_key = OPENSSL_malloc(pending);
    BIO_read(rsa_bio, rsa_key, pending);
    rsa_len = pending;
    BIO_free(rsa_bio);
    EVP_PKEY_free(rsa_keypair);

    //printf("\nRSA_len: %d\n", rsa_len);
    //printblock("Clave AES encriptada", cipher_aes_key, 2048>>3);
    //printblock("Clave RSA", rsa_key, rsa_len);

    /* Encriptar la clave RSA con la contrasena AES */
    EVP_CIPHER_CTX* c_ctx;
    int len;

    c_ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c_ctx, EVP_aes_256_cbc(), NULL, password, NULL);
    cipher_rsa_key = OPENSSL_malloc(rsa_len*2);
    EVP_EncryptUpdate(c_ctx, cipher_rsa_key, &len, rsa_key, rsa_len);
    cipher_rsa_len = len;
    EVP_EncryptFinal_ex(c_ctx, cipher_rsa_key+len, &len);
    cipher_rsa_len += len;
    EVP_CIPHER_CTX_free(c_ctx);

    //printf("\nCipher_RSA_len: %d\n", cipher_rsa_len);
    //printblock("RSA encriptada", cipher_rsa_key, cipher_rsa_len);
    OPENSSL_free(rsa_key);

    /* Desencriptar la clave RSA con la contrasena AES */
    int plaintext_len;

    c_ctx = EVP_CIPHER_CTX_new();
    rsa_key = OPENSSL_malloc(rsa_len);
    EVP_DecryptInit_ex(c_ctx, EVP_aes_256_cbc(), NULL, password, NULL);
    EVP_DecryptUpdate(c_ctx, rsa_key, &len, cipher_rsa_key, cipher_rsa_len);
    rsa_len = len;
    EVP_DecryptFinal_ex(c_ctx, rsa_key+len, &len);
    rsa_len += len;
    EVP_CIPHER_CTX_free(c_ctx);
    OPENSSL_free(cipher_rsa_key);

    //printf("\nRSA_len: %d\n", rsa_len);
    //printblock("Clave RSA desencriptada", rsa_key, rsa_len);

    /* Desencriptar la clave AES principal con RSA */
    for (int i = 0; i<256>>3; i++)
        aes_key[i] = 0;

    printblock("Clave AES", aes_key, 256>>3);

    rsa_bio = BIO_new(BIO_s_mem());
    BIO_write(rsa_bio, rsa_key, rsa_len);
    rsa_keypair = PEM_read_bio_PrivateKey_ex(rsa_bio, NULL, NULL, NULL, NULL, NULL);
    BIO_free(rsa_bio); 

    ctx = EVP_PKEY_CTX_new(rsa_keypair, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_decrypt(ctx, aes_key, &outlen, cipher_aes_key, 2048>>3);

    printf("%zu", outlen);
    printblock("Clave AES", aes_key, 256>>3);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(rsa_keypair);
    OPENSSL_free(rsa_key);
    return 0;
} 


void printblock(char* title, unsigned char* block, int size) {
    printf("\n\n%s\n", title);
    for (int i = 0; i<size; i++) {
        printf("%02x ", block[i]);
        if(((i+1)%16)==0) 
            printf("\n");}
}
