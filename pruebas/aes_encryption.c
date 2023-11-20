#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#define AES_KEY_BYTES 32
#define RSA_KEY_BYTES 256

int encryptRSAKey_withAES(u_char* rsa, size_t rsa_len, 
	u_char* cipher_rsa, u_char* aes_key) 
{
  EVP_CIPHER_CTX* ctx;
  int cipher_len;
  int len;
 
  ctx = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, NULL);
  EVP_EncryptUpdate(ctx, cipher_rsa, &len, rsa, rsa_len);
  cipher_len = len;
  EVP_EncryptFinal_ex(ctx, cipher_rsa+len, &len);
  cipher_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return cipher_len;
}

int decryptRSAKey_withAES(const u_char* cipher_rsa, const size_t cipher_rsa_len,
	u_char* rsa, const u_char* aes) 
{
  EVP_CIPHER_CTX *ctx;
  int plaintext_len;
  int len;

  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes, NULL);
  EVP_DecryptUpdate(ctx, rsa, &len, cipher_rsa, cipher_rsa_len);
  plaintext_len = len;
  EVP_DecryptFinal_ex(ctx, rsa+len, &len);
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int main(void) {
	u_char aes_key[AES_KEY_BYTES];// = "376281pr4h321dxndr8y2p1qs,s4zrq2upxz";
	u_char* rsa_key;
	u_char* cipher_rsa_key;
	
	printf("Type a message: ");
	scanf("%s", aes_key);
	
	// Inicializar RSA key
	rsa_key = (u_char*) malloc(sizeof(u_char)*RSA_KEY_BYTES);
	cipher_rsa_key = (u_char*) malloc((sizeof(u_char)*RSA_KEY_BYTES)+128);
	
	for(int i=0; i<RSA_KEY_BYTES; i++)
		rsa_key[i] = i;
	
	for(int i=0; i<RSA_KEY_BYTES; i++)
		printf("%02x ", rsa_key[i]);
		
	
	// Encrypt the RSA key
	int cipher_size = encryptRSAKey_withAES(
		rsa_key,
		RSA_KEY_BYTES,
		cipher_rsa_key,
		aes_key
	); 
	
	// Restaurar RSA key
	for(int i=0; i<RSA_KEY_BYTES; i++)
		rsa_key[i] = 0;
		
		printf("\n\n");
	for(int i=0; i<RSA_KEY_BYTES; i++)
		printf("%02x ", rsa_key[i]);
	
	// Decrypt the RSA key
	int plain_size = decryptRSAKey_withAES(
		cipher_rsa_key,
		cipher_size,
		rsa_key,
		aes_key
	);
	
	printf("\n\n");
	for(int i=0; i<RSA_KEY_BYTES; i++)
		printf("%02x ", rsa_key[i]);
	
	free(rsa_key);
	free(cipher_rsa_key);
	return 0;
}
