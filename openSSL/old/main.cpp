#include "encrypter.hpp"
#include "decrypter.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#define MODE 0
using namespace std;

/* Definir la clave de encriptacion/
 * desencriptacion usada en las pruebas. */
const unsigned char key[] = { 
  0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39,
  0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39,
};

int main(void) {
#if(MODE==1)
  /* Ejemplo de encriptacion de String */
  unsigned char text[] = "Hello world!";
  int text_len = strlen((const char*) text);

  cout<< "\nEncrypted String: ";
  unsigned char cipher[4096];
  int cipher_len = Encryption::encryptStr(text, text_len, key, cipher);
  
  for (int i = 0; i < cipher_len; i++)
    cout << (int) cipher[i];
  cout<<endl;

  cout<<"Decrypted String: ";
  unsigned char decrypted[4096];
  int dec_len = Decryption::decryptStr(cipher, cipher_len, key, decrypted);
  
  for (int i = 0; i < dec_len; i++)
    cout<< (int) decrypted[i];
  cout<<endl;
#endif

#if(MODE==0) 
  /* Ejemplo de encriptacion de archivo */
  char filename[] = "cacas";
  char enc_filename[] = "cacas.enc";

  Encryption::encryptFile(filename, key);
  Decryption::decryptFile(enc_filename, key);
  //
  Encryption::readfileBin("cacas");
  Encryption::readfileBin("cacas.enc.dec");

#endif

  return 0;
}
