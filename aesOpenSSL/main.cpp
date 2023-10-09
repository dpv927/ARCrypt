#include "encrypter.hpp"
#include "decrypter.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#define MODE 0

using namespace std;

int main(void) {
  unsigned char key[] = { 
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31
  };

#if(MODE==0) 
  /* Ejemplo de encriptacion de archivo */
  char filename[] = "textfile";
  Encryption::encryptFile(filename, key);
  cout<<"Finished Encryption."<<endl;
  //getchar();
  //Decryption::decryptFile(filename, key);
  //cout<<"Finished Decryption.";
#endif

#if(MODE==1)
  /* Ejemplo de encriptacion de String */
  unsigned char text[] = "Hello world!";
  int text_len = strlen((const char*) text);

  cout<< "Encrypted: ";
  unsigned char cipher[64];
  int cipher_len = Encryption::encryptStr(text, text_len, key, cipher);
  
  for (int i = 0; i < cipher_len; i++)
    cout << (int) cipher[i];
  cout<<endl;

  cout<<"Decrypted: ";
  unsigned char decrypted[64];
  int dec_len = Decryption::decryptStr(cipher, cipher_len, key, decrypted);

  for (int i = 0; i < dec_len; i++)
    cout<< decrypted[i];
  cout<<endl;
#endif
  return 0;
}
