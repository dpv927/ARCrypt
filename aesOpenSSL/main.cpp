#include "encrypter.hpp"
#include "decrypter.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace std;

int main(void) {

  unsigned char key[]  = "0123456789abcdef";
  unsigned char text[] = "Hello worldaas";
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
  return 0;
}
