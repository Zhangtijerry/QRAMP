#include <openssl/evp.h>
#include <openssl/rsa.h>
void f(){ RSA_generate_key(2048,3,0,0); }
