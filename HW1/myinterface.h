#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <stdio.h>

using namespace std ;

#ifndef MYINTERFACE_H_
#define MYINTERFACE_H_

void handleErrors(void);
int encrypt(char* filename, const EVP_CIPHER* (*crypo_algm)(void), unsigned char *key, unsigned char *iv);
int decrypt(char* filename, const EVP_CIPHER* (*crypo_algm)(void), unsigned char *key, unsigned char *iv);

#endif
