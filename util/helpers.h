#ifndef __HELPERS__
#define __HELPERS__
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include "../atm/atm.h"

int gen_rand_128(unsigned char* storage);
int gen_rand_uint(unsigned int* storage);
int encrypt_with_aes(EVP_CIPHER_CTX* ctx,unsigned char* msg,unsigned char* key, size_t msglen, unsigned char * dest);
int decrypt_with_aes(EVP_CIPHER_CTX* ctx, unsigned char* encrypted,unsigned char* shared_key, size_t encrypted_len, unsigned char* dest);

#endif
