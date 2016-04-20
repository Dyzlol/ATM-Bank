/*
 * The Bank takes commands from stdin as well as from the ATM.  
 *
 * The Bank can read both .card files AND .pin files.
 */

#ifndef __BANK_H__
#define __BANK_H__

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include "../util/session.h"
#include "../util/hash_table.h"
#include "../util/user.h"


typedef struct _Bank
{
    // Networking state
    int sockfd;
    struct sockaddr_in rtr_addr;
    struct sockaddr_in bank_addr;
    RSA* bank_priv_key;
    RSA* bank_pub_key;
    RSA* atm_pub_key;
    unsigned char IV[16];
    SESSION* session;
    EVP_CIPHER_CTX* decrypt_ctx;
    EVP_CIPHER_CTX* encrypt_ctx;
    HashTable* table;
    // Protocol state
    // TODO add more, as needed
} Bank;

Bank* bank_create();
void bank_free(Bank *bank);
ssize_t bank_send(Bank *bank, char *data, size_t data_len);
ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len);
void bank_process_local_command(Bank *bank, char *command, size_t len);
void bank_process_remote_command(Bank *bank, char *command, size_t len);

#endif
