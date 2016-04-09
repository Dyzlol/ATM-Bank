/* 
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <sys/types.h>

static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    char* filename = argv[1];
    FILE* fp;
  
    fp = fopen(filename,"r");
    if(fp == NULL){
        puts("ERROR OPENING FILE");
        return 64;
    }
    
    char user_input[10000];
    /*BIO * keybio = BIO_new(BIO_s_mem());
    RSA_print(keybio, rsa_pub, 0);
    char buffer [1024];
    while (BIO_read (keybio, buffer, 1024) > 0)
    {
        printf("%s",buffer);
    }
    BIO_free(keybio);*/
    
    
    ATM *atm = atm_create();
    /*Make sure to free atm->bank_pub_key at some point*/
    
    atm->bank_pub_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if(atm->bank_pub_key == NULL)
    {
        printf("\n%s\n", "Error Reading bank public key");
        RSA_free(atm->bank_pub_key);
        return 0;
    }
    
    atm->atm_pub_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if(atm->atm_pub_key == NULL)
    {
        printf("\n%s\n", "Error Reading atm public key");
        RSA_free(atm->atm_pub_key);
        return 0;
    }
    
    atm->atm_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if(atm->atm_priv_key == NULL)
    {
        printf("\n%s\n", "Error Reading atm private key");
        RSA_free(atm->atm_priv_key);
        return 0;
    } 
    
    
    /*BIO * keybio = BIO_new(BIO_s_mem());
    RSA_print(keybio,atm->bank_pub_key, 0);
    char buffer [1024];
    while (BIO_read (keybio, buffer, 1024) > 0)
    {
        printf("%s",buffer);
    }
    BIO_free(keybio);
    keybio = BIO_new(BIO_s_mem());
    RSA_print(keybio,atm->atm_pub_key, 0);
    char buffer2 [1024];
    while (BIO_read (keybio, buffer2, 1024) > 0)
    {
        printf("%s",buffer2);
    }
    BIO_free(keybio);*/

    
    fclose(fp);

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 10000,stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        if(atm->session != NULL){
            printf("ATM (%s): ", atm->session->username);
            fflush(stdout);
        } else {
            printf("%s", prompt);
            fflush(stdout);
        }
        
    }
    RSA_free(atm->bank_pub_key);
    RSA_free(atm->atm_pub_key);
    RSA_free(atm->atm_priv_key);
	return EXIT_SUCCESS;
}
