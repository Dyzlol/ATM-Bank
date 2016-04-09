/* 
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char**argv)
{
    char* filename = argv[1];
    FILE* fp;
    fp = fopen(filename,"r");
    if(fp == NULL){
        puts("ERROR OPENING FILE");
        return 64;
    }
    int n;
    char sendline[1000];
    char recvline[1000];

    Bank *bank = bank_create();
    bank->bank_pub_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if(bank->bank_pub_key == NULL)
    {
        printf("\n%s\n", "Error Reading bank public key");
        RSA_free(bank->bank_pub_key);
        return 0;
    }
    bank->bank_priv_key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if(bank->bank_priv_key == NULL)
    {
        printf("\n%s\n", "Error Reading bank private key");
        RSA_free(bank->bank_priv_key);
        return 0;
    }
    bank->atm_pub_key = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
    if(bank->atm_pub_key == NULL)
    {
        printf("\n%s\n", "Error Reading atm public key");
        RSA_free(bank->atm_pub_key);
        return 0;
    }
    
    fclose(fp);

    printf("%s", prompt);
    fflush(stdout);

    while(1)
    {
       fd_set fds;
       FD_ZERO(&fds);
       FD_SET(0, &fds);
       FD_SET(bank->sockfd, &fds);
       select(bank->sockfd+1, &fds, NULL, NULL, NULL);

       if(FD_ISSET(0, &fds))
       {
           fgets(sendline, 10000,stdin);
           bank_process_local_command(bank, sendline, strlen(sendline));
           printf("%s", prompt);
           fflush(stdout);
       }
       else if(FD_ISSET(bank->sockfd, &fds))
       {
           n = bank_recv(bank, recvline, 10000);
           bank_process_remote_command(bank, recvline, n);
       }
    }
    RSA_free(bank->bank_priv_key);
    return EXIT_SUCCESS;
}
