#include "atm.h"
#include "../ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include "../util/textprocessing.h"
#include "../util/user.h"
#include "../util/session.h"
#include "../util/helpers.h"
#define SKEY_SIZE 16
ATM* atm_create()
{
    ATM *atm = (ATM*) malloc(sizeof(ATM));
    if(atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }
    atm->session = NULL;
    // Set up the network state
    atm->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&atm->rtr_addr,sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    // HI ADAM
    // no
    atm->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port=htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd,(struct sockaddr *)&atm->atm_addr,sizeof(atm->atm_addr));
    atm->encrypt_ctx = EVP_CIPHER_CTX_new();
    atm->decrypt_ctx = EVP_CIPHER_CTX_new();
    
    // Set up the protocol state
    // TODO set up more, as needed

    return atm;
}

void atm_free(ATM *atm)
{
    if(atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr*) &atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void atm_process_command(ATM *atm, char *command){


    //int len = strlen(command);
    char cpy_cmd[10000];
    strncpy(cpy_cmd,command,sizeof(cpy_cmd)-1);
    cpy_cmd[9999] = '\0';
    const char *delim = " ";
    char *token;
    token = strtok(cpy_cmd,delim);
    
    unsigned char recvbuf[10000];
    unsigned char encrypted_msg[10000];
    unsigned char decrypt_buffer[10000];
    int ctextlen;


    if(strncmp(token,"begin-session",strlen("begin-session"))==0){
        
        if (cpy_cmd[strlen("begin-session")] != '\0' &&
                cpy_cmd[strlen("begin-session")] != '\n') {
            puts("Invalid Command");
            return; 
        }


        char * arg1,*extra;
        arg1 = strtok(NULL,delim);
        //arg2 = strtok(NULL,delim);
        extra = strtok(NULL,delim);
        strtok(arg1,"\n");
        if(arg1 == NULL || extra != NULL){
            //puts("Incorrect number of arguments");
            puts("Usage: begin-session <user-name>");
            return;
        }
        if(strlen(arg1) > 250){
            puts("Usage: begin-session <user-name>");
            return;
        }
        /*Check for invalid characters*/
        if(!(is_only_letters(arg1))){
            puts("Usage: begin-session <user-name>");
            return;
        }
        /*Do stuff*/
        /*-------------------*/
        
        /*Open urandom*/
        unsigned char skey[SKEY_SIZE];
        if(gen_rand_128(skey) == -1){
            //puts("Error generating session key");
            return;
        }
        if(atm->session != NULL){
            puts("There is already a user logged in");
            return;
        }
        atm->session = (SESSION*)calloc(1,sizeof(SESSION));
        memcpy(atm->session->session_key,skey,SKEY_SIZE);
        atm->session->timestamp = time(0);
        strncpy(atm->session->username,arg1,sizeof(atm->session->username));
        char recvline[10000];
        int n;
        atm_send(atm, command, strlen(command));
        n = atm_recv(atm,recvline,10000);
        recvline[n]=0;
        
        if(strncmp(recvline,"no user",7) == 0){
            puts("No user found");
            free_session(&(atm->session));
            return;
        }
        char fname[251+5];
        strncpy(fname,arg1,250);
        strcat(fname,".card");
        if( access( fname, F_OK ) == -1 ) {
            printf("Unable to access %s's card\n",arg1);
            fflush(stdout);
            atm_send(atm,"asdf", 5);
            free_session(&(atm->session));
            return;
        }

        if(strncmp(recvline,"PIN? ",strlen("PIN? "))==0){
            int padding = RSA_PKCS1_PADDING;

            unsigned char hash[SHA256_DIGEST_LENGTH];
            unsigned char encrypted_hash[256];
            SHA256_CTX sha256;
            SHA256_Init(&sha256);
            SHA256_Update(&sha256, atm->session->session_key, 
                            sizeof(atm->session->session_key));
            SHA256_Final(hash, &sha256);
            RSA_private_encrypt(sizeof(hash),hash,encrypted_hash,
                                atm->atm_priv_key,padding);
                                

            atm_send(atm, encrypted_hash, sizeof(encrypted_hash));

           
            RSA_public_encrypt(sizeof(atm->session->session_key),
            atm->session->session_key,encrypted_msg,atm->bank_pub_key,padding);

            atm_send(atm, encrypted_msg, sizeof(encrypted_msg));

            n = atm_recv(atm,recvbuf,10000);
            recvbuf[n]=0;
            int dec_len = decrypt_with_aes(atm->decrypt_ctx,
                                recvbuf,atm->session->session_key,n,decrypt_buffer);
            if(dec_len == -1){
                fprintf(stderr,"Handshake failed\n");
                atm_send(atm,"asdf", 5);
                free_session(&atm->session);
                return;
            }
            if(strncmp(decrypt_buffer,"no user",10) == 0){
                puts("No such user");
                free_session(&atm->session);
                return;
            }
       
            if(strncmp(decrypt_buffer,arg1,strlen(decrypt_buffer))==0){
                
                char * enc = "start";
                ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    enc,atm->session->session_key,strlen(enc)+1,encrypted_msg);
                atm_send(atm, encrypted_msg, ctextlen);
                n = atm_recv(atm,recvbuf,10000);
    
                recvbuf[n]=0;
                if(decrypt_with_aes(atm->decrypt_ctx,recvbuf,
                    atm->session->session_key,n,decrypt_buffer) == -1){
                    fprintf(stderr,"Decryption failed\n");
                    free_session(&atm->session);
                    return;
                }
                if(strncmp(decrypt_buffer,"SENDPIN",9) == 0){
                    printf("%s","PIN? ");
                    fflush(stdout);
                    char user_input[1000];
                    char* p_tok;
                    fgets(user_input, 10000,stdin);
                    p_tok = strtok(user_input,"\n");
                    if(strlen(p_tok) != 4){
                        puts("Not authorized");
                        
                        ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                            "badform",atm->session->session_key,
                            strlen("badform")+1,encrypted_msg);      
                        atm_send(atm, encrypted_msg, ctextlen);
                     
                        free_session(&(atm->session));
                        return;
                    }
                    if(!is_only_numbers(p_tok)){
                        puts("Not authorized");
                        
                        ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                            "badform",atm->session->session_key,
                            strlen("badform")+1,encrypted_msg);      
                        atm_send(atm, encrypted_msg, ctextlen);
                        
                        free_session(&(atm->session));
                        return;
                    }

                    ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    p_tok,atm->session->session_key,strlen(p_tok)+1,encrypted_msg);
                    atm_send(atm, encrypted_msg, ctextlen);
                    
                    
                    FILE *fp = fopen(fname, "r");
                    if(fp == NULL){
                        printf("Unable to access %s's card\n",atm->session->username);
                        fflush(stdout);
                        free_session(&atm->session);
                        return;
                    }
                    char account_no[16];
                    fgets(account_no,16,fp);
                    fclose(fp);
                
                    ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    account_no,atm->session->session_key,16,encrypted_msg);
                    atm_send(atm, encrypted_msg, ctextlen);
                    
                    n = atm_recv(atm,recvbuf,10000);
                    recvbuf[n]=0;
                    if(decrypt_with_aes(atm->decrypt_ctx,recvbuf,
                        atm->session->session_key,n,decrypt_buffer) == -1){
                        fprintf(stderr,"Decryption failed\n");
                        free_session(&atm->session);
                        return;
                    }
                    if(strncmp(decrypt_buffer,"VALID",7) == 0){
                        puts("Authorized");
                    } else if (strncmp(decrypt_buffer,"lock",7) == 0){
                        puts("Account locked");
                        free_session(&atm->session);
                        return;
                    } else {
                        puts("Not Authorized");
                        free_session(&atm->session);
                        return;     
                    }
                }         
            } else {
                fprintf(stderr,"Handshake failed\n");
                atm_send(atm,"asdf", 5);
                free_session(&atm->session);
                return;
            }
            
              
        } else {
            //puts(recvline);
            free_session(&(atm->session));
            return;
        }
    } else if(strncmp(token,"withdraw",strlen("withdraw"))==0){

        if (cpy_cmd[strlen("withdraw")] != '\0' &&
                cpy_cmd[strlen("withdraw")] != '\n') {
            puts("Invalid Command");
            return; 
        }
        if(atm->session == NULL){
            puts("No user logged in");
            return;
        }

        char * arg1,*extra;
        char * int_max = "4294967295";
        arg1 = strtok(NULL,delim);
        extra = strtok(NULL,delim);
        strtok(arg1,"\n");
        /*Check number of arguments*/
        if(arg1 == NULL || extra != NULL){
            //puts("Incorrect number of arguments");
            puts("Usage: withdraw <amt>");
            return;
        }
        /*Check for invalid characters*/
        if(!is_only_numbers(arg1)){
            puts("Usage: withdraw <amt>");
            return;
        }
        
        /*Boundry Check*/
        if(is_greater_than(arg1,int_max)){
            puts("Usage: withdraw <amt>");
            return;
        }
        
        /*Do stuff*/
        int n;
        ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    command,atm->session->session_key,strlen(command),encrypted_msg);
        atm_send(atm, encrypted_msg, ctextlen);
        n = atm_recv(atm,recvbuf,10000);
        recvbuf[n]=0;
        int len;
        if((len = decrypt_with_aes(atm->decrypt_ctx,recvbuf,
            atm->session->session_key,n,decrypt_buffer) == -1)){
            fprintf(stderr,"A transmission error has occured\n");
            return;
        }
        if(strcmp(decrypt_buffer,"valid") != 0){
            puts("Insufficient funds");
            return;
        }
        printf("$%s dispensed\n", arg1);
        fflush(stdout);

    } else if(strncmp(token,"balance",strlen("balance"))==0){
        char* extra = strtok(NULL,delim);
        strtok(token,"\n");
        if(strlen(token) != strlen("balance")){
            puts("Invalid command");
            return;
        }
        if(atm->session == NULL){
            puts("No user logged in");
            return;
        }

        /*Check number of arguments*/
        if(extra != NULL){
            puts("Usage: balance");
            return;
        }
        int n;
        ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    command,atm->session->session_key,strlen(command),encrypted_msg);
        atm_send(atm, encrypted_msg, ctextlen);
        n = atm_recv(atm,recvbuf,10000);
        recvbuf[n]=0;
        int len;
        if((len = decrypt_with_aes(atm->decrypt_ctx,recvbuf,
            atm->session->session_key,n,decrypt_buffer) == -1)){
            fprintf(stderr,"A transmission error has occured\n");
            return;
        }
        printf("$%s\n",decrypt_buffer);
        fflush(stdout);


    } else if(strncmp(token,"end-session",strlen("end-session"))==0){
        char* extra = strtok(NULL,delim);
        strtok(token,"\n");
        if(strlen(token) != strlen("end-session")){
            puts("Invalid Command");
            return;
        }
        if(atm->session == NULL){
            puts("No user logged in");
            return;
        }
 
        /*Check number of arguments*/

        if(extra != NULL){
            puts("Usage: end-session");
            return;
        }
        ctextlen = encrypt_with_aes(atm->encrypt_ctx,
                    command,atm->session->session_key,strlen(command),encrypted_msg);
        atm_send(atm, encrypted_msg, ctextlen);
        free_session(&(atm->session));
        puts("User logged out");
    } else {
        puts("Invalid command");
        return;
    }
}
