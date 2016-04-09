#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include "../util/textprocessing.h"
#include "../util/helpers.h"

Bank* bank_create()
{
    system("rm *.card > /dev/null 2>&1");
    Bank *bank = (Bank*) malloc(sizeof(Bank));
    if(bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd=socket(AF_INET,SOCK_DGRAM,0);

    bzero(&bank->rtr_addr,sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port=htons(ROUTER_PORT);
    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd,(struct sockaddr *)&bank->bank_addr,sizeof(bank->bank_addr));
    bank->encrypt_ctx = EVP_CIPHER_CTX_new();
    bank->decrypt_ctx = EVP_CIPHER_CTX_new();
    bank->session = NULL;
    bank->table = hash_table_create(100);
    
    // Set up the protocol state
    // TODO set up more, as needed
    
    return bank;
}

void bank_free(Bank *bank)
{
    if(bank != NULL)
    {
        free_session(&(bank->session));
        hash_table_free(bank->table);
        close(bank->sockfd);
        free(bank);
        
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr*) &bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    
    char cpy_cmd[len+1];
    strncpy(cpy_cmd,command,sizeof(cpy_cmd));
    cpy_cmd[len] = '\0';
    const char *delim = " ";
    char *token;
    token = strtok(cpy_cmd,delim);
    
    if(strncmp(token,"create-user",strlen("create-user"))==0){

        if (cpy_cmd[strlen("create-user")] != '\0' && 
               cpy_cmd[strlen("create-user")] != '\n') {
            puts("Invalid Command");
            return; 
        }

        char * arg1,*arg2,*arg3,*extra;
        arg1 = strtok(NULL,delim);
        arg2 = strtok(NULL,delim);
        arg3 = strtok(NULL,delim);
        extra = strtok(NULL,delim);
        char * int_max = "4294967295";
        strtok(arg3,"\n");
        if(arg1 == NULL || arg2 == NULL || arg3 == NULL || extra != NULL){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        if(strlen(arg1) > 250){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
       
        if(strlen(arg2) != 4){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        
        /*Check arg3 for invalid characters*/
        if(!is_only_numbers(arg3)){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        /*Boundry Check*/
        if(is_greater_than(arg3,int_max)){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        /*Check rest of arguments for invalid characters*/
        if(!is_only_letters(arg1)){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        
        if(!is_only_numbers(arg2)){
            puts("Usage: create-user <user-name> <pin> <balance>");
            return;
        }
        /*Do stuff*/
        USER* user = calloc(1,sizeof(USER));
        user->balance = strtoul(arg3,NULL,10);
        strncpy(user->PIN,arg2,4);
        strncpy(user->name,arg1,250);
       
        unsigned int part1;
        unsigned int part2;
        unsigned int part3;
        unsigned int part4;
        gen_rand_uint(&part1);
        gen_rand_uint(&part2);
        gen_rand_uint(&part3);
        gen_rand_uint(&part4);
        part1%=10000;
        part2%=10000;
        part3%=10000;
        part4%=10000;
        snprintf(user->account_no,16,"%04u%04u%04u%04u",part1,part2,part3,part4);
        
        
        if(hash_table_add(bank->table,user->name,user) == -1){
            puts("User already exists");
            return;
        }
        char fname[251+5];
        
        strncpy(fname,user->name,250);
        strcat(fname,".card");
 
        
        
        FILE *fp = fopen(fname, "w");
        if(fp == NULL){
            printf("Error creating card file for %s\n",arg1);
            fflush(stdout);
        }
        fprintf(fp,"%.*s",16,user->account_no);
        fclose(fp);
        printf("Created user %s\n",arg1);
        fflush(stdout);


    }else if(strncmp(token,"deposit",strlen("deposit"))==0){

        if (cpy_cmd[strlen("deposit")] != '\0'&& 
                cpy_cmd[strlen("deposit")] != '\n') {
            puts("Usage: deposit <user-name> <amt>");
            return; 
        }

        char * arg1,*arg2,*extra;
        arg1 = strtok(NULL,delim);
        arg2 = strtok(NULL,delim);
        extra = strtok(NULL,delim);
        char * int_max = "4294967295";
        unsigned int bigint = 4294967295u;
        char  bigint_str[11];
        strtok(arg2,"\n");
        if(arg1 == NULL || arg2 == NULL ||extra != NULL){
            puts("Usage: deposit <user-name> <amt>");
            return;
        }
        if(strlen(arg1) > 250){
            puts("Usage: deposit <user-name> <amt>");
            return;
        }
        
        if(!is_only_numbers(arg2)){
            puts("Usage: deposit <user-name> <amt>");
            return;
        }
        
        /*Boundry Check*/
        if(is_greater_than(arg2,int_max)){
            puts("Usage: deposit <user-name> <amt>");
            return;
        }
        
        /*Check rest of arguments for invalid characters*/
        if(!is_only_letters(arg1)){
            puts("Usage: deposit <user-name> <amt>");
            return;
        }
        USER* user = (USER*)hash_table_find(bank->table, arg1);
        if(user == NULL){
            puts("No such user");
            return;
        }
     
        
        bigint -= user->balance; 
        
        sprintf(bigint_str, "%u", bigint);
        
        if(is_greater_than(arg2,bigint_str)){
           
            puts("Too rich for this program");
            return;
        }
        user->balance += strtoul(arg2,NULL,10);
        printf("$%s added to %s's account\n",arg2,arg1);
        fflush(stdout);
        
    }else if(strncmp(token,"balance",strlen("balance"))==0){
        
        if (cpy_cmd[strlen("balance")] != '\0') {
            puts("Usage: balance <user-name>");
            return; 
        }

        char * arg1,*extra;
        arg1 = strtok(NULL,delim);
        extra = strtok(NULL,delim);
        strtok(arg1,"\n");
        if(arg1 == NULL ||extra != NULL){
            puts("Usage: balance <user-name>");
            return;
        }
        if(strlen(arg1) > 250){
            puts("Usage: balance <user-name>");
            return;
        }

        if(!is_only_letters(arg1)){
            puts("Usage: balance <user-name>");
            return;
        }
        /*Do stuff*/
        USER* user = (USER*)hash_table_find(bank->table, arg1);
       
        if(user == NULL){
            puts("No such user");
            return;
        }
        printf("$%u\n",user->balance);

        fflush(stdout);
    } else {
      
        puts("Invalid Command");
    }
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    
    char cpy_cmd[len+1];
    strncpy(cpy_cmd,command,sizeof(cpy_cmd));
    cpy_cmd[len] = '\0';
    const char *delim = " ";
    char *token;
    if(bank->session != NULL){
        
     
        /*We want to encrypt stuff*/
        unsigned char decrypted_msg[10000];
        unsigned char encrypted_msg[10000];
        unsigned char recvbuf[10000];
        memcpy(recvbuf,command,len);
        int length =decrypt_with_aes(bank->decrypt_ctx,recvbuf,
            bank->session->session_key,len,decrypted_msg);
        decrypted_msg[length] = '\0';
        if(length == -1){
            bank_send(bank, "bad", 3);
            //puts("decrypt failure");
            return;
        }
        token = strtok(decrypted_msg,delim);
        fflush(stdout);
            
        if(strncmp(token,"withdraw",strlen("withdraw"))==0){
            char * arg1,*extra;
            char * int_max = "4294967295";
            arg1 = strtok(NULL,delim);
            extra = strtok(NULL,delim);
            strtok(arg1,"\n");
            /*Check number of arguments*/
            if(arg1 == NULL || extra != NULL){
                //puts("Incorrect number of arguments");
                return;
            }
            /*Check for invalid characters*/
            if(!is_only_numbers(arg1)){
                //puts("Invalid characters");
                return;
            }
            
            /*Boundry Check*/
            if(is_greater_than(arg1,int_max)){
                //puts("amount too large");
                return;
            }
            
            /*Do stuff*/
            int ctextlen;
            USER* user = (USER*)hash_table_find(bank->table, bank->session->username);
            int subtract = strtoul(arg1,NULL,10);
            if(subtract > user->balance){
                ctextlen = encrypt_with_aes(bank->encrypt_ctx,"funds",
                                            bank->session->session_key,
                                            strlen("funds")+1,
                                            encrypted_msg);
                bank_send(bank, encrypted_msg, ctextlen);    
                return;      
            }
            user->balance -= subtract;
           
            
            
            ctextlen = encrypt_with_aes(bank->encrypt_ctx,"valid",
                                        bank->session->session_key,
                                        strlen("valid")+1,
                                        encrypted_msg);
            bank_send(bank, encrypted_msg, ctextlen);

        } else if(strncmp(token,"balance",strlen("balance"))==0){
            char* extra = strtok(NULL,delim);
            /*Check number of arguments*/
            strtok(token,"\n");
            if(strlen(token) != strlen("balance")){
                puts("Invalid command");
                return;
            }
            if(extra != NULL){
                puts("Incorrect number of arguments");
                return;
            }
            USER* user = (USER*)hash_table_find(bank->table, bank->session->username);
            unsigned char balance_str[11];
            sprintf(balance_str, "%u", user->balance);
            
            int ctextlen = encrypt_with_aes(bank->encrypt_ctx,balance_str,
                                        bank->session->session_key,
                                        strlen(balance_str)+1,
                                        encrypted_msg);
            bank_send(bank, encrypted_msg, ctextlen);
            
        } else if(strncmp(token,"end-session",strlen("end-session"))==0){
            char* extra = strtok(NULL,delim);
            /*Check number of arguments*/
            strtok(token,"\n");
            if(strlen(token) != strlen("end-session")){
                //puts("Invalid command");
                return;
            }
            if(extra != NULL){
                //puts("Incorrect number of arguments");
                return;
            }
            free_session(&bank->session);
            
        } else {
            //puts("Invalid command");
            return;
        }
    } else {
        /*No session yet, so we initialize encryption and stuff*/
        token = strtok(cpy_cmd,delim);
        if(strncmp(token,"begin-session",strlen(token))==0){
            char * arg1,*extra;
            arg1 = strtok(NULL,delim);
            extra = strtok(NULL,delim);
            strtok(arg1,"\n");
            if(arg1 == NULL || extra != NULL){
                //puts("Incorrect number of arguments");
                return;
            }
            if(strlen(arg1) > 250){
               // puts("Username too long");
                return;
            }
            /*Check for invalid characters*/
            if(!(is_only_letters(arg1))){
                //puts("Invalid characters");
                return;
            }
            USER* user = (USER*)hash_table_find(bank->table, arg1);
            
            if(user != NULL){

                bank_send(bank,"PIN? ", strlen("PIN? "));

                
                char recvline[10000];
                unsigned char decrypted_skey[256];
                unsigned char decrypted_hash[4096];
                unsigned char check_hash[SHA256_DIGEST_LENGTH];
                int padding = RSA_PKCS1_PADDING;
                /*Recieve encrypted hash?*/
                int n = bank_recv(bank, recvline, 10000);
                recvline[n]=0;
            
                int ret = RSA_public_decrypt(256,(unsigned char*)recvline,
                            decrypted_hash,bank->atm_pub_key,padding);

                if(ret == -1){
                   
                    bank_send(bank, "asdf", strlen("asdf"));
                    return;
                }       
                /*Recieve encrypted SKEY?*/  
                n = bank_recv(bank, recvline, 10000);
                recvline[n]=0;
              
                int test = RSA_private_decrypt(256,(unsigned char*)recvline,
                    decrypted_skey,bank->bank_priv_key,padding);     
                if(test == -1){
                   
                    return;
                }
                /*Digital Signature*/
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, decrypted_skey, 16);
                SHA256_Final(check_hash, &sha256);
                if(memcmp(decrypted_hash,check_hash,SHA256_DIGEST_LENGTH) == 0){
                   
                    unsigned char encrypted_msg[10000];
                    unsigned char decrypted_msg[10000];
                    int ctextlen;
                    if(user != NULL){
                        ctextlen = encrypt_with_aes(bank->encrypt_ctx,arg1,
                                        decrypted_skey,strlen(arg1)+1,
                                        encrypted_msg);
                        bank_send(bank, encrypted_msg, ctextlen);
                    } else {
                        ctextlen = encrypt_with_aes(bank->encrypt_ctx,"no user",
                                        decrypted_skey,strlen("no user")+1,
                                        encrypted_msg);
                        bank_send(bank, encrypted_msg, ctextlen);
                        return;
                    }                    
                    unsigned char recvbuf[10000];
                    n = bank_recv(bank, recvbuf, 10000);
                    recvbuf[n]=0;
                    int len =decrypt_with_aes(bank->decrypt_ctx,recvbuf,
                     decrypted_skey,n,decrypted_msg);
                     
                    if(len == -1){
                        
                        bank_send(bank, "error", 5);
                        return;
                    }
                    if(strncmp(decrypted_msg,"start",7) == 0){
                        
                        ctextlen = encrypt_with_aes(bank->encrypt_ctx,"SENDPIN",
                                    decrypted_skey,strlen("SENDPIN")+1,
                                    encrypted_msg);
                        bank_send(bank, encrypted_msg, ctextlen);
                        n = bank_recv(bank, recvbuf, 10000);
                        recvbuf[n]=0;
                        char decrypted_acc_msg[10000];
                        len = decrypt_with_aes(bank->decrypt_ctx,recvbuf,
                            decrypted_skey,n,decrypted_msg);
                        
                        if(strcmp("badform",decrypted_msg)==0){
                            
                            return;
                        }
                        n = bank_recv(bank, recvbuf, 10000);
                        int len2 = decrypt_with_aes(bank->decrypt_ctx,recvbuf,
                            decrypted_skey,n,decrypted_acc_msg);
                            
                        if(len == -1 || len2 == -1){
                            
                            ctextlen = encrypt_with_aes(bank->encrypt_ctx,"no",
                                    decrypted_skey,strlen("no")+1,
                                    encrypted_msg);
                            bank_send(bank, encrypted_msg, ctextlen);
                            return;
                        }
                        
                        
                        if(memcmp(decrypted_msg,user->PIN,4) == 0 && 
                           memcmp(decrypted_acc_msg,user->account_no,16) == 0 &&
                           user->account_locked != 1){
                            ctextlen = encrypt_with_aes(bank->encrypt_ctx,"VALID",
                                    decrypted_skey,strlen("VALID")+1,
                                    encrypted_msg);
                            user->num_tries = 0;
                            bank_send(bank, encrypted_msg, ctextlen);
                            bank->session = (SESSION*)calloc(1,sizeof(SESSION));
                            
                            memcpy(bank->session->session_key,decrypted_skey,16);
                            strcpy(bank->session->username,user->name);
                            memcpy(bank->session->account_no,user->account_no,16);
                            return;
                            
                        } else {
                            
                            if(user->num_tries == 3){
                                user->account_locked = 1;
                                ctextlen = encrypt_with_aes(bank->encrypt_ctx,"lock",
                                    decrypted_skey,strlen("lock")+1,
                                    encrypted_msg);
                            } else {
                                user->num_tries += 1;
                                ctextlen = encrypt_with_aes(bank->encrypt_ctx,"no",
                                    decrypted_skey,strlen("no")+1,
                                    encrypted_msg);
                            }

                            bank_send(bank, encrypted_msg, ctextlen);
                            return;
                        }
                        
                     
                    } else {
                        
                        return;
                    }
                
        
                } else {
                    
                    return;
                }
                return;
            }
            else{
                /*User doesnt exist, send error to the ATM*/
                bank_send(bank,"no user", strlen("no user")+1);
                return;
            }
        } else {
            puts("No session");
        }
    }
}
