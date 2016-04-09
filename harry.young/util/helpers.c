#include "helpers.h"

int gen_rand_128(unsigned char* storage){
    
    int randfile = open("/dev/urandom",O_RDONLY);
    if(read(randfile,storage,16) == -1){
        close(randfile);
        return -1;
    }
    close(randfile);
    return 0;
}
int gen_rand_uint(unsigned int* storage){
    
    int randfile = open("/dev/urandom",O_RDONLY);
    if(read(randfile,storage,16) == -1){
        close(randfile);
        return -1;
    }
    close(randfile);
    return 0;
}

int encrypt_with_aes(EVP_CIPHER_CTX* ctx,unsigned char* msg,unsigned char* key, size_t msglen, unsigned char * dest){

    unsigned char iv[16];
        
    /*Generate IV*/
    if(gen_rand_128(iv) == -1){
        //puts("Failure to generate IV");
        return -1;
    }
    unsigned char digest[20];
    HMAC(EVP_sha1(), key, 16, (unsigned char*)msg,msglen,digest,NULL);


    unsigned char buffer[msglen+20];
    EVP_EncryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,key,iv);
    int ciphertext_len;
    
    memcpy(buffer,msg,msglen);
    unsigned char* ptr;
    ptr = buffer;
    ptr += msglen;
    memcpy(ptr,digest,20);
    int len;
    EVP_EncryptUpdate(ctx,dest,&len,buffer,msglen+20);
 
    ciphertext_len = len;
  
    EVP_EncryptFinal_ex(ctx,dest+len,&len);

    ciphertext_len += len;
    ptr = dest + ciphertext_len;
    memcpy(ptr,iv,16);
    return ciphertext_len+16;
}
int decrypt_with_aes(EVP_CIPHER_CTX* ctx, unsigned char* encrypted,unsigned char* shared_key, size_t encrypted_len, unsigned char* dest){
    size_t cipher_len = encrypted_len - 16;
    unsigned char iv[16];
    unsigned char hmac[20];
    unsigned char ciphertext[cipher_len];
    unsigned char* ptr = encrypted;
    unsigned char buffer[4096];
    unsigned char computed_hmac[20];
    if(encrypted_len < 16){
        return -1;
    }
    ptr+=(encrypted_len-16);
    memcpy(iv,ptr,16);
    memcpy(ciphertext,encrypted,cipher_len);

    int dec_len;
    int len;
    EVP_DecryptInit_ex(ctx,EVP_aes_128_cbc(),NULL,shared_key,iv);

    if(!EVP_DecryptUpdate(ctx,buffer,&len,ciphertext,cipher_len)){
        //puts("Decrypting failed");
        return -1;
     }
    dec_len = len;
    if(!EVP_DecryptFinal_ex(ctx,buffer+len,&len)){
        //puts("Decrypting failed");
        return -1;
    }

    dec_len += len;

    memcpy(hmac,(buffer+(dec_len-20)),20);
    HMAC(EVP_sha1(), shared_key, 16,buffer,(dec_len-20),computed_hmac,NULL);
    if(memcmp(hmac,computed_hmac,20)!=0){
        //puts("Authentication Failed");
        dest = NULL;
        return -1;
    }
    
    memcpy(dest,buffer,dec_len-20);
    return dec_len-20;
}




