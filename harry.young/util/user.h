#ifndef __USER__
#define __USER__
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

typedef struct _USER{
    unsigned char account_no[16];
    char name[251];
    unsigned int balance;
    char PIN[5];
    int num_tries;
    int account_locked;
}USER;

void free_user(USER ** user);
#endif
