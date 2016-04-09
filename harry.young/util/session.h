#ifndef __SESSION__
#define __SESSION__
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
typedef struct _SESSION{
    char username[251];
    time_t timestamp;
    unsigned char session_key[16];
    unsigned char account_no[16];
}SESSION;

void free_session(SESSION** session);
#endif

