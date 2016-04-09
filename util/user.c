#include "user.h"

void free_user(USER** user){
    free(*user);
    *user = NULL;
}
