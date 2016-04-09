#include "session.h"

void free_session(SESSION** session){
    if(*session != NULL){
        free(*session);
        *session = NULL;
    }
}
