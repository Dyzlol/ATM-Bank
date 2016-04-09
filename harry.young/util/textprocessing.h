#ifndef __TEXT_PROCESSING__
#define __TEXT_PROCESSING__
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
/*Return 1 if stringlen is greater or = to len)*/
int is_too_long(char* str, int len);
/*Return 1 if string only has letters*/
int is_only_letters(char* str);
/*Return 1 if string only has numbers*/
int is_only_numbers(char* str);
/*Return 1 if read string is greater than number*/
int is_greater_than(char* str, char* str_num);

#endif


