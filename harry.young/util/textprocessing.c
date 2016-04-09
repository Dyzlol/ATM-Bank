#include "textprocessing.h"

// Check length of String
int is_too_long(char* str, int len){
    if(strlen(str) > len){
	    return 1;
    }
    return 0;
}

// Check str contains only alpha values
int is_only_letters(char* str){
	char * cursor = str;
	int arglen = strlen(str);
	int i;
	int invalid = 0;

	// Loop through string checking for non-alphabet chars
	for(i = 0; i < arglen && !invalid;i++,cursor++){
		char val = tolower(*cursor);
		if(val<97 || val>122){
			invalid = 1;
		}
	}
	return !invalid;
}

// Check str contains only num values
int is_only_numbers(char* str){
	char* cursor = str;
	int arglen = strlen(str);
	int i;
	int invalid = 0;

	// Loop through string checking for non-num chars
	for(i = 0; i < arglen && !invalid;i++,cursor++){
		//char val = tolower(*cursor);
		char val = *cursor;
		if(val<48 || val>57){
			invalid = 1;
		}
	}
	return !invalid;
}

// 
int is_greater_than(char* str, char* str_num){
    if(strlen(str) > strlen(str_num)){
		return 1;
	} else if(strlen(str) == strlen(str_num)){
	    int i = 0;
	    int check_next_digit = 1;
	    int invalid = 0;    
	    while(i < strlen(str) && check_next_digit){
	        int user_val = str[i] - '0';
	        int int_val = str_num[i] - '0';
	        
	        if(user_val > int_val){
	            //printf("%d,%d",user_val,int_val);
	            invalid = 1;
	            check_next_digit = 0;
	        } else if (user_val == int_val){
	            check_next_digit = 1;
	        } else {
	            check_next_digit = 0;
	        }
	        i++;
	    }
	    if(invalid){
	        return 1;
	    } else {
	        return 0;
	    }
	} else {
	    return 0;
	}
}
