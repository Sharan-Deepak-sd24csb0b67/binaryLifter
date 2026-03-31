#include <stdio.h>
#include <string.h>

extern char *gets(char *str);

int main() {
    char buffer[100];
    char *ptr;

    ptr = gets(buffer);

    char *second_ptr = ptr;
    
    return (int)second_ptr[0]; 
}