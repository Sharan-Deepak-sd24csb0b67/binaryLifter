
#include <stdio.h>
#include <string.h>

void greet(char *input) {
    char buf[64];
    strcpy(buf, input);        // taint source 1
    printf("Hello, %s\n", buf);
}

int main() {
    char name[128];
    gets(name);                // taint source 2
    greet(name);
    return 0;
}
