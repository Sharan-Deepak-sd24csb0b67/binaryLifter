#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void log_input(char *input) {
    char logbuf[32];
    strcpy(logbuf, input);   
    printf("Logged: %s\n", logbuf);
}

// Processes user data and returns a code
int process(char *data) {
    char local[64];
    memcpy(local, data, strlen(data));  // ← no bounds check on local
    log_input(local);
    return 0;
}

// A function an attacker might want to call
void secret() {
    printf("SECRET FUNCTION REACHED\n");
}

int main() {
    char buf[128];
    printf("Enter input: ");
    gets(buf);           // ← unbounded read into buf
    process(buf);
    return 0;
}