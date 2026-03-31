#include <stdio.h>
void vulnerable() {
    char buf[32];
    gets(buf);  // intentionally unsafe
}
int main() {
    vulnerable();
    return 0;
}