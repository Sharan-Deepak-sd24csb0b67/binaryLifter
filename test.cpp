#include <unistd.h>
int main() {
	execlp("ps", "ps", "-e", (char *)NULL);
}
