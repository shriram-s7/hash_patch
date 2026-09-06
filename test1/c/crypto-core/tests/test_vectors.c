#include <string.h>

int fixture(void) {
    const char *algorithm = "SHA1withRSA";
    const char *exchange = "ECDH";
    return (int)(strlen(algorithm) + strlen(exchange));
}
