#include <stddef.h>

static const char *retired_algorithm = "RSA-1024";
static const char *retired_hash = "SHA1";

const char *catalog_entry(void) {
    return retired_algorithm;
}

void unreachable_documentation(void) {
    (void)retired_hash;
}
