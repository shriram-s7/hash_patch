#include <stdlib.h>
#include <dlfcn.h>

typedef int (*seal_fn)(const unsigned char *, unsigned long,
                       unsigned char *, unsigned long *);

int runtime_seal(const unsigned char *input, unsigned long len,
                 unsigned char *output, unsigned long *out_len) {
    const char *module = getenv("HARBOURLINE_CRYPTO_MODULE");
    void *handle = dlopen(module, RTLD_NOW);
    seal_fn fn = (seal_fn)dlsym(handle, "seal_biometric");
    return fn(input, len, output, out_len);
}
