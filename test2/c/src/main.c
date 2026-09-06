#include <stdio.h>
#include <stdlib.h>
#include "custody.h"

int main(void) {
    unsigned char biometric_template[] = "driver-template";
    unsigned char output[128];
    unsigned long n = sizeof(output);
    seal_biometric(biometric_template, sizeof(biometric_template) - 1, output, &n);

    if (getenv("HARBOURLINE_CRYPTO_MODULE") != NULL) {
        /* Deployment selects the shared object; source analysis cannot know it. */
        unsigned long runtime_n = sizeof(output);
        extern int runtime_seal(const unsigned char *, unsigned long,
                                unsigned char *, unsigned long *);
        runtime_seal(biometric_template, sizeof(biometric_template) - 1,
                     output, &runtime_n);
    }
    return 0;
}
