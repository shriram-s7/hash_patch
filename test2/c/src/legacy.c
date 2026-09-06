#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/md5.h>

void legacy_fingerprint(const unsigned char *data, unsigned long len,
                        unsigned char *out) {
    MD5(data, len, out);
}

int legacy_encrypt(const unsigned char *in, unsigned char *out,
                   const unsigned char *key) {
    DES_key_schedule ks;
    DES_set_key_unchecked((const_DES_cblock *)key, &ks);
    DES_cblock input, output;
    memcpy(input, in, 8);
    DES_ecb_encrypt(&input, &output, &ks, DES_ENCRYPT);
    memcpy(out, output, 8);
    return 8;
}
