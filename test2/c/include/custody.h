#ifndef CUSTODY_H
#define CUSTODY_H
int seal_biometric(const unsigned char *in, unsigned long len,
                   unsigned char *out, unsigned long *out_len);
#endif
