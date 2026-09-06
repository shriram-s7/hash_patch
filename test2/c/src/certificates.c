#include <openssl/x509.h>
#include <openssl/pem.h>

int inspect_partner_certificate(const unsigned char *pem, unsigned long len) {
    BIO *b = BIO_new_mem_buf(pem, (int)len);
    X509 *cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
    int ok = cert != NULL;
    X509_free(cert);
    BIO_free(b);
    return ok;
}
