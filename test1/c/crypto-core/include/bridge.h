#ifndef BRIDGE_H
#define BRIDGE_H
const char *crypto_exchange_name(int compatibility);
int legacy_signature_path(const unsigned char *data, int len);
#endif
