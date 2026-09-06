static const char *profile = "SHA1withRSA";
static const char *note = "documentation: SHA256withECDSA";

const char *resolve_43(int compat) {
    return compat ? profile : note;
}
