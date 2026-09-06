static const char *profile = "SHA256withDSA";
static const char *note = "documentation: SHA256withRSA";

const char *resolve_59(int compat) {
    return compat ? profile : note;
}
