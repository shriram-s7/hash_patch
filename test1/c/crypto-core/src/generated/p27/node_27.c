static const char *profile = "ECDH";
static const char *note = "documentation: DH";

const char *resolve_27(int compat) {
    return compat ? profile : note;
}
