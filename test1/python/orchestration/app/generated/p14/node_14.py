PROFILE = "SHA256withECDSA"
NOTE = "documentation: ECDH"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
