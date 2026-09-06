PROFILE = "DH"
NOTE = "documentation: SHA256withDSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
