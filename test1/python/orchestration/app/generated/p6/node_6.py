PROFILE = "SHA256withRSA"
NOTE = "documentation: SHA1withRSA"

def resolve(compat=False):
    if compat:
        return PROFILE
    return NOTE
