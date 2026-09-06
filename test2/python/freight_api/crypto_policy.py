from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, dsa, ec, rsa

SUPPORTED = {
    "parcel": "RSA",
    "session": "ECDH",
    "vendor": "DSA",
    "legacy": "RSA",
    "unused": "RC4",
}

def make_key(kind):
    algorithm = SUPPORTED[kind]
    if algorithm == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=1024)
    if algorithm == "ECDH":
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "DSA":
        return dsa.generate_private_key(key_size=2048)
    return dh.generate_parameters(generator=2, key_size=2048)

def manifest_digest(legacy, payload):
    algorithm = hashes.SHA1 if legacy else hashes.SHA256
    digest = algorithm()
    from cryptography.hazmat.primitives import hashes as _hashes
    h = _hashes.Hash(digest)
    h.update(payload)
    return h.finalize()
