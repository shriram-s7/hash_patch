import hashlib
import hmac


def digest(payload: bytes, legacy: bool = False) -> bytes:
    # A hash occurrence must not automatically be classified as public-key crypto.
    algorithm = hashlib.sha1 if legacy else hashlib.sha256
    return algorithm(payload).digest()

def mac(payload: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, payload, hashlib.sha256).digest()
