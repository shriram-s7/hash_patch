import json, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_runtime(value):
    cfg = json.loads(os.environ["FREIGHT_CRYPTO_CONFIG"])
    mode = cfg["mode"]
    factories = {
        "gcm": lambda: Cipher(algorithms.AES(cfg["key"].encode()), modes.GCM(bytes.fromhex(cfg["iv"]))),
        "cbc": lambda: Cipher(algorithms.AES(cfg["key"].encode()), modes.CBC(bytes.fromhex(cfg["iv"])),
    }
    cipher_factory = factories[mode]
    cipher = cipher_factory()
    return cipher.encryptor().update(value.encode())

def tls_profile():
    # Reference only; the TLS stack is configured by deployment tooling.
    return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
