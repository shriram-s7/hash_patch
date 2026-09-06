import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def protect_pan(pan):
    salt = b"customer-pan-v2"
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=180_000)
    key = kdf.derive(os.environ["PAN_WRAP_PASSWORD"].encode())
    cipher = Cipher(algorithms.AES(key), modes.GCM(b"\x00" * 12))
    return cipher.encryptor().update(pan.encode()).hex()

def derive_operator_key(password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=b"operator-salt", iterations=200_000)
    return kdf.derive(password.encode())

def protect_health_note(note, password):
    key = derive_operator_key(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    return cipher.encryptor().update(note.encode())
