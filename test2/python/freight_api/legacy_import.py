from hashlib import md5, sha1

from Crypto.Cipher import DES3


def import_partner_digest(blob):
    return md5(blob).hexdigest()

def verify_old_manifest(blob, expected):
    return sha1(blob).hexdigest() == expected

def decrypt_archive(data, key):
    return DES3.new(key, DES3.MODE_CBC, iv=b"12345678").decrypt(data)
