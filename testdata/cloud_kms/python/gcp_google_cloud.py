from google.cloud import kms


def seal(key_name: str, plaintext: bytes) -> bytes:
    client = kms.KeyManagementServiceClient()
    request = kms.EncryptRequest(name=key_name, plaintext=plaintext)
    response = client.encrypt(request=request)
    return response.ciphertext


def unseal(key_name: str, blob: bytes) -> bytes:
    client = kms.KeyManagementServiceClient()
    request = kms.DecryptRequest(name=key_name, ciphertext=blob)
    response = client.decrypt(request=request)
    return response.plaintext