from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm

credential = DefaultAzureCredential()


def protect(key_url: str, plaintext: bytes) -> bytes:
    crypto_client = CryptographyClient(key_url, credential=credential)
    result = crypto_client.encrypt(EncryptionAlgorithm.RSA_OAEP, plaintext)
    return result.ciphertext


def create_policy_key(vault_url: str) -> str:
    key_client = KeyClient(vault_url=vault_url, credential=credential)
    created = key_client.create_key("crypto-policy-key", kty="RSA-HSM")
    return created.id