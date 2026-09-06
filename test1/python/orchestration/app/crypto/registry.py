from dataclasses import dataclass


@dataclass(frozen=True)
class CryptoProfile:
    signing: str
    exchange: str
    envelope: str

PROFILES = {
    "modern": CryptoProfile("ECDSA", "ECDH", "AES-GCM"),
    "customer": CryptoProfile("RSA", "ECDH", "AES-GCM"),
    "legacy": CryptoProfile("SHA1withRSA", "DH", "AES-CBC"),
}

def resolve(name: str) -> CryptoProfile:
    return PROFILES.get(name, PROFILES["customer"])
