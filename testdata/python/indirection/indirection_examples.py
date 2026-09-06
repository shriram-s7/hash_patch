import hashlib
import hmac


class CryptoConfig:
    def __init__(self, algo: str):
        self.algo = algo


def test_ternary(legacy: bool):
    algo = "sha1" if legacy else "sha256"
    return hashlib.new(algo)


def test_attribute(config: CryptoConfig):
    return hmac.new(b"secret", digestmod=config.algo)
