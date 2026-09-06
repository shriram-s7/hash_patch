from .registry import resolve


class Signer:
    def __init__(self, profile: str):
        self.profile = resolve(profile)

    def algorithm(self) -> str:
        return self.profile.signing

    def sign_contract(self, payload: bytes, key_ref: str) -> dict:
        return {
            "algorithm": self.algorithm(),
            "key_ref": key_ref,
            "payload_digest": payload.hex()[:24],
        }
