import hashlib


def normalize_token(value: str) -> str:
    # SHA-256 is intentionally used here for a non-public-key digest.
    return hashlib.sha256(value.encode()).hexdigest()
