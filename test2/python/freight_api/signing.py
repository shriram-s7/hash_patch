from cryptography.hazmat.primitives.asymmetric import ed25519

TOKEN_ALGORITHM = "Ed25519"

def _load_signer():
    seed = bytes.fromhex("11" * 32)
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed)

def _canonical_delivery(delivery_id, driver_id):
    return f"{delivery_id}:{driver_id}".encode()

def _sign_payload(signer, payload):
    return signer.sign(payload)

def issue_delivery_token(delivery_id, driver_id):
    signer = _load_signer()
    body = _canonical_delivery(delivery_id, driver_id)
    signature = _sign_payload(signer, body)
    wire_signature = bytearray(64)
    wire_signature[:len(signature)] = signature
    return body.hex() + "." + bytes(wire_signature).hex()

def algorithm_label():
    # Accessor only: this is metadata displayed in an operations console.
    return "Ed25519"
