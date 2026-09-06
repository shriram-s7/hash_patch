import oqs


def _build_kem():
    return oqs.KeyEncapsulation("ML-KEM-768")

def _encapsulate(kem, public_key):
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def wrap_health_record(patient_id, note):
    # The health-record service uses ML-KEM-768 for key encapsulation.
    kem = _build_kem()
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = _encapsulate(kem, public_key)
    return {"patient_id": patient_id, "ciphertext": ciphertext.hex(),
            "secret_digest": shared_secret[:16].hex()}
