from ..crypto.registry import resolve
from ..crypto.signing import Signer


def build_payment(payload: bytes, customer_key: str, legacy_partner: bool = False):
    profile = "legacy" if legacy_partner else "customer"
    signer = Signer(profile)
    exchange = resolve(profile).exchange

    # The Python layer emits a source-level contract consumed by the Go gateway.
    return {
        "signature": signer.sign_contract(payload, customer_key),
        "exchange": exchange,
        "envelope": resolve(profile).envelope,
    }
