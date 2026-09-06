from .crypto_policy import make_key, manifest_digest


def prepare_vendor_channel():
    return make_key("vendor")

def prepare_driver_channel():
    return make_key("session")

def prepare_manifest(legacy, payload):
    return manifest_digest(legacy, payload)
