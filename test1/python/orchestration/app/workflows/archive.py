from ..crypto.wrappers import digest


def archive_record(blob: bytes):
    # Historical format marker; this is a real SHA-1 operation.
    checksum = digest(blob, legacy=True)
    return {"checksum": checksum.hex(), "format": "archive-v1"}
