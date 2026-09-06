from .pq_client import wrap_health_record


def archive_health_record(patient_id, note):
    return wrap_health_record(patient_id, note)

def local_audit_digest(text):
    from hashlib import sha256
    return sha256(text.encode()).hexdigest()
