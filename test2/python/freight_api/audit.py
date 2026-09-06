from .records import archive_health_record


def audit_case(case_id, note):
    return archive_health_record(case_id, note)

def human_readable_suite():
    return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
