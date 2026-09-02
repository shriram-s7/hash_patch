import ssl


def create_secure_context() -> ssl.SSLContext:
    ssl_context = ssl.create_default_context()
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
    return ssl_context
