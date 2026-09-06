import boto3


class DataProtector:
    def __init__(self, region: str = "us-east-1"):
        self.kms_client = boto3.client("kms", region_name=region)

    def protect(self, plaintext: bytes) -> bytes:
        response = self.kms_client.encrypt(KeyId="alias/protect", Plaintext=plaintext)
        return response["CiphertextBlob"]

    def unprotect(self, blob: bytes) -> bytes:
        response = self.kms_client.decrypt(CiphertextBlob=blob)
        return response["Plaintext"]