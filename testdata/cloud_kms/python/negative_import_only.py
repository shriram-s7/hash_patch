import boto3


def get_client(region_name: str = "us-west-2"):
    return boto3.client("kms", region_name=region_name)