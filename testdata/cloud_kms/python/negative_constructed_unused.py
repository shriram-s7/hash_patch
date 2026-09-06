import boto3


def init_kms(region_name: str = "us-east-1"):
    client = boto3.client("kms", region_name=region_name)
    print(f"kms client ready in {region_name}")