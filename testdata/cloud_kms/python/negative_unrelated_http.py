import requests


def upload(params: dict) -> int:
    encrypt = "encrypt"
    key = "campaign-key"
    payload = {"key": key, "algorithm": encrypt, **params}
    response = requests.post("https://api.example.com/v1/keys", json=payload, timeout=5)
    return response.status_code