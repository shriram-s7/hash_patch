from flask import Flask, jsonify, request

from .audit import audit_case
from .customer_crypto import protect_health_note, protect_pan
from .dispatch import prepare_manifest
from .runtime_crypto import encrypt_runtime
from .signing import issue_delivery_token
from .transport import choose_transport_cipher

app = Flask(__name__)

@app.post("/deliveries/token")
def delivery_token():
    payload = request.get_json()
    token = issue_delivery_token(payload["delivery_id"], payload["driver_id"])
    return jsonify({"token": token})

@app.post("/customers/pan")
def customer_pan():
    pan = request.form["pan"]
    return jsonify({"stored": protect_pan(pan)})

@app.post("/health/note")
def health_note():
    return jsonify({"stored": protect_health_note(
        request.form["clinical_note"], request.form["operator_password"]
    ).hex()})

@app.post("/manifest/digest")
def manifest():
    payload = request.get_data()
    legacy = request.args.get("legacy") == "1"
    return jsonify({"digest": prepare_manifest(legacy, payload).hex()})

@app.post("/runtime/encrypt")
def runtime_encrypt():
    return jsonify({"ciphertext": encrypt_runtime(request.get_data()).hex()})

@app.post("/audit/case")
def audit():
    return jsonify(audit_case(
        request.form["patient_id"], request.form["clinical_note"]
    ))

@app.get("/transport/cipher")
def transport_cipher():
    return jsonify({"suite": choose_transport_cipher(request.args.get("mode", "modern"))})
