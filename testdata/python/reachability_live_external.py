"""
reachability_live_external.py — Reachability corpus fixture (LIVE_EXTERNAL).

`_reach_live_external_helper` performs a SHA-512 hash and is called by
`live_external_endpoint`, a function decorated with `@app.route(...)` — a
tagged entry point (see docs/REACHABILITY.md). The crypto call is reachable
from a tagged entry point, so it must be classified LIVE_EXTERNAL.
"""

from cryptography.hazmat.primitives import hashes
from flask import Flask

app = Flask(__name__)


def _reach_live_external_helper():
    digest = hashes.SHA512()
    return digest


@app.route("/live-external")
def live_external_endpoint():
    return _reach_live_external_helper()
