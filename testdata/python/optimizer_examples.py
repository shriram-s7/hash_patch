"""
optimizer_examples.py — Pillar 5 (Migration Optimiser) corpus fixture.

The existing accumulated testdata/python + testdata/java corpus (checked
before writing this file) has broken-by-shor findings, but none of them are
LIVE_EXTERNAL or carry real shelf-life data — every one defaults on both
axes, which makes for a flat, uninteresting risk-score spread. This file
adds LIVE_EXTERNAL (Flask `@app.route`) findings with real Pillar-2
shelf-life signal, giving the optimizer corpus genuine density variation
(see docs/OPTIMISER.md for the worked example this fixture set is built
around):

  - `export_aadhaar_record` (RSA) and `export_biometric_template_record`
    (X448): two CHEAP + HIGH-RISK findings -- live-external, with real,
    long shelf-life signal (`aadhaar` 27yr / `biometric` 50yr, the two
    longest categories in ontology/data_sensitivity.yaml) via their own
    function names, and no same-file blast-radius correlation (X448) or
    only the flat existing one (RSA -- see testdata/c/blast_radius_examples.c),
    so cost stays at the flat default. These get scheduled FIRST by any
    reasonable ordering.
  - `rotate_api_key_signing_key` / `rotate_access_token_signing_key` /
    `rotate_client_secret_signing_key` (DSA / Ed448 / DH): three CHEAP,
    MODERATE-RISK findings -- live-external, but a much shorter real
    shelf-life (`credentials`, 1 year -- these protect a rotatable secret,
    not personal data) via their own function names, and no blast-radius
    correlation -> flat default cost (0.5 days each). Three of them cost
    1.5 days combined -- LESS than the 2.5 days
    testdata/c/optimizer_expensive.c's single "expensive" ECDSA finding
    costs, yet their combined risk (1.0 each = 3.0) exceeds that finding's
    risk (1.5). This mismatch is what makes the greedy risk-density
    optimiser diverge from the naive risk-only ordering on this corpus at
    the right budget: naive prioritises that one pricier, higher-single-
    number finding, while greedy correctly recognises that the SAME
    budget spent on these three smaller ones eliminates more total risk.
    See docs/OPTIMISER.md.

    `credentials`'s short (1yr) real shelf-life also has a second effect:
    under EVERY one of ontology/quantum_arrival.yaml's 3 scenarios, these
    three findings' data will plausibly already be safe to disclose long
    before a CRQC arrives, so hash_patch/analyze/optimizer.py's scenario
    urgency discount applies to all three, in all three scenarios --
    unlike the "expensive" ECDSA finding (which has no real Pillar-2
    shelf-life at all -- C is out of scope for Pillar 2 -- so it is NEVER
    discounted, per the "never discount without real evidence" rule).
    That is deliberate: it keeps the same greedy-vs-naive divergence this
    fixture set demonstrates visible even in the SCENARIO-ADJUSTED numbers
    `hash_patch optimize` actually reports, not just the scenario-
    independent risk_score. See docs/OPTIMISER.md's worked example.

See also testdata/python/test_optimizer_low_value.py for this corpus's
deliberately INERT, no-signal "cheap + low risk" fixture.
"""

from cryptography.hazmat.primitives.asymmetric import dh, dsa, ed448, rsa, x448
from flask import Flask

app = Flask(__name__)


@app.route("/records/aadhaar/export")
def export_aadhaar_record(key_data):
    return rsa.import_public_key(key_data)


@app.route("/records/biometric/export")
def export_biometric_template_record():
    return x448.generate_key()


@app.route("/keys/api-key/rotate")
def rotate_api_key_signing_key(backend):
    return dsa.generate_private_key(key_size=2048, backend=backend)


@app.route("/keys/access-token/rotate")
def rotate_access_token_signing_key():
    return ed448.generate()


@app.route("/keys/client-secret/rotate")
def rotate_client_secret_signing_key(parameters):
    return dh.generate_private_key(parameters)
