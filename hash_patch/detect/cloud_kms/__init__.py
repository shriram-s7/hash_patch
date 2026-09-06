"""hash_patch/detect/cloud_kms/ — Phase 1: Cloud KMS/HSM client-side usage
detection (Python, Java, Go).

HONEST FRAMING (read before using any finding from this package for
anything): this detects code that CALLS a cloud key-management/HSM service
client. It does NOT and structurally CANNOT verify what the cloud provider
actually does on the other side of that API call — which algorithm it
uses, how the key is actually protected, whether the provider has already
migrated to PQC. Every finding here is "cloud-managed key usage detected",
never "cloud infrastructure scanned" or "KMS configuration verified" — see
CLAUDE.md's "Cloud KMS" section. This is why every finding carries
`hash_patch:property.cloudKey.verificationScope = "client_call_only"`
(never omitted) and why `quantum_status` is always
`QuantumStatus.ALGORITHM_OPAQUE` (hash_patch/model/assets.py) rather than a
guessed broken-by-shor/weakened-by-grover/quantum-safe/broken-classically
value — a static scanner has no way to know the provider-side algorithm,
and must never pretend otherwise.

C is deliberately NOT covered. Cloud SDKs are rare in C directly, and the
realistic alternative — a C service calling a cloud KMS over a generic
HTTP/REST client (e.g. libcurl hitting a KMS-shaped URL) — has no reliable
structural signal to key detection off (unlike a language-specific SDK
client-constructor call, "an HTTP call whose URL looks KMS-ish" is exactly
the over-broad, name/shape-guessing heuristic that produced real false
positives earlier in this project's own reference-detection and
shelf-life work — see the biometric "fingerprint" pattern history in
ontology/data_sensitivity.yaml). Zero C coverage is reported explicitly
here rather than forcing a weak heuristic to fill the gap.

Detectors in this package ARE registered into hash_patch.detect.registry
(unlike hash_patch/detect/blast_radius/, which is not) — a cloud-key
operation finding is a real CryptoAsset, evidence-backed, reachable exactly
like any other OPERATION finding (see hash_patch/analyze/reachability.py;
this package intentionally does NOT special-case its own Evidence.source_type,
so the existing Python/Java call-graph reachability classification applies
to it automatically, no separate wiring needed). Pillar 3 (Blast Radius) and
Pillar 5 (Migration Optimiser) both only ever consider
`QuantumStatus.BROKEN_BY_SHOR` assets, so a cloud-key finding
(`QuantumStatus.ALGORITHM_OPAQUE`) is automatically excluded from both,
with no separate exclusion logic required. Pillar 2 (Shelf-Life) applies
normally when a cloud-key call genuinely sits near DPDP-relevant
sensitive-data naming — same ontology, no separate mechanism.
"""

from __future__ import annotations
