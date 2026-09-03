"""
shelf_life_examples.py — Pillar 2 (Shelf-Life Inference) corpus fixture.

See docs/SHELF_LIFE.md and tests/golden/shelf_life_manifest.json.

Three scenarios, each using a DIFFERENT hash algorithm so each crypto call
produces its own distinct CryptoAsset (same canonical name + same file would
otherwise merge multiple call sites' evidence onto one asset):

  1. hash_national_id() — SHA256.new(aadhaar_bytes): the identifier passed
     directly into the crypto call itself names the aadhaar category
     (ontology/data_sensitivity.yaml) via the `call_argument` candidate kind
     -> must produce a ShelfLifeFinding with category="aadhaar".

  2. cache_temp_value() — SHA512.new(temp_cache_value): a plain,
     non-sensitive-looking name, no enclosing class, no matching enclosing
     function name -> must produce NO ShelfLifeFinding at all (genuinely no
     signal found, never a silent generic_pii guess).

  3. CustomerRecord.hash_record() — SHA3_256.new(record_bytes): neither the
     call argument ("record_bytes") nor the method name ("hash_record") nor
     the class name ("CustomerRecord") is crypto-suggestive, so the only
     signal comes from CustomerRecord's own two dataclass fields
     (`model_field` candidate kind, class-scoped — see
     hash_patch/detect/shelf_life/data_context.py): aadhaar_number (aadhaar
     category) and account_number (financial_account category). Per
     hash_patch/analyze/shelf_life.py's longest-shelf-life-wins fail-safe
     rule, this must resolve to whichever of {aadhaar, financial_account}
     has the LONGER shelf_life_years in ontology/data_sensitivity.yaml — the
     test reads those actual numbers rather than assuming which one wins.
"""

from dataclasses import dataclass

from Crypto.Hash import SHA3_256, SHA256, SHA512


def hash_national_id(aadhaar_bytes):
    digest = SHA256.new(aadhaar_bytes)
    return digest.hexdigest()


def cache_temp_value(temp_cache_value):
    digest = SHA512.new(temp_cache_value)
    return digest.hexdigest()


@dataclass
class CustomerRecord:
    aadhaar_number: str
    account_number: str

    def hash_record(self, record_bytes):
        digest = SHA3_256.new(record_bytes)
        return digest.hexdigest()
