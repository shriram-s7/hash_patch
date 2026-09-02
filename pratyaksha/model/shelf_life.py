from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pratyaksha.model.evidence import Evidence

DataContextCandidateKind = Literal[
    "call_argument", "enclosing_function", "enclosing_class", "model_field"
]
ShelfLifeLanguage = Literal["python", "java"]
ShelfLifeConfidence = Literal["high", "medium"]


class DataContextMatch(BaseModel):
    """A heuristic, name-pattern-only signal that a candidate identifier found
    near a crypto call site matches a data-sensitivity category from
    ontology/data_sensitivity.yaml.

    Four candidate kinds (pratyaksha/detect/shelf_life/data_context.py):
      - call_argument:      a plain-identifier argument of the crypto call
                             itself (e.g. `SHA256.new(aadhaar_bytes)`).
      - enclosing_function:  the name of the function/method containing the
                             crypto call.
      - enclosing_class:     the name of the class containing that function.
      - model_field:         a dataclass/pydantic field name (Python) or a
                             class field/getter name (Java) declared in the
                             SAME CLASS as the crypto call — see the module
                             docstring on data_context.py for why this is
                             class-scoped rather than file-wide.

    This is deliberately NOT a CryptoAsset and NOT tied to a specific
    CryptoAsset id — correlating it with a real CryptoAsset (same file AND
    same call-site line only — see docs/SHELF_LIFE.md) is
    pratyaksha/analyze/shelf_life.py's job, the same separation of concerns
    pratyaksha/model/blast_radius.py's SizeConstraint uses for Pillar 3.

    `evidence[0].line` is ALWAYS the line of the crypto call site this match
    was found near, NOT necessarily the line where the matched identifier
    itself is declared (e.g. a model_field match's field may be declared on
    a different line than the call it's being associated with). This is a
    deliberate design choice: it lets pratyaksha/analyze/shelf_life.py
    correlate a DataContextMatch to a CryptoAsset via simple, honest exact
    (locator, line) equality against the asset's own evidence — the same
    anti-cross-contamination rigor pratyaksha/analyze/blast_radius.py's
    nearest-by-line rule provides for Pillar 3, without a second distance
    heuristic. `evidence[0].snippet` always names the actual matched
    identifier and, for model_field, where it was declared, so that real
    location is never lost — just not used as the correlation key. See
    docs/SHELF_LIFE.md.

    This is a heuristic, not a real dataflow analysis: candidate identifiers
    are matched by case-insensitive substring only, never traced through
    assignments, renames, or across function-call boundaries. See
    docs/SHELF_LIFE.md.
    """

    model_config = ConfigDict(frozen=False)

    category: str  # ontology/data_sensitivity.yaml category key, e.g. "aadhaar"
    matched_identifier: str
    matched_pattern: str
    candidate_kind: DataContextCandidateKind
    language: ShelfLifeLanguage
    evidence: list[Evidence] = Field(default_factory=list)


class ShelfLifeFinding(BaseModel):
    """The Pillar 2 (Shelf-Life Inference) output: an assignment of how long
    data protected by `asset_id`/`asset_name` must remain confidential,
    derived from same-file, same-call-site DataContextMatch signal(s) — see
    pratyaksha/analyze/shelf_life.py and docs/SHELF_LIFE.md.

    When more than one category matches the same crypto call (e.g. both an
    aadhaar-pattern and a financial_account-pattern identifier are present),
    the category with the LONGEST `shelf_life_years` wins — a fail-safe:
    always assume the more sensitive/longer-lived category on ambiguity,
    never the shorter one. See pratyaksha/analyze/shelf_life.py.

    `mosca_note` is a descriptive, human-readable string only — it does NOT
    implement the full Mosca-inequality comparison against a
    quantum-arrival estimate (that needs Pillar 5's Monte Carlo work,
    planned separately).
    """

    model_config = ConfigDict(frozen=False)

    asset_id: str
    asset_name: str
    category: str
    shelf_life_years: int
    statutory_basis: str
    confidence: ShelfLifeConfidence
    evidence: list[Evidence] = Field(default_factory=list)
    mosca_note: str
