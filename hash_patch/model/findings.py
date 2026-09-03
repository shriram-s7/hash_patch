from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from hash_patch.model.assets import CryptoAsset
from hash_patch.model.blast_radius import BlastRadiusFinding
from hash_patch.model.config_finding import ContradictionFinding, TlsConfigFinding
from hash_patch.model.shelf_life import ShelfLifeFinding


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=False)

    target: str
    assets: list[CryptoAsset] = Field(default_factory=list)
    scan_started_at: datetime
    tool_version: str
    # Pillar 3 (Blast Radius) findings — see hash_patch/analyze/blast_radius.py.
    # Not part of the CBOM document's own schema; the ones with a real
    # correlated CryptoAsset are also mirrored onto that asset's `properties`
    # (hash_patch.cli.run_scan), the same way reachability is. This list is
    # what the CLI summary line and any future report consumer read from.
    blast_radius_findings: list[BlastRadiusFinding] = Field(default_factory=list)
    # Pillar 2 (Shelf-Life Inference) findings — see
    # hash_patch/analyze/shelf_life.py and docs/SHELF_LIFE.md. Every finding
    # here always has a real correlated CryptoAsset (unlike blast radius's
    # db_column fallback) and is mirrored onto that asset's `properties`.
    shelf_life_findings: list[ShelfLifeFinding] = Field(default_factory=list)
    # Pillar 4 (Cross-Layer Contradictions) findings — see
    # hash_patch/analyze/contradictions.py and docs/CONTRADICTIONS.md.
    tls_config_findings: list[TlsConfigFinding] = Field(default_factory=list)
    contradiction_findings: list[ContradictionFinding] = Field(default_factory=list)

    def add_asset(self, asset: CryptoAsset) -> None:
        """Add an asset, merging into an existing one with the same id.

        Merging unions the evidence lists (deduplicated and stably sorted by
        Evidence.key()) rather than discarding either side's proof.
        """
        for existing in self.assets:
            if existing.id == asset.id:
                seen = {e.key() for e in existing.evidence}
                for ev in asset.evidence:
                    if ev.key() not in seen:
                        existing.evidence.append(ev)
                        seen.add(ev.key())
                existing.evidence.sort(key=lambda e: e.key())
                for key, value in asset.properties.items():
                    existing.properties.setdefault(key, value)
                return
        self.assets.append(asset)

    def sorted_assets(self) -> list[CryptoAsset]:
        """Return assets in a stable, deterministic order (sorted by id)."""
        return sorted(self.assets, key=lambda a: a.id)
