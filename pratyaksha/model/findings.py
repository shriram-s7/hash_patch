from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from pratyaksha.model.assets import CryptoAsset


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=False)

    target: str
    assets: list[CryptoAsset] = Field(default_factory=list)
    scan_started_at: datetime
    tool_version: str

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
