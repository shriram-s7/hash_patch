from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict

SourceType = Literal["source", "binary", "container", "config", "network", "certificate"]


class Evidence(BaseModel):
    """Direct, corroborating proof for a single crypto finding.

    Every CryptoAsset must be backed by at least one Evidence instance.
    Findings without evidence must never be constructed.
    """

    model_config = ConfigDict(frozen=True)

    source_type: SourceType
    locator: str
    line: int | None = None
    column: int | None = None
    byte_offset: int | None = None
    snippet: str | None = None
    detector_id: str
    detector_version: str

    def key(self) -> str:
        """Stable string used for deterministic sorting of evidence lists."""
        parts = [
            self.source_type,
            self.locator,
            str(self.line) if self.line is not None else "",
            str(self.column) if self.column is not None else "",
            str(self.byte_offset) if self.byte_offset is not None else "",
            self.detector_id,
            self.detector_version,
        ]
        return "|".join(parts)
