"""hash_patch/qa/registry.py — In-memory scan-resolution registry

Maintains the association between internal scan identifiers, CycloneDX CBOM
serial numbers, raw CBOMs, parsed ScanIndexes, and scan-scoped conversation contexts.

Architectural principles:
- Internal scan identity (scan_id) and CycloneDX serialNumber are conceptually
  separate fields, even if they share the same initial string value.
- Conversations are scoped to (scan_id, conversation_id), preventing conversation
  history leakage across different scans.
- Unresolved scan_ids never silently fall back to an unrelated scan.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from hash_patch.qa.index import ScanIndex
from hash_patch.qa.query import ConversationContext


@dataclass
class ScanRecord:
    """Represents a registered scan with all associated artefacts."""

    scan_id: str
    cbom: dict[str, Any]
    serial_number: str | None = None
    created_at: float = field(default_factory=time.time)
    plan: dict[str, Any] | None = None
    index: ScanIndex | None = None

    def get_or_build_index(self) -> ScanIndex:
        if self.index is None:
            self.index = ScanIndex.from_cbom(self.cbom, self.plan, scan_id=self.scan_id)
        return self.index


class ScanRegistry:
    """In-memory registry for scans and scan-scoped conversations."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}
        self._by_serial: dict[str, str] = {}
        self._latest_scan_id: str | None = None
        self._conversations: dict[tuple[str, str], ConversationContext] = {}

    def register_scan(
        self,
        cbom: dict[str, Any],
        plan: dict[str, Any] | None = None,
        scan_id: str | None = None,
    ) -> ScanRecord:
        """Registers a CBOM (and optional migration plan) in the registry."""
        serial_number = cbom.get("serialNumber") if isinstance(cbom, dict) else None

        # Determine scan_id: explicit > serialNumber > new random UUID
        resolved_scan_id = scan_id or serial_number or f"scan_{uuid4().hex[:12]}"

        # If already registered with this scan_id, update plan if provided
        if resolved_scan_id in self._scans:
            rec = self._scans[resolved_scan_id]
            if plan is not None:
                rec.plan = plan
                rec.index = None  # Rebuild on next access
            self._latest_scan_id = resolved_scan_id
            return rec

        record = ScanRecord(
            scan_id=resolved_scan_id,
            cbom=cbom,
            serial_number=serial_number,
            plan=plan,
        )

        self._scans[resolved_scan_id] = record
        if serial_number:
            self._by_serial[serial_number] = resolved_scan_id
        self._latest_scan_id = resolved_scan_id
        return record

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        """Resolves a scan by its scan_id or serialNumber."""
        if scan_id in self._scans:
            return self._scans[scan_id]
        if scan_id in self._by_serial:
            target_id = self._by_serial[scan_id]
            return self._scans.get(target_id)
        return None

    def get_latest_scan(self) -> ScanRecord | None:
        """Returns the most recently registered scan, if any."""
        if self._latest_scan_id and self._latest_scan_id in self._scans:
            return self._scans[self._latest_scan_id]
        return None

    def get_conversation(
        self,
        scan_id: str,
        conversation_id: str,
    ) -> ConversationContext:
        """Retrieves or creates a ConversationContext scoped to (scan_id, conversation_id)."""
        key = (scan_id, conversation_id)
        if key not in self._conversations:
            self._conversations[key] = ConversationContext()
        return self._conversations[key]

    def clear(self) -> None:
        """Clears all stored scans and conversations (used in tests)."""
        self._scans.clear()
        self._by_serial.clear()
        self._latest_scan_id = None
        self._conversations.clear()


# Global singleton registry for the service process
GLOBAL_SCAN_REGISTRY = ScanRegistry()
