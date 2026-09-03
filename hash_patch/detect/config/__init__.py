"""hash_patch/detect/config — Configuration layer detectors (Pillar 4)."""

from hash_patch.detect.config.source_tls_intent import detect_source_tls_intent
from hash_patch.detect.config.tls_config import detect_tls_config_file

__all__ = ["detect_source_tls_intent", "detect_tls_config_file"]
