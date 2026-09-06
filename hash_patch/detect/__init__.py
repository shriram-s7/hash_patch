"""hash_patch/detect/__init__.py

Importing this package triggers side-effect registration of all concrete
detectors into the shared registry. Add a new detector module here once it
is ready so the CLI picks it up automatically.
"""

from __future__ import annotations

import hash_patch.detect.binary as _binary_detector  # noqa: F401

# Side-effect imports: each registers its detector into registry.
import hash_patch.detect.c as _c_detector  # noqa: F401
import hash_patch.detect.cloud_kms.go_cloud_kms as _go_cloud_kms_detector  # noqa: F401
import hash_patch.detect.cloud_kms.java_cloud_kms as _java_cloud_kms_detector  # noqa: F401
import hash_patch.detect.cloud_kms.python_cloud_kms as _python_cloud_kms_detector  # noqa: F401
import hash_patch.detect.go as _go_detector  # noqa: F401
import hash_patch.detect.java as _java_detector  # noqa: F401
import hash_patch.detect.python as _python_detector  # noqa: F401
from hash_patch.detect.base import registry

__all__ = ["registry"]
