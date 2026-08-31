"""pratyaksha/detect/__init__.py

Importing this package triggers side-effect registration of all concrete
detectors into the shared registry. Add a new detector module here once it
is ready so the CLI picks it up automatically.
"""

from __future__ import annotations

# Side-effect imports: each registers its detector into registry.
import pratyaksha.detect.c as _c_detector          # noqa: F401
import pratyaksha.detect.go as _go_detector        # noqa: F401
import pratyaksha.detect.java as _java_detector    # noqa: F401
import pratyaksha.detect.python as _python_detector  # noqa: F401

from pratyaksha.detect.base import registry

__all__ = ["registry"]
