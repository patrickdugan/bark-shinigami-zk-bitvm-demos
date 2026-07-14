"""Namespace shim that selects Garaga's pure-Python hint path.

The pinned Windows wheel contains an unusable historical Rust extension. The
showcase only needs deterministic off-chain MSM hint construction, for which
Garaga already ships a pure-Python implementation. Cairo rechecks the hints.
"""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)

from . import garaga_rs

__all__ = ["garaga_rs"]
