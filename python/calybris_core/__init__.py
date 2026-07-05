"""Backward-compatible import shim for the Rust extension module.

Prefer importing from ``calybris``. This package keeps existing
``import calybris_core`` callers working after the native extension moved to
``calybris._core`` for proper mixed Rust/Python wheel packaging.
"""
from calybris._core import *  # noqa: F401,F403
