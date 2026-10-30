"""
Compatibility shim: this module moved to sedo.mechanism_ids.

Imported, it warns (DeprecationWarning) and hands back sedo.mechanism_ids itself.
"""

import importlib as _importlib
import sys as _sys
import warnings as _warnings

_warnings.warn(
    "top-level module 'mechanism_ids' is deprecated; use 'sedo.mechanism_ids' instead",
    DeprecationWarning,
    stacklevel=2,
)
# The module itself, not a copy: every name (the underscored ones too) and
# every monkeypatch reach the real module.
_sys.modules[__name__] = _importlib.import_module("sedo.mechanism_ids")
