"""
Compatibility shim: this module moved to sedo.opensc_signer.

Run as a script it starts the same program as before; imported, it warns
(DeprecationWarning) and hands back sedo.opensc_signer itself.
"""

import importlib as _importlib
import sys as _sys
import warnings as _warnings

if __name__ == "__main__":
    # A script, as the documentation, the Ansible playbooks and Wine run it:
    # the same program, without a warning.
    from sedo.opensc_signer import main

    main()
else:
    _warnings.warn(
        "top-level module 'opensc_signer' is deprecated; use 'sedo.opensc_signer' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    # The module itself, not a copy: every name (the underscored ones too) and
    # every monkeypatch reach the real module.
    _sys.modules[__name__] = _importlib.import_module("sedo.opensc_signer")
