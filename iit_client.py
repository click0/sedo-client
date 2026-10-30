"""
Compatibility shim: this module moved to sedo.iit_client.

Run as a script it starts the same program as before; imported, it warns
(DeprecationWarning) and hands back sedo.iit_client itself.
"""

import importlib as _importlib
import sys as _sys
import warnings as _warnings

if __name__ == "__main__":
    # A script, as the documentation, the Ansible playbooks and Wine run it:
    # the same program, without a warning.
    from sedo.iit_client import main

    main()
else:
    _warnings.warn(
        "top-level module 'iit_client' is deprecated; use 'sedo.iit_client' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    # The module itself, not a copy: every name (the underscored ones too) and
    # every monkeypatch reach the real module.
    _sys.modules[__name__] = _importlib.import_module("sedo.iit_client")
