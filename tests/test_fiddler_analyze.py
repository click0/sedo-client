"""
S2: scripts/fiddler_analyze.py must not echo the token PIN from a capture.
"""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "fiddler_analyze", ROOT / "scripts" / "fiddler_analyze.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_saz(path: Path, method: str, params) -> Path:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    request = (
        "POST /json-rpc HTTP/1.1\r\n"
        "Host: 127.0.0.1:8081\r\n"
        "Content-Type: application/json\r\n"
        "\r\n" + body
    )
    response = "HTTP/1.1 200 OK\r\n\r\n{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":null}"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("raw/1_c.txt", request)
        zf.writestr("raw/1_s.txt", response)
    return path


def test_read_private_key_pin_redacted(tmp_path, capsys):
    saz = _make_saz(tmp_path / "cap.saz", "ReadPrivateKey",
                    [{"devIndex": 0, "typeIndex": 7}, "9876"])
    _load_script().analyze(saz)
    out = capsys.readouterr().out
    assert "9876" not in out
    assert "ReadPrivateKey" in out
    assert "[***]" in out


def test_non_secret_method_params_shown(tmp_path, capsys):
    saz = _make_saz(tmp_path / "cap.saz", "GetOwnCertificate", [7])
    _load_script().analyze(saz)
    out = capsys.readouterr().out
    assert "GetOwnCertificate([7])" in out


def test_redaction_set_matches_iit_client():
    """scripts/ duplicates the set — keep it in sync with iit_client."""
    import iit_client
    assert _load_script()._REDACTED_METHODS == iit_client._REDACTED_METHODS
