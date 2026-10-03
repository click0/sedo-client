"""
opensc backend: the CKA_ID comes from the token (`--list-objects`), "01" is
only the fallback. Output shapes are verbatim OpenSC 0.25 (SoftHSM2 run).
"""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from opensc_signer import OpenSCSigner, parse_objects, select_cert_id

TWO_PAIRS = """\
Using slot 0 with a present token (0x8ff34ca)
Private Key Object; EC
  label:      sign
  ID:         01
  Usage:      decrypt, sign, signRecover, unwrap, derive
  Access:     sensitive, always sensitive, never extractable, local
Private Key Object; EC
  label:      enc
  ID:         02
  Usage:      decrypt, unwrap, derive
  Access:     sensitive, always sensitive, never extractable, local
Certificate Object; type = X.509 cert
  label:      sign-cert
  subject:    DN: CN=sedo-test
  serial:     7EDC4FEB174D2865B56048B8D947496F7E532C56
  ID:         01
Public Key Object; EC  EC_POINT 256 bits
  EC_POINT:   044104a4ff
  EC_PARAMS:  06082a8648ce3d030107 (OID 1.2.840.10045.3.1.7)
  label:      sign
  ID:         01
  Usage:      encrypt, verify, verifyRecover, wrap, derive
  Access:     local
Certificate Object; type = X.509 cert
  label:      enc-cert
  subject:    DN: CN=enc
  ID:         02
"""


class TestParseObjects:
    def test_kinds_ids_labels_usage(self):
        objs = parse_objects(TWO_PAIRS)
        assert [(o["kind"], o["id"]) for o in objs] == [
            ("private_key", "01"), ("private_key", "02"), ("certificate", "01"),
            ("public_key", "01"), ("certificate", "02")]
        assert objs[0]["label"] == "sign"
        assert objs[0]["usage"] == ("decrypt", "sign", "signRecover", "unwrap", "derive")
        assert objs[4]["usage"] == ()

    def test_ids_are_normalised_to_lower_case(self):
        assert parse_objects("Certificate Object; type = X.509 cert\n  ID:         0A\n")[0]["id"] == "0a"

    def test_empty_output(self):
        assert parse_objects("") == []
        assert parse_objects("Using slot 0 with a present token (0x0)\n") == []


class TestSelectCertId:
    def test_signing_pair_wins_over_encryption_pair(self):
        assert select_cert_id(parse_objects(TWO_PAIRS)) == "01"

    def test_the_only_pair_is_used_whatever_its_id(self):
        """The Avtor question: a token whose single pair is under id 02."""
        text = TWO_PAIRS.replace("  ID:         01\n", "  ID:         77\n", 1)   # key 01 → 77
        assert select_cert_id(parse_objects(text)) == "02"

    def test_several_signing_pairs_take_the_first_with_a_warning(self, caplog):
        text = TWO_PAIRS.replace("Usage:      decrypt, unwrap, derive",
                                 "Usage:      decrypt, sign, unwrap, derive")
        assert select_cert_id(parse_objects(text)) == "01"
        assert "Several key/certificate pairs" in caplog.text

    def test_no_pair_falls_back_with_a_warning(self, caplog):
        only_keys = "Private Key Object; EC\n  ID:         05\n  Usage:      sign\n"
        assert select_cert_id(parse_objects(only_keys)) == "01"
        assert select_cert_id(parse_objects(only_keys), fallback="09") == "09"
        assert "No private key shares a CKA_ID" in caplog.text

    def test_pair_without_sign_usage_still_pairs(self):
        text = TWO_PAIRS.replace("decrypt, sign, signRecover, unwrap, derive", "decrypt, unwrap")
        assert select_cert_id(parse_objects(text)) == "01"   # first paired key


def _signer(tmp_path, **kw):
    tool = tmp_path / "pkcs11-tool"
    tool.write_bytes(b"fake")
    module = tmp_path / "PKCS11.dll"
    module.write_bytes(b"fake")
    s = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool), **kw)
    s.login("1234")
    return s


def _runner(list_objects_text: str, calls: list):
    def fake_run(cmd, **kwargs):
        args = list(cmd)
        calls.append(args)
        if "--list-objects" in args:
            return subprocess.CompletedProcess(args, 0, stdout=list_objects_text.encode(), stderr=b"")
        Path(args[args.index("--output-file") + 1]).write_bytes(b"\x30\x01")
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")
    return fake_run


class TestSignerUsesTokenId:
    @patch("opensc_signer.subprocess.run")
    def test_certificate_and_signature_use_the_detected_id(self, mock_run, tmp_path):
        text = TWO_PAIRS.replace("  ID:         01\n", "  ID:         77\n", 1)   # only pair = 02
        calls = []
        mock_run.side_effect = _runner(text, calls)
        s = _signer(tmp_path)
        s.get_certificate()
        s.sign(b"data")
        ids = [a[a.index("--id") + 1] for a in calls if "--id" in a]
        assert ids == ["02", "02"]
        assert sum("--list-objects" in a for a in calls) == 1     # detected once

    @patch("opensc_signer.subprocess.run")
    def test_explicit_cert_id_skips_detection(self, mock_run, tmp_path):
        calls = []
        mock_run.side_effect = _runner(TWO_PAIRS, calls)
        _signer(tmp_path, cert_id="05").get_certificate()
        assert not any("--list-objects" in a for a in calls)
        assert calls[0][calls[0].index("--id") + 1] == "05"

    @patch("opensc_signer.subprocess.run")
    def test_wrong_pin_costs_one_attempt_and_nothing_is_signed(self, mock_run, tmp_path):
        mock_run.return_value = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"CKR_PIN_INCORRECT")
        s = _signer(tmp_path)
        with pytest.raises(RuntimeError, match="list-objects failed"):
            s.sign(b"data")
        assert mock_run.call_count == 1

    @patch("opensc_signer.subprocess.run")
    def test_logout_forgets_the_detected_id(self, mock_run, tmp_path):
        calls = []
        mock_run.side_effect = _runner(TWO_PAIRS, calls)
        s = _signer(tmp_path)
        s.get_certificate()
        s.logout()
        s.login("1234")
        s.get_certificate()
        assert sum("--list-objects" in a for a in calls) == 2
        s2 = _signer(tmp_path, cert_id="03")
        s2.logout()
        assert s2._cert_id == "03"
