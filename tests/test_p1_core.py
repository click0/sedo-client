"""
Regression tests for the v0.31 P1 core audit: signing results, auth-flow
robustness, and the PKCS#11 session lifecycle (slot, CKA_ID pairing, leaks).

All mocked — the PKCS#11 tests run on the ``fake_pykcs11`` fixture.
"""

import base64
import logging
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from iit_client import IITClient, IITRPCError
from sedo_client import SEDOClient

DER = b"\x30\x82\x01\x00" + b"\xab" * 20


def _iit():
    with patch("iit_client.requests.Session"):
        return IITClient()


def _iit_envelope(body):
    """An IITClient whose transport returns ``body`` as the JSON envelope."""
    with patch("iit_client.requests.Session") as S:
        sess = MagicMock()
        S.return_value = sess
        sess.post.return_value = MagicMock(status_code=200, text="", json=lambda: body)
        return IITClient()


# ─── 1. Signing results are always bytes, correctly decoded ──

class TestSignatureDecoding:
    @pytest.mark.parametrize("label,result", [
        ("base64", base64.b64encode(DER).decode()),
        ("hex", DER.hex()),
        ("HEX", DER.hex().upper()),
        ("mime-wrapped base64", base64.encodebytes(DER).decode()),
        ("dict signature", {"signature": base64.b64encode(DER).decode()}),
        ("dict data hex", {"data": DER.hex()}),
        ("raw bytes", DER),
    ])
    def test_sign_data_accepts_every_encoding(self, label, result):
        c = _iit()
        c.call = MagicMock(return_value=result)
        out = c.sign_data(b"challenge")
        assert isinstance(out, bytes), label
        assert out == DER, label

    def test_hex_is_no_longer_decoded_as_base64(self):
        """The regression: hex digits are all valid base64 → silent garbage."""
        c = _iit()
        c.call = MagicMock(return_value=DER.hex())
        wrong = base64.b64decode(DER.hex())
        assert c.sign_data(b"x") != wrong
        assert c.sign_data(b"x") == DER

    def test_dict_without_a_signature_field_is_a_clear_error(self):
        c = _iit()
        c.call = MagicMock(return_value={"status": "ok"})
        with pytest.raises(IITRPCError, match="without a signature field"):
            c.sign_data(b"x")

    def test_non_der_cms_is_rejected(self):
        c = _iit()
        c.call = MagicMock(return_value=base64.b64encode(b"not-der").decode())
        with pytest.raises(IITRPCError, match="not DER"):
            c.sign_data(b"x")

    @pytest.mark.parametrize("bad", [5, 1.5, ["AAAA"], True])
    def test_unexpected_types_raise_rpc_error_not_typeerror(self, bad):
        c = _iit()
        c.call = MagicMock(return_value=bad)
        with pytest.raises(IITRPCError):
            c.sign_data(b"x")

    def test_sign_hash_raw_signature_is_not_required_to_be_der(self):
        raw = b"\x11" * 64  # a raw DSTU 4145 signature
        c = _iit()
        c.call = MagicMock(return_value=raw.hex())
        assert c.sign_hash(b"h" * 32) == raw

    def test_the_downstream_encoder_no_longer_crashes(self):
        """sedo_client base64-encodes the result; a dict used to TypeError there."""
        c = _iit()
        c.call = MagicMock(return_value={"signature": base64.b64encode(DER).decode()})
        base64.b64encode(c.sign_data(b"x"))  # must not raise


# ─── 2. JSON-RPC envelopes that are not objects ──────────────

class TestRpcEnvelope:
    @pytest.mark.parametrize("body", [[], "ok", 42, None])
    def test_non_object_envelope_is_rpc_error(self, body):
        with pytest.raises(IITRPCError, match="non-object JSON"):
            _iit_envelope(body).call("X")

    def test_string_error_member_is_rpc_error(self):
        with pytest.raises(IITRPCError) as exc:
            _iit_envelope({"error": "boom"}).call("X")
        assert exc.value.message == "boom"

    def test_string_method_not_found_maps_to_32601(self):
        with pytest.raises(IITRPCError) as exc:
            _iit_envelope({"error": "Requested method not found"}).call("X")
        assert exc.value.code == -32601

    def test_non_numeric_code_does_not_crash(self):
        with pytest.raises(IITRPCError) as exc:
            _iit_envelope({"error": {"code": "E42", "message": "odd"}}).call("X")
        assert exc.value.code == -1

    def test_signdata_fallback_reachable_with_string_error(self):
        """The regression: a bare-string error made the fallback unreachable."""
        with patch("iit_client.requests.Session") as S:
            sess = MagicMock()
            S.return_value = sess
            sess.post.side_effect = [
                MagicMock(status_code=200, text="",
                          json=lambda: {"error": "Requested method not found"}),
                MagicMock(status_code=200, text="",
                          json=lambda: {"result": base64.b64encode(DER).decode()}),
            ]
            client = IITClient()
            assert client.sign_data(b"x") == DER
        methods = [c.kwargs["json"]["method"] for c in sess.post.call_args_list]
        assert methods == ["Sign", "SignData"]


# ─── 3. Auth flow: one odd reply must not kill the whole run ──

class _Signer:
    def __init__(self, sign_error=None):
        self.sign_error = sign_error

    def login(self, pin): pass
    def get_certificate(self): return b"\x30\x82"

    def sign(self, data):
        if self.sign_error:
            raise self.sign_error
        return b"\x00" * 64

    def logout(self): pass


def _client(signer=None):
    with patch("sedo_client.SEDOClient._pick_backend", return_value=signer or _Signer()):
        c = SEDOClient()
    c.session = MagicMock()
    return c


def _resp(status, body):
    r = MagicMock(status_code=status, ok=200 <= status < 400)
    r.json.return_value = body
    return r


class TestAuthRobustness:
    @pytest.mark.parametrize("odd", [[], "ok", 7])
    def test_non_object_init_body_moves_to_next_candidate(self, odd):
        c = _client()
        challenge = base64.b64encode(b"nonce").decode()
        c.session.post.side_effect = [
            _resp(200, odd),                        # candidate 1: odd body
            _resp(200, {"challenge": challenge}),   # candidate 2: init
            _resp(200, {}),                         # candidate 2: verify ok
        ]
        assert c._flow_direct_kep(b"cert") is True
        assert c.session.post.call_count == 3

    def test_authorize_survives_non_object_body_everywhere(self):
        c = _client()
        c.session.get.return_value = MagicMock(headers={"Location": ""})
        c.session.post.return_value = _resp(200, [])
        with pytest.raises(RuntimeError, match="All auth flows failed"):
            c.authorize("1234")

    def test_token_error_is_visible_without_verbose(self, caplog):
        c = _client(_Signer(sign_error=RuntimeError("sign failed: CKR_MECHANISM_INVALID")))
        c.session.get.return_value = MagicMock(headers={"Location": ""})
        c.session.post.return_value = _resp(200, {"challenge": "bm9uY2U="})
        with caplog.at_level(logging.WARNING, logger="sedo_client"):
            with pytest.raises(RuntimeError) as exc:
                c.authorize("1234")
        assert "CKR_MECHANISM_INVALID" in caplog.text
        # …and in the final message, not just "run Fiddler".
        assert "CKR_MECHANISM_INVALID" in str(exc.value)

    def test_not_implemented_flow_is_not_reported_as_an_error(self, caplog):
        c = _client()
        c.session.get.return_value = MagicMock(headers={"Location": ""})
        c.session.post.return_value = _resp(404, {})
        with caplog.at_level(logging.WARNING, logger="sedo_client"):
            with pytest.raises(RuntimeError) as exc:
                c.authorize("1234")
        assert "cms_post" not in caplog.text
        assert "Errors:" not in str(exc.value)


class TestInboxShape:
    def test_non_object_inbox_is_value_error(self):
        c = _client()
        c.session.get.return_value = _resp(200, [{"id": "d1"}])
        with pytest.raises(ValueError, match="Unexpected inbox response"):
            c.fetch_inbox()

    def test_non_list_documents_is_value_error(self):
        c = _client()
        c.session.get.return_value = _resp(200, {"documents": {"id": "d1"}})
        with pytest.raises(ValueError, match="'documents' type"):
            c.fetch_inbox()

    def test_missing_documents_is_empty_list(self):
        c = _client()
        c.session.get.return_value = _resp(200, {})
        assert c.fetch_inbox() == []


# ─── 4. PKCS#11: mechanism is discovered on the logged-in slot ──

@pytest.fixture(params=["pkcs11", "virtual"])
def signer_factory(request, fake_pykcs11, tmp_path):
    """Build either PyKCS11-backed signer against the fake module."""
    def build():
        if request.param == "pkcs11":
            from pkcs11_signer import PKCS11Signer
            mod = tmp_path / "PKCS11.EKeyAlmaz1C.dll"
            mod.write_bytes(b"fake")
            return PKCS11Signer(str(mod))
        from virtual_signer import VirtualSigner
        mod = tmp_path / "PKCS11.Virtual.EKeyAlmaz1C.dll"
        mod.write_bytes(b"fake")
        return VirtualSigner(module_path=str(mod))
    build.kind = request.param
    return build


class TestMechanismSlot:
    def test_login_on_slot_1_uses_slot_1_mechanisms(self, fake_pykcs11, signer_factory):
        """Almaz in slot 0, an Avest-style token in slot 1."""
        P = fake_pykcs11
        P.SLOTS = [0, 1]
        P.MECHS_BY_SLOT = {0: {0x80420031: P.CKF_SIGN},
                           1: {0x00000352: P.CKF_SIGN}}
        signer = signer_factory()
        signer.login("1234", slot=1)
        assert signer._sign_mechanism == 0x00000352
        signer.sign(b"data")
        assert P.SIGN_CALLS[-1][1] == 0x00000352

    def test_default_slot_still_first(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.SLOTS = [0, 1]
        P.MECHS_BY_SLOT = {0: {0x80420031: P.CKF_SIGN},
                           1: {0x00000352: P.CKF_SIGN}}
        signer = signer_factory()
        signer.login("1234")
        assert signer._sign_mechanism == 0x80420031

    def test_relogin_on_another_slot_rediscovers(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.SLOTS = [0, 1]
        P.MECHS_BY_SLOT = {0: {0x80420031: P.CKF_SIGN},
                           1: {0x00000352: P.CKF_SIGN}}
        signer = signer_factory()
        signer.login("1234", slot=0)
        signer.login("1234", slot=1)
        assert signer._sign_mechanism == 0x00000352


# ─── 5. PKCS#11: the certificate belongs to the signing key ──

class TestCertificateMatchesKey:
    def _two_pair_token(self, P, key_ids, cert_ids):
        keys = [object() for _ in key_ids]
        certs = [object() for _ in cert_ids]
        P.PRIVATE_KEYS, P.CERTS = keys, certs
        for k, kid in zip(keys, key_ids):
            P.OBJ_ATTRS[k] = {P.CKA_ID: kid}
        for c, cid in zip(certs, cert_ids):
            P.OBJ_ATTRS[c] = {P.CKA_ID: cid, P.CKA_VALUE: b"\x30CERT-" + cid}
        return keys, certs

    def test_cert_is_the_one_with_the_keys_cka_id(self, fake_pykcs11, signer_factory):
        """Encryption cert listed FIRST — the old code returned it."""
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        keys, _ = self._two_pair_token(P, key_ids=[b"\x02"],
                                       cert_ids=[b"\x09", b"\x02"])
        signer = signer_factory()
        signer.login("1234")
        assert signer.get_certificate() == b"\x30CERT-\x02"
        signer.sign(b"data")
        assert P.SIGN_CALLS[-1][0] is keys[0]

    def test_key_chosen_to_match_an_available_cert(self, fake_pykcs11, signer_factory):
        """Two keys, only the second has a certificate."""
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        keys, _ = self._two_pair_token(P, key_ids=[b"\x07", b"\x03"],
                                       cert_ids=[b"\x03"])
        signer = signer_factory()
        signer.login("1234")
        signer.sign(b"data")
        assert P.SIGN_CALLS[-1][0] is keys[1]
        assert signer.get_certificate() == b"\x30CERT-\x03"

    def test_unlinked_multi_object_token_warns(self, fake_pykcs11, signer_factory, caplog):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        self._two_pair_token(P, key_ids=[b"\x01", b"\x02"], cert_ids=[b"\x08", b"\x09"])
        signer = signer_factory()
        with caplog.at_level(logging.WARNING):
            signer.login("1234")
        assert "CKA_ID" in caplog.text

    def test_single_pair_default_token_unchanged(self, fake_pykcs11, signer_factory, caplog):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        signer = signer_factory()
        with caplog.at_level(logging.WARNING):
            signer.login("1234")
        assert signer.get_certificate() == P.CERT_DER
        assert "CKA_ID" not in caplog.text

    def test_no_certificate_is_a_clear_error(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        P.CERTS = []
        signer = signer_factory()
        signer.login("1234")
        with pytest.raises(RuntimeError, match="No certificates"):
            signer.get_certificate()


# ─── 6. PKCS#11: no leaked session handles ────────────────────

class TestSessionLifecycle:
    def test_wrong_pin_closes_the_session(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        P.LOGIN_ERROR = RuntimeError("CKR_PIN_INCORRECT")
        signer = signer_factory()
        with pytest.raises(RuntimeError, match="CKR_PIN_INCORRECT"):
            signer.login("0000")
        assert len(P.SESSIONS) == 1 and P.SESSIONS[0].closed
        assert signer._session is None and signer._priv_key is None

    def test_retries_after_wrong_pin_leave_nothing_open(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        signer = signer_factory()
        P.LOGIN_ERROR = RuntimeError("CKR_PIN_INCORRECT")
        for _ in range(3):
            with pytest.raises(RuntimeError):
                signer.login("0000")
        P.LOGIN_ERROR = None
        signer.login("1234")
        open_ = [s for s in P.SESSIONS if not s.closed]
        assert len(open_) == 1 and open_[0] is signer._session

    def test_relogin_closes_the_previous_session(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        signer = signer_factory()
        signer.login("1234")
        first = signer._session
        signer.login("1234")
        assert first.closed
        assert signer._session is not first and not signer._session.closed

    def test_failure_after_login_closes_the_session(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        P.PRIVATE_KEYS = []
        signer = signer_factory()
        with pytest.raises(RuntimeError, match="No private keys"):
            signer.login("1234")
        assert P.SESSIONS[-1].closed and signer._session is None

    def test_no_mechanism_closes_the_session(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420014: P.CKF_SIGN}  # SYM_MAC only
        signer = signer_factory()
        with pytest.raises(RuntimeError):
            signer.login("1234")
        assert P.SESSIONS[-1].closed and signer._session is None

    def test_logout_clears_certificate(self, fake_pykcs11, signer_factory):
        P = fake_pykcs11
        P.MECHS = {0x80420031: P.CKF_SIGN}
        signer = signer_factory()
        signer.login("1234")
        signer.logout()
        with pytest.raises(RuntimeError, match="Not logged in"):
            signer.get_certificate()


# ─── 7. OpenSC signs with the certificate's CKA_ID ───────────

class TestOpenSCSignsWithCertId:
    @pytest.mark.parametrize("cert_id", ["01", "02"])
    @patch("opensc_signer.subprocess.run")
    def test_sign_passes_the_same_id_as_the_certificate(self, mock_run, tmp_path, cert_id):
        from opensc_signer import OpenSCSigner
        tool = tmp_path / "pkcs11-tool"
        tool.write_bytes(b"fake")
        module = tmp_path / "PKCS11.dll"
        module.write_bytes(b"fake")
        signer = OpenSCSigner(module_path=str(module), pkcs11_tool=str(tool), cert_id=cert_id)
        signer.login("1234")
        seen = []

        def fake_run(cmd, **kwargs):
            args = list(cmd)
            seen.append(args)
            Path(args[args.index("--output-file") + 1]).write_bytes(b"\x30\x01")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = fake_run
        signer.get_certificate()
        signer.sign(b"data")
        cert_args, sign_args = seen
        assert cert_args[cert_args.index("--id") + 1] == cert_id
        assert "--sign" in sign_args
        assert sign_args[sign_args.index("--id") + 1] == cert_id
