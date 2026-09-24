"""
Автоматизація авторизації в СЕДО ЗСУ (sedo.mod.gov.ua).

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import base64
import binascii
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional, Protocol
from urllib.parse import quote

import requests

log = logging.getLogger(__name__)

# Server-supplied document ids are used as a path segment and a filename —
# restrict to a safe charset so ".." / "/" / drive-letters can't escape output_dir.
_DOC_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# Windows device names. "downloads\\NUL.zip" is the NUL device, not a file —
# the extension does not help — so a document with id "NUL" or "CON" was
# silently discarded (or written to the console) while download_document()
# reported success. Checked on the part before the first dot, case-insensitive,
# as Windows does.
_WINDOWS_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"]
    + [f"COM{i}" for i in range(1, 10)] + [f"LPT{i}" for i in range(1, 10)]
)


def _safe_doc_id(doc_id) -> str:
    """Validate a document id from SEDO JSON before using it in a path/URL."""
    if not isinstance(doc_id, str) or not _DOC_ID_RE.match(doc_id) or ".." in doc_id:
        raise ValueError(f"Unsafe document id: {doc_id!r}")
    stem = doc_id.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED or doc_id.endswith("."):
        # A trailing dot is stripped by Win32, so "a." and "a" collide.
        raise ValueError(f"Unsafe document id (Windows reserved name): {doc_id!r}")
    return doc_id


# Keys a verify endpoint may use to say "no" inside a 200 response.
_REJECTION_FLAGS = ("authenticated", "authorized", "success", "ok", "valid", "result")


def _verify_accepted(r) -> bool:
    """
    Did the verify step actually authorise us?

    ``Response.ok`` alone is true for every status below 400, including 3xx
    (a redirect back to the login page) and a 200 carrying
    ``{"authenticated": false}``. The client then printed "Авторизація
    успішна" and failed later in fetch_inbox() with an opaque 401 that points
    nowhere near the real cause.

    The real endpoint is still unknown (needs a Fiddler capture), so this only
    rejects what is unambiguous: a non-2xx status, an ``error`` member, or an
    explicit ``false`` in one of the usual flag fields. Anything else in a
    2xx is accepted, as before.
    """
    status = getattr(r, "status_code", None)
    if not isinstance(status, int) or not 200 <= status < 300:
        return False
    ctype = str(r.headers.get("Content-Type", "")).lower()
    if "json" not in ctype:
        return True
    try:
        body = r.json()
    except ValueError:
        return False  # claims JSON, isn't — not a success we can trust
    if not isinstance(body, dict):
        return True
    if body.get("error"):
        return False
    return not any(body.get(k) is False for k in _REJECTION_FLAGS)


# Re-exported for backwards compatibility; the implementation lives in
# _console.py and is shared by every CLI entry point.
from _console import force_utf8_io, read_pin  # noqa: E402


__all__ = ["SEDOClient", "Signer", "SEDO_MOD_URL", "IITAgentAdapter",
           "force_utf8_io"]

# Standard locations for Key-6.dat (virtual token auto-detect)
KEY_FILE_SEARCH_PATHS = [
    Path("./Key-6.dat"),
    Path("./libs/Key-6.dat"),
    Path.home() / ".iit" / "Key-6.dat",
    Path("/var/lib/sedo-client/Key-6.dat"),
]

# Фіксоване посилання — СЕДО ЗСУ, не старе sedo.gov.ua
SEDO_MOD_URL = "https://sedo.mod.gov.ua"

# Valid values of SEDOClient(backend=...) and of --backend.
_BACKENDS = ("auto", "opensc", "pkcs11", "virtual", "iit_agent")


class Signer(Protocol):
    """
    Абстрактний підписник.

    ⚠️ ``sign()`` НЕ повертає однаковий формат у всіх backend-ах
    (атрибут ``signature_format``):

    - ``"raw"`` — opensc / pkcs11 / virtual: сирий підпис ДСТУ 4145
      (C_Sign, 64–128 байт, без сертифіката);
    - ``"cms"`` — iit_agent: CMS SignedData (CAdES-BES, DER, з сертифікатом).

    Який із них чекає СЕДО, невідомо до Fiddler-захоплення живого входу.
    Тому _flow_direct_kep логує формат: якщо вхід працює з одним backend-ом
    і не працює з іншим, причина — саме тут, а не в PIN чи токені.

    ``close()`` (необов'язковий) — остаточне звільнення ресурсів після
    ``logout()``: вивантажити PKCS#11-модуль, закрити HTTP-сесію агента.
    """
    signature_format: str

    def login(self, pin: str) -> None: ...
    def get_certificate(self) -> bytes: ...
    def sign(self, data: bytes) -> bytes: ...
    def logout(self) -> None: ...


class SEDOClient:
    """Повний цикл авторизації та роботи зі СЕДО ЗСУ."""

    def __init__(self, sedo_url: str = SEDO_MOD_URL,
                 backend: str = "auto",
                 module_path: Optional[str] = None,
                 key_file: Optional[str] = None):
        self.sedo_url = sedo_url.rstrip("/")
        self.signer: Signer = self._pick_backend(backend, module_path, key_file)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "sedo-automation/1.0",
            "Accept-Language": "uk,en;q=0.5",
        })

    def _pick_backend(self, name: str, module_path: Optional[str],
                      key_file: Optional[str] = None) -> Signer:
        """
        Вибирає backend:
        - 'opensc'    — OpenSC pkcs11-tool.exe (найпростіший, рекомендовано)
        - 'pkcs11'    — PyKCS11 + PKCS11_EKeyAlmaz1C.dll (HW token)
        - 'virtual'   — PyKCS11 + PKCS11.Virtual.EKeyAlmaz1C.dll + Key-6.dat
        - 'iit_agent' — JSON-RPC до EUSignAgent (потребує GUI)
        - 'auto'      — opensc → pkcs11 → virtual → iit_agent
        """
        # argparse `choices` guards only the CLI; a library caller passing
        # backend="pkcs12" used to fall through every branch and silently get
        # the IIT agent — which then received the PIN.
        if name not in _BACKENDS:
            raise ValueError(f"Unknown backend {name!r}; expected one of "
                             f"{', '.join(_BACKENDS)}")

        if name in ("opensc", "auto"):
            try:
                from opensc_signer import OpenSCSigner
                from mechanism_ids import detect_dstu4145_mechanism
                if module_path is None:
                    raise ValueError("OpenSC backend requires --module path")
                # The token's own mechanism list decides (no PIN needed);
                # the module name is only the fallback. A live ST-338 showed
                # why: Av337CryptokiD.dll exposes the IIT ids 0x80420031/32,
                # not the 0x352 the name-based table assumed.
                mech = f"0x{detect_dstu4145_mechanism(module_path):08X}"
                signer = OpenSCSigner(module_path=module_path, mechanism=mech)
                mech = self._discover_opensc_mechanism(signer, module_path, mech)
                signer.set_mechanism(mech)
                log.info("Backend: OpenSC pkcs11-tool (subprocess), mechanism %s",
                         mech)
                return signer
            except Exception as e:
                if name == "opensc":
                    raise
                log.info("OpenSC unavailable (%s), trying PyKCS11", e)

        if name in ("pkcs11", "auto"):
            try:
                from pkcs11_signer import PKCS11Signer
                signer = PKCS11Signer(module_path)
                log.info("Backend: PKCS#11 (PyKCS11 direct)")
                return signer
            except Exception as e:
                if name == "pkcs11":
                    raise
                log.info("PyKCS11 unavailable (%s), trying Virtual", e)

        if name in ("virtual", "auto"):
            try:
                from virtual_signer import VirtualSigner
                resolved_key = key_file or self._find_key_file()
                if name == "virtual" and not resolved_key:
                    raise FileNotFoundError(
                        "Virtual backend requires --key-file or Key-6.dat "
                        "in a standard location"
                    )
                signer = VirtualSigner(module_path=module_path,
                                       key_file=resolved_key)
                log.info("Backend: Virtual token (Key-6.dat, no USB)")
                return signer
            except Exception as e:
                if name == "virtual":
                    raise
                log.info("Virtual unavailable (%s), falling back to IIT Agent", e)

        # Fallback: IIT Agent JSON-RPC
        from iit_client import IITClient, IITAgentNotFound
        try:
            client = IITClient.auto_discover(origin=self.sedo_url)
            log.info("Backend: IIT Agent JSON-RPC (%s:%d)", client.host, client.port)
            return IITAgentAdapter(client)
        except IITAgentNotFound as e:
            raise RuntimeError(f"No working backend: {e}")

    @staticmethod
    def _discover_opensc_mechanism(signer, module_path: str, default: str) -> str:
        """
        DSTU 4145 mechanism as the token itself reports it.

        --list-mechanisms needs no PIN, so this costs no attempt; the policy
        is the same choose_sign_mechanism the PyKCS11 backends use. The name
        of the module is not enough: an unknown module fell back to the IIT id,
        and Av337CryptokiD.dll (ST-338) turned out to expose IIT ids, not the
        0x352 assumed for "Avtor". ``default`` (name-based) is used only when
        the list cannot be read.
        """
        import subprocess
        from mechanism_ids import choose_sign_mechanism
        try:
            mech = choose_sign_mechanism(signer.sign_mechanism_ids())
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
            log.warning("No usable mechanism list from %s (%s); falling back "
                        "to %s by module name", module_path, e, default)
            return default
        log.info("Mechanism 0x%08X chosen from the token's list", mech)
        return f"0x{mech:08X}"

    @staticmethod
    def _find_key_file() -> Optional[str]:
        """Search standard locations for Key-6.dat (virtual token auto-detect)."""
        wine_prefix = os.environ.get("WINEPREFIX")
        if wine_prefix:
            wine_candidate = Path(wine_prefix) / "drive_c" / "sedo-libs" / "Key-6.dat"
            if wine_candidate.exists():
                return str(wine_candidate)

        for p in KEY_FILE_SEARCH_PATHS:
            if p.exists():
                return str(p)
        return None

    # ─── Авторизація ─────────────────────────────────────────

    def authorize(self, pin: str) -> None:
        """
        Повний flow: login у токен → challenge від СЕДО → підпис → verify.

        Повертає None при успіху, кидає RuntimeError якщо жоден flow не
        спрацював.

        Точні URL-endpoints СЕДО ЗСУ уточнюються Fiddler-ом (30 хв роботи).
        Поки що — 3 можливі flow.
        """
        log.info("Logging in to token...")
        self.signer.login(pin)

        cert = self.signer.get_certificate()
        log.info("Got certificate: %d bytes", len(cert))

        # Пробуємо три flow
        errors = []
        for flow_name, flow_fn in [
            ("oidc", self._flow_oidc),
            ("direct_kep", self._flow_direct_kep),
            ("cms_post", self._flow_cms_post),
        ]:
            log.info("Trying flow: %s", flow_name)
            try:
                if flow_fn(cert):
                    log.info("✓ Authorized via %s", flow_name)
                    return
            except NotImplementedError as e:
                log.debug("%s flow not implemented: %s", flow_name, e)
            except (requests.RequestException, ValueError, RuntimeError) as e:
                # RuntimeError is what every backend raises for a real token
                # failure (CKR_*, "sign failed: …", no mechanism). At DEBUG it
                # was invisible without -v, and the operator only saw "run
                # Fiddler" — pointing at the wrong root cause entirely.
                log.warning("%s flow failed: %s", flow_name, e)
                errors.append(f"{flow_name}: {e}")

        detail = f" Errors: {'; '.join(errors)}." if errors else ""
        raise RuntimeError(
            "All auth flows failed." + detail +
            " If no error above is a token/signing error, run a Fiddler "
            "capture of a live login to identify the real SEDO flow, then "
            "update the _flow_* methods."
        )

    # The flows take no PIN: login() already used it, and every frame that
    # holds it is one more place a locals-dumping tool (pytest --showlocals,
    # Sentry, cgitb) can print it from.

    def _flow_oidc(self, cert: bytes) -> bool:
        """СЕДО → redirect → id.gov.ua КЕП login → redirect назад."""
        r = self.session.get(f"{self.sedo_url}/auth/login",
                             allow_redirects=False, timeout=10)
        location = r.headers.get("Location", "")
        if "id.gov.ua" not in location:
            return False
        log.info("OIDC flow detected, IdP: %s", location)
        # TODO: implement id.gov.ua OIDC dance
        # Це окремий протокол, потребує окремої розвідки
        return False

    def _flow_direct_kep(self, cert: bytes) -> bool:
        """Сайт дає challenge, ми підписуємо, відправляємо."""
        candidates = [
            f"{self.sedo_url}/api/auth/kep/init",
            f"{self.sedo_url}/auth/kep/challenge",
            f"{self.sedo_url}/login/kep/init",
        ]
        for url in candidates:
            try:
                r = self.session.post(url, timeout=10)
                if r.status_code != 200:
                    continue
                data = r.json()
                # These are GUESSED endpoints: a generic handler answering
                # 200 [] or 200 "ok" is plausible. .get() on that raised
                # AttributeError, which no except here or in authorize()
                # caught — the remaining candidates were never tried.
                if not isinstance(data, dict):
                    log.debug("%s: 200 with non-object JSON (%s), next candidate",
                              url, type(data).__name__)
                    continue
                challenge = data.get("challenge") or data.get("nonce") or data.get("data")
                if not challenge or not isinstance(challenge, (str, bytes)):
                    continue

                log.info("Got challenge (%d %s)", len(challenge),
                         "chars" if isinstance(challenge, str) else "bytes")
                if isinstance(challenge, str):
                    # Strict decode: a plaintext nonce is NOT valid base64 and
                    # must be signed as-is, not silently mangled by b64decode.
                    try:
                        challenge_bytes = base64.b64decode(challenge, validate=True)
                    except (binascii.Error, ValueError):
                        challenge_bytes = challenge.encode()
                else:
                    challenge_bytes = challenge

                signature = self.signer.sign(challenge_bytes)
                log.info("Signature: %d bytes, format %s", len(signature),
                         getattr(self.signer, "signature_format", "unknown"))

                # Замінюємо лише останній сегмент шляху, не випадкові підрядки
                verify_url = url.rsplit("/", 1)[0] + "/verify"
                r2 = self.session.post(verify_url, json={
                    "signature": base64.b64encode(signature).decode(),
                    "certificate": base64.b64encode(cert).decode(),
                    "session_id": data.get("session_id") or data.get("id"),
                }, timeout=10)
                if _verify_accepted(r2):
                    return True
                # Verify failed on this guessed endpoint — keep probing the
                # remaining candidates instead of aborting on the first 200/init.
                log.info("verify rejected by %s: HTTP %s", verify_url,
                         getattr(r2, "status_code", "?"))
                continue
            except (requests.RequestException, ValueError):
                continue
        return False

    def _flow_cms_post(self, cert: bytes) -> bool:
        """Повний CAdES-BES підпис, який відправляється на сервер."""
        raise NotImplementedError(
            "CMS POST flow requires Fiddler capture of real SEDO auth "
            "to know exact endpoint and signed payload format"
        )

    # ─── Робота з документами ────────────────────────────────

    def fetch_inbox(self, since: Optional[str] = None) -> list:
        params = {"since": since} if since else {}
        r = self.session.get(f"{self.sedo_url}/api/documents/inbox",
                             params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, dict):
            raise ValueError(f"Unexpected inbox response: {type(data).__name__}, "
                             "expected an object with 'documents'")
        docs = data.get("documents", [])
        if not isinstance(docs, list):
            raise ValueError(f"Unexpected 'documents' type: {type(docs).__name__}")
        return docs

    def download_document(self, doc_id: str, output_dir: Path) -> Path:
        doc_id = _safe_doc_id(doc_id)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        r = self.session.get(
            f"{self.sedo_url}/api/documents/{quote(doc_id, safe='')}/export",
            timeout=60)
        r.raise_for_status()
        output = output_dir / f"{doc_id}.zip"
        output.write_bytes(r.content)
        return output

    def __enter__(self):
        return self

    def close(self) -> None:
        """Log out, release the backend (DLL / agent connection), close HTTP."""
        try:
            try:
                self.signer.logout()
            finally:
                close = getattr(self.signer, "close", None)
                if callable(close):
                    close()
        finally:
            self.session.close()

    def __exit__(self, *args):
        # Close the HTTP session even if logout() raises, to avoid leaks.
        self.close()
        return False


class IITAgentAdapter:
    """Адаптер IITClient до протоколу Signer."""
    # Agent "Sign" = CAdES-BES CMS SignedData, not a raw C_Sign value.
    signature_format = "cms"

    def __init__(self, client):
        self._c = client
        self._cert_bytes = None
        self._device = None

    def login(self, pin: str):
        self._c.initialize()
        devices = self._c.enum_key_media_devices()
        if not devices:
            raise RuntimeError("No devices")
        self._device = devices[0]
        self._c.read_private_key(self._device, pin)
        certs = self._c.enum_own_certificates()
        if not certs:
            raise RuntimeError("No certificates bound to private key")
        cert_info = self._c.get_own_certificate(0)
        # get_own_certificate повертає DER у полі 'data' (hex) — див. docs/PROTOCOL-JSON-RPC.md
        # Guard the envelope: None/str would raise TypeError on `in`/subscript.
        if not isinstance(cert_info, dict):
            raise RuntimeError(
                f"Unexpected GetOwnCertificate result: {type(cert_info).__name__}"
            )
        if "data" in cert_info:
            self._cert_bytes = self._decode_cert(cert_info["data"])
        elif "certificate" in cert_info:
            self._cert_bytes = self._decode_cert(cert_info["certificate"])
        else:
            raise RuntimeError(
                f"Unknown cert envelope; keys: {list(cert_info.keys())}"
            )

    @staticmethod
    def _decode_cert(value) -> bytes:
        """DER may arrive as hex or base64 — try hex first, then strict base64."""
        if not isinstance(value, str):
            raise RuntimeError(f"Certificate field is not a string: {type(value).__name__}")
        try:
            return bytes.fromhex(value)
        except ValueError:
            pass
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as e:
            raise RuntimeError(f"Certificate is neither hex nor base64: {e}") from e

    def get_certificate(self) -> bytes:
        if self._cert_bytes is None:
            raise RuntimeError("Not logged in")
        return self._cert_bytes

    def sign(self, data: bytes) -> bytes:
        if self._cert_bytes is None:
            raise RuntimeError("Not logged in")
        return self._c.sign_data(data)

    def logout(self):
        # Never let teardown raise: a lost agent here would mask the real
        # error raised inside the with-block (see finalize()).
        from iit_client import IITError
        try:
            self._c.finalize()
        except IITError as e:
            log.warning("IIT agent finalize failed (ignored): %s", e)

    def close(self) -> None:
        """Close the agent HTTP connection pool (after logout)."""
        self._c.close()


# ═══════════════════════════════════════════════════════════════

def _build_parser():
    """CLI argument parser (separate so tests can inspect real choices)."""
    import argparse

    parser = argparse.ArgumentParser(description="SEDO ЗСУ automation")
    parser.add_argument("--url", default=SEDO_MOD_URL,
                        help=f"СЕДО URL (default: {SEDO_MOD_URL})")
    parser.add_argument("--backend", default="auto",
                        choices=list(_BACKENDS),
                        help="Signing backend")
    parser.add_argument("--module", help="Path to PKCS#11 module DLL")
    parser.add_argument("--key-file",
                        help="Path to Key-6.dat (virtual backend). NOTE: the "
                             "virtual DLL locates Key-N.dat from its own "
                             "configured directory; this flag only validates.")
    parser.add_argument("--pin",
                        help="Token PIN. Visible in the process list — prefer "
                             "the SEDO_PIN environment variable or the prompt.")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--since", help="Fetch docs since YYYY-MM-DD")
    parser.add_argument("--output", default="./downloads")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main():
    force_utf8_io()

    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    # PIN precedence: --pin (argv, least safe) → SEDO_PIN env → interactive
    # prompt. An empty PIN exits here instead of costing a token attempt.
    args.pin = read_pin(args.pin)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with SEDOClient(sedo_url=args.url, backend=args.backend,
                        module_path=args.module,
                        key_file=args.key_file) as sedo:
            sedo.authorize(args.pin)
            print("✓ Авторизація успішна")

            if args.fetch:
                docs = sedo.fetch_inbox(since=args.since)
                print(f"📄 Документів: {len(docs)}")
                for doc in docs:
                    if not isinstance(doc, dict):
                        log.warning("Document entry is not an object, "
                                    "skipping: %r", doc)
                        continue
                    doc_id = doc.get("id")
                    if not doc_id:
                        log.warning("Document without id, skipping: %s",
                                    doc.get("title", doc))
                        continue
                    path = sedo.download_document(doc_id, output_dir)
                    print(f"  ✓ {path.name}")
    except Exception as e:
        log.error("❌ %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
