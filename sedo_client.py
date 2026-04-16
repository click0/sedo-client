"""
Автоматизація авторизації в СЕДО ЗСУ (sedo.mod.gov.ua).

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.25
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import base64
import logging
from pathlib import Path
from typing import Optional, Protocol

import requests

log = logging.getLogger(__name__)

# Фіксоване посилання — СЕДО ЗСУ, не старе sedo.gov.ua
SEDO_MOD_URL = "https://sedo.mod.gov.ua"


class Signer(Protocol):
    """Абстрактний підписник."""
    def login(self, pin: str) -> None: ...
    def get_certificate(self) -> bytes: ...
    def sign(self, data: bytes) -> bytes: ...
    def logout(self) -> None: ...


class SEDOClient:
    """Повний цикл авторизації та роботи зі СЕДО ЗСУ."""

    def __init__(self, sedo_url: str = SEDO_MOD_URL,
                 backend: str = "auto",
                 module_path: Optional[str] = None):
        self.sedo_url = sedo_url.rstrip("/")
        self.signer: Signer = self._pick_backend(backend, module_path)

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "sedo-automation/1.0",
            "Accept-Language": "uk,en;q=0.5",
        })

    def _pick_backend(self, name: str, module_path: Optional[str]) -> Signer:
        """
        Вибирає backend:
        - 'opensc'    — OpenSC pkcs11-tool.exe (найпростіший, рекомендовано)
        - 'pkcs11'    — PyKCS11 + PKCS11_EKeyAlmaz1C.dll
        - 'iit_agent' — JSON-RPC до EUSignAgent (потребує GUI)
        - 'auto'      — opensc → pkcs11 → iit_agent
        """
        if name in ("opensc", "auto"):
            try:
                from opensc_signer import OpenSCSigner
                if module_path is None:
                    raise ValueError("OpenSC backend requires --module path")
                signer = OpenSCSigner(module_path=module_path)
                log.info("Backend: OpenSC pkcs11-tool (subprocess)")
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
                log.info("PyKCS11 unavailable (%s), falling back to IIT Agent", e)

        # Fallback: IIT Agent JSON-RPC
        from iit_client import IITClient, IITAgentNotFound
        try:
            client = IITClient.auto_discover(origin=self.sedo_url)
            log.info("Backend: IIT Agent JSON-RPC (%s:%d)", client.host, client.port)
            return IITAgentAdapter(client)
        except IITAgentNotFound as e:
            raise RuntimeError(f"No working backend: {e}")

    # ─── Авторизація ─────────────────────────────────────────

    def authorize(self, pin: str) -> bool:
        """
        Повний flow: login у токен → challenge від СЕДО → підпис → verify.

        Точні URL-endpoints СЕДО ЗСУ уточнюються Fiddler-ом (30 хв роботи).
        Поки що — 3 можливі flow.
        """
        log.info("Logging in to token...")
        self.signer.login(pin)

        cert = self.signer.get_certificate()
        log.info("Got certificate: %d bytes", len(cert))

        # Пробуємо три flow
        for flow_name, flow_fn in [
            ("oidc", self._flow_oidc),
            ("direct_kep", self._flow_direct_kep),
            ("cms_post", self._flow_cms_post),
        ]:
            log.info("Trying flow: %s", flow_name)
            try:
                if flow_fn(cert, pin):
                    log.info("✓ Authorized via %s", flow_name)
                    return True
            except Exception as e:
                log.debug("%s flow failed: %s", flow_name, e)

        raise RuntimeError(
            "All auth flows failed. "
            "Run Fiddler capture on live login to identify real SEDO flow, "
            "then update _flow_* methods."
        )

    def _flow_oidc(self, cert: bytes, pin: str) -> bool:
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

    def _flow_direct_kep(self, cert: bytes, pin: str) -> bool:
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
                challenge = data.get("challenge") or data.get("nonce") or data.get("data")
                if not challenge:
                    continue

                log.info("Got challenge (%d chars)", len(challenge))
                challenge_bytes = (
                    base64.b64decode(challenge) if isinstance(challenge, str)
                    else bytes(challenge)
                )

                signature = self.signer.sign(challenge_bytes)

                # Замінюємо лише останній сегмент шляху, не випадкові підрядки
                verify_url = url.rsplit("/", 1)[0] + "/verify"
                r2 = self.session.post(verify_url, json={
                    "signature": base64.b64encode(signature).decode(),
                    "certificate": base64.b64encode(cert).decode(),
                    "session_id": data.get("session_id") or data.get("id"),
                }, timeout=10)
                return r2.ok
            except (requests.RequestException, ValueError):
                continue
        return False

    def _flow_cms_post(self, cert: bytes, pin: str) -> bool:
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
        return r.json().get("documents", [])

    def download_document(self, doc_id: str, output_dir: Path) -> Path:
        r = self.session.get(f"{self.sedo_url}/api/documents/{doc_id}/export",
                             timeout=60)
        r.raise_for_status()
        output = output_dir / f"{doc_id}.zip"
        output.write_bytes(r.content)
        return output

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.signer.logout()
        self.session.close()


class IITAgentAdapter:
    """Адаптер IITClient до протоколу Signer."""
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
        if "data" in cert_info:
            self._cert_bytes = bytes.fromhex(cert_info["data"])
        elif "certificate" in cert_info:
            self._cert_bytes = base64.b64decode(cert_info["certificate"])
        else:
            raise RuntimeError(
                f"Unknown cert envelope; keys: {list(cert_info.keys())}"
            )

    def get_certificate(self) -> bytes:
        if self._cert_bytes is None:
            raise RuntimeError("Not logged in")
        return self._cert_bytes

    def sign(self, data: bytes) -> bytes:
        return self._c.sign_data(data)

    def logout(self):
        self._c.finalize()


# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="SEDO ЗСУ automation")
    parser.add_argument("--url", default=SEDO_MOD_URL,
                        help=f"СЕДО URL (default: {SEDO_MOD_URL})")
    parser.add_argument("--backend", default="auto",
                        choices=["auto", "opensc", "pkcs11", "iit_agent"],
                        help="Signing backend")
    parser.add_argument("--module", help="Path to PKCS11_EKeyAlmaz1C.dll")
    parser.add_argument("--pin", help="Token PIN")
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--since", help="Fetch docs since YYYY-MM-DD")
    parser.add_argument("--output", default="./downloads")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    if not args.pin:
        import getpass
        args.pin = getpass.getpass("Token PIN: ")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        with SEDOClient(sedo_url=args.url, backend=args.backend,
                        module_path=args.module) as sedo:
            sedo.authorize(args.pin)
            print("✓ Авторизація успішна")

            if args.fetch:
                docs = sedo.fetch_inbox(since=args.since)
                print(f"📄 Документів: {len(docs)}")
                for doc in docs:
                    path = sedo.download_document(doc["id"], output_dir)
                    print(f"  ✓ {path.name}")
    except Exception as e:
        log.error("❌ %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
