"""
PKCS#11 клієнт через subprocess до OpenSC pkcs11-tool.exe.

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

__all__ = ["OpenSCSigner", "OpenSCNotFound"]


class OpenSCNotFound(Exception):
    """pkcs11-tool.exe не знайдено."""


class OpenSCSigner:
    """
    Signer через OpenSC pkcs11-tool.exe (subprocess).

    Стандартні шляхи для пошуку:
    - C:\\Program Files\\OpenSC Project\\OpenSC\\tools\\pkcs11-tool.exe
    - /usr/bin/pkcs11-tool (Linux)

    Приклад:
        signer = OpenSCSigner(
            module_path=r"C:\\...\\PKCS11_EKeyAlmaz1C.dll",
            mechanism="0x80420031"  # IIT DSTU 4145 SIGN (EC F_2M) — CONFIRMED on live token
        )
        signer.login("1234")
        cert = signer.get_certificate()
        signature = signer.sign(b"data to sign")
    """

    DEFAULT_PKCS11_TOOL_PATHS = [
        r"C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe",
        r"C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe",
        "/usr/bin/pkcs11-tool",
        "/usr/local/bin/pkcs11-tool",
    ]

    def __init__(self, module_path: str,
                 mechanism: str = "0x80420031",
                 pkcs11_tool: Optional[str] = None):
        if pkcs11_tool is None:
            pkcs11_tool = self._find_tool()
        if not Path(pkcs11_tool).exists():
            raise OpenSCNotFound(f"pkcs11-tool not found: {pkcs11_tool}")

        self._tool = pkcs11_tool
        self._module = module_path
        self._mechanism = mechanism
        self._pin: Optional[str] = None

        if not Path(module_path).exists():
            raise FileNotFoundError(f"PKCS#11 module not found: {module_path}")

        log.info("Using pkcs11-tool: %s", self._tool)
        log.info("Module: %s", self._module)

    @classmethod
    def _find_tool(cls) -> str:
        # Check PATH first
        tool = shutil.which("pkcs11-tool") or shutil.which("pkcs11-tool.exe")
        if tool:
            return tool
        # Check standard paths
        for p in cls.DEFAULT_PKCS11_TOOL_PATHS:
            if Path(p).exists():
                return p
        raise OpenSCNotFound(
            f"pkcs11-tool not found in PATH or standard locations: "
            f"{cls.DEFAULT_PKCS11_TOOL_PATHS}"
        )

    def _run(self, args: list, input_data: Optional[bytes] = None,
             timeout: float = 30.0) -> subprocess.CompletedProcess:
        """Виклик pkcs11-tool із прапором --module."""
        cmd = [self._tool, "--module", self._module, *args]
        log.debug("$ %s", " ".join(cmd))
        result = subprocess.run(cmd, input=input_data, capture_output=True,
                                timeout=timeout, check=False)
        if result.stderr:
            log.debug("stderr: %s", result.stderr.decode("utf-8", errors="replace").rstrip())
        return result

    # ─── Інформаційні (без PIN) ─────────────────────────────

    def list_slots(self) -> str:
        """Повертає сирий текст виводу --list-slots."""
        r = self._run(["--list-slots"])
        return r.stdout.decode("utf-8", errors="replace")

    def list_mechanisms(self) -> list[str]:
        """Перелік підтримуваних механізмів."""
        r = self._run(["--list-mechanisms"])
        return r.stdout.decode("utf-8", errors="replace").splitlines()

    def show_info(self) -> str:
        """Module and token info. (CLI: opensc_signer.py --list-slots)"""
        r = self._run(["--show-info"])
        return r.stdout.decode("utf-8", errors="replace")

    # ─── З PIN ──────────────────────────────────────────────

    def login(self, pin: str) -> None:
        """
        Зберігає PIN для наступних викликів (не робить SC_Login негайно).

        ⚠️ PIN передається у командному рядку pkcs11-tool — видимий іншим
        локальним користувачам через список процесів. Для багатокористувацьких
        Windows-воркерів використовуй backend=iit_agent.
        """
        self._pin = pin

    def list_objects(self) -> str:
        if not self._pin:
            raise RuntimeError("PIN не встановлено — викликай login() спочатку")
        r = self._run(["--login", "--pin", self._pin, "--list-objects"])
        return r.stdout.decode("utf-8", errors="replace")

    def get_certificate(self, object_id: str = "01") -> bytes:
        """Експорт сертифіката у DER-форматі."""
        if not self._pin:
            raise RuntimeError("PIN не встановлено")
        # mkstemp закриває fd одразу — щоб pkcs11-tool на Windows міг відкрити файл на запис
        fd, out_path = tempfile.mkstemp(suffix=".der")
        os.close(fd)
        try:
            r = self._run([
                "--login", "--pin", self._pin,
                "--read-object", "--type", "cert", "--id", object_id,
                "--output-file", out_path,
            ])
            if r.returncode != 0:
                stderr = r.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"read-object failed: {stderr}")
            return Path(out_path).read_bytes()
        finally:
            try:
                Path(out_path).unlink()
            except OSError:
                pass

    def sign(self, data: bytes) -> bytes:
        """Підпис даних через --sign."""
        if not self._pin:
            raise RuntimeError("PIN не встановлено")

        fd, inp_path = tempfile.mkstemp()
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        out_path = inp_path + ".sig"

        try:
            r = self._run([
                "--login", "--pin", self._pin,
                "--sign", "--mechanism", self._mechanism,
                "--input-file", inp_path,
                "--output-file", out_path,
            ])
            if r.returncode != 0:
                stderr = r.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"sign failed: {stderr}")
            return Path(out_path).read_bytes()
        finally:
            for p in (inp_path, out_path):
                try:
                    Path(p).unlink()
                except OSError:
                    pass

    def logout(self) -> None:
        """Очистити PIN з пам'яті."""
        self._pin = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.logout()


# ═══════════════════════════════════════════════════════════════

def main():
    import argparse
    parser = argparse.ArgumentParser(description="OpenSC pkcs11-tool wrapper")
    parser.add_argument("--module", required=True, help="PKCS11_EKeyAlmaz1C.dll")
    parser.add_argument("--mechanism", default="0x80420031")
    parser.add_argument("--pkcs11-tool", help="Path to pkcs11-tool.exe")
    parser.add_argument("--list-slots", action="store_true")
    parser.add_argument("--list-mechanisms", action="store_true")
    parser.add_argument("--pin", help="Token PIN")
    parser.add_argument("--list-objects", action="store_true")
    parser.add_argument("--get-cert", action="store_true")
    parser.add_argument("--sign", help="File to sign")
    parser.add_argument("--output", help="Output signature path")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s"
    )

    signer = OpenSCSigner(
        module_path=args.module,
        mechanism=args.mechanism,
        pkcs11_tool=args.pkcs11_tool,
    )

    if args.list_slots:
        print(signer.list_slots())
    if args.list_mechanisms:
        for line in signer.list_mechanisms():
            print(f"  {line}")

    if args.pin:
        signer.login(args.pin)

        if args.list_objects:
            print(signer.list_objects())

        if args.get_cert:
            cert = signer.get_certificate()
            Path("almaz-cert.der").write_bytes(cert)
            print(f"✓ Cert: almaz-cert.der ({len(cert)} bytes)")

        if args.sign:
            data = Path(args.sign).read_bytes()
            sig = signer.sign(data)
            out = args.output or args.sign + ".sig"
            Path(out).write_bytes(sig)
            print(f"✓ Signature: {out} ({len(sig)} bytes)")


if __name__ == "__main__":
    main()
