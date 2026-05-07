"""
fiddler_analyze.py — розбирає Fiddler SAZ capture, виявляє auth flow СЕДО.

Вхід: sedo-auth-capture.saz (експорт Fiddler All Sessions → Save)
Вихід: аналіз потрібних HTTP викликів + підказки для _flow_* методів

Використання:
    python scripts/fiddler_analyze.py sedo-auth-capture.saz
"""

import json
import sys
import zipfile
import re
from pathlib import Path
from xml.etree import ElementTree as ET


def parse_saz(saz_path: Path) -> list[dict]:
    """Парсить SAZ файл (ZIP с sessions всередині)."""
    sessions = []
    with zipfile.ZipFile(saz_path) as zf:
        # Session files: raw/<N>_c.txt (request), raw/<N>_s.txt (response)
        # N can be any number of digits (Fiddler does not always zero-pad).
        req_files = {}
        resp_files = {}
        for name in zf.namelist():
            m = re.match(r'raw/(\d+)_c\.txt$', name)
            if m:
                req_files[int(m.group(1))] = name
                continue
            m = re.match(r'raw/(\d+)_s\.txt$', name)
            if m:
                resp_files[int(m.group(1))] = name

        for num in sorted(req_files.keys() & resp_files.keys()):
            try:
                req = zf.read(req_files[num]).decode("utf-8", errors="replace")
                resp = zf.read(resp_files[num]).decode("utf-8", errors="replace")
                sessions.append({"num": num, "request": req, "response": resp})
            except KeyError:
                continue
    return sessions


def classify_session(sess: dict) -> dict:
    """Класифікує сесію: localhost IIT agent / SEDO / OIDC / інше."""
    req = sess["request"]
    first_line = req.split("\n")[0].strip() if req else ""
    method_url = first_line

    classification = "other"
    host_match = re.search(r'Host:\s*([^\r\n]+)', req, re.I)
    host = host_match.group(1).strip() if host_match else ""

    if "127.0.0.1" in host or "localhost" in host:
        classification = "iit_agent"
    elif "sedo.mod.gov.ua" in host:
        classification = "sedo"
    elif "id.gov.ua" in host:
        classification = "oidc_idp"
    elif host.endswith("sedo.gov.ua"):
        classification = "sedo_old"

    return {
        "num": sess["num"],
        "class": classification,
        "method_url": method_url,
        "host": host,
        "request": req,
        "response": sess["response"],
    }


def analyze(saz_path: Path):
    print(f"Analyzing: {saz_path}")
    sessions = parse_saz(saz_path)
    print(f"Total HTTP sessions: {len(sessions)}")

    classified = [classify_session(s) for s in sessions]
    categories = {}
    for s in classified:
        categories.setdefault(s["class"], []).append(s)

    print("\n=== Категорії ===")
    for cat, items in categories.items():
        print(f"  {cat}: {len(items)}")

    # ─── IIT Agent calls ─────────────────────────────────────
    iit = categories.get("iit_agent", [])
    if iit:
        print(f"\n=== IIT Agent JSON-RPC calls ({len(iit)}) ===")
        print("Послідовність викликів (method → result):")
        for s in iit[:30]:
            # Витягти JSON body з request
            body_match = re.search(r'\r?\n\r?\n(.+)', s["request"], re.DOTALL)
            if not body_match:
                continue
            try:
                payload = json.loads(body_match.group(1).strip())
                method = payload.get("method", "?")
                params_preview = str(payload.get("params", []))[:60]
                print(f"  [{s['num']:4}] {method}({params_preview})")
            except (json.JSONDecodeError, ValueError):
                print(f"  [{s['num']:4}] {s['method_url'][:80]}")

    # ─── SEDO calls ──────────────────────────────────────────
    sedo = categories.get("sedo", []) + categories.get("sedo_old", [])
    if sedo:
        print(f"\n=== SEDO server calls ({len(sedo)}) ===")
        print("Унікальні URL-и:")
        urls = set()
        for s in sedo:
            m = re.match(r'(\w+)\s+(\S+)', s["method_url"])
            if m:
                urls.add(f"{m.group(1)} {m.group(2)}")
        for u in sorted(urls):
            print(f"  {u}")

    # ─── OIDC ────────────────────────────────────────────────
    oidc = categories.get("oidc_idp", [])
    if oidc:
        print(f"\n=== OIDC redirect (id.gov.ua) — {len(oidc)} calls ===")
        print("Це означає СЕДО використовує OIDC flow!")
        for s in oidc[:5]:
            print(f"  [{s['num']:4}] {s['method_url'][:90]}")

    # ─── Висновок ────────────────────────────────────────────
    print("\n" + "=" * 60)
    print("РЕКОМЕНДАЦІЯ для sedo_client.py:")
    print("=" * 60)

    if oidc:
        print("""
СЕДО використовує OIDC через id.gov.ua.
→ Реалізувати _flow_oidc() з кодом для:
   1. GET /auth/login → отримати redirect на id.gov.ua
   2. На id.gov.ua викликати EUSignAgent JSON-RPC напряму
   3. Отримати id_token / code → передати на sedo.mod.gov.ua
""")
    elif iit and sedo:
        print("""
СЕДО викликає EUSignAgent напряму (direct KEP flow).
→ Реалізувати _flow_direct_kep() або _flow_cms_post() з URL:""")
        for u in sorted(urls)[:10]:
            print(f"     {u}")
    else:
        print("Не вдалося однозначно класифікувати. Перевірте SAZ вручну.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python fiddler_analyze.py <capture.saz>")
        sys.exit(1)
    analyze(Path(sys.argv[1]))
