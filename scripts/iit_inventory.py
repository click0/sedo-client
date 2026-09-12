#!/usr/bin/env python3
"""
iit_inventory.py — інвентаризація DLL/EXE з пакетів IIT («Користувач ЦСК-1»,
EUSignWeb, драйвер Алмаз-1К) без запуску бінарників і без сторонніх бібліотек.

Для кожного файла збирає: розмір, sha256, бітність, PE-timestamp, FileVersion /
ProductVersion / CompanyName, експорти (і чи це PKCS#11-модуль за
`C_GetFunctionList`), імпортовані DLL, DLL/.cap, на які посилаються рядки
(LoadLibrary-залежності), OID ДСТУ, `CKM_*`-рядки і — головне — кількість
входжень 12 IIT mechanism ID як DWORD-констант (механізми в бінарнику лежать
числами, не текстом).

Використання:

    # інвентар одного або кількох розпакованих пакетів + diff проти baseline
    python scripts/iit_inventory.py extracted/eusignweb --label eusignweb \
        --snapshot-label S3-2026-07-web_dll --source "Web_dll.7z sha256=78f9…" \
        --baseline docs/inventory/snapshot-a-v5.json \
        --baseline docs/inventory/snapshot-b-v6.json \
        --json docs/inventory/S3-2026-07-web_dll.json --md /tmp/inv.md

    # реєстр: матриця файл × snapshot по кількох JSON
    python scripts/iit_inventory.py --registry docs/inventory/*.json --md docs/DLL-REGISTRY.md

    # списки експортів критичних модулів (для майбутніх diff-ів)
    python scripts/iit_inventory.py extracted/eusignweb --exports-dir docs/inventory/exports

Тільки stdlib. `--engine pefile` — cross-check через pefile (pip install .[analysis]).

Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path
from typing import Iterable, Optional

SCHEMA = 1
TOOL = "iit_inventory"
TOOL_VERSION = "1.0"

# 12 vendor-defined IIT mechanism IDs (0x8042XXXX). Дубль mechanism_ids.IIT_MECHANISMS —
# scripts/ не імпортують модулі репо; синхронність перевіряє тест.
IIT_MECHANISM_IDS = (
    0x80420011, 0x80420012, 0x80420013, 0x80420014, 0x80420016,
    0x80420021, 0x80420031, 0x80420032,
    0x80420041, 0x80420042, 0x80420043, 0x80420044,
)

# Файли, які відстежуємо в кожному snapshot (docs/IIT-ANALYSIS-ADDENDUM-v5 §1, -v6 §8.1).
CRITICAL_FILES = (
    "PKCS11.EKeyAlmaz1C.dll", "PKCS11.Virtual.EKeyAlmaz1C.dll",
    "CSPBase.dll", "CSPExtension.dll", "CSPIBase.dll", "PKIFormats.dll",
    "EUSignCP.dll", "EUSignRPC.dll", "EUSignAgent.exe",
    "KM.dll", "KM.PKCS11.dll", "KM.FileSystem.dll",
    "KM.EKeyAlmaz1C.dll", "KM.EKeyAlmaz1CBTA.dll",
    "KM.EKeyCrystal1.dll", "KM.CModGryada61.dll",
    "LDAPClient.dll", "NCHostCP.dll", "EKAlmaz1CConfiguration.exe",
)

# Модулі, для яких робимо глибокий скан (експорти/імпорти/рядки/DWORD-константи).
CRYPTO_MODULE_RE = re.compile(
    r"^(PKCS11[._].*|EUSign.*|CSP.*|PKIFormats|KM[._].*|NCHost.*|LDAPClient|SSLUtils)\.(dll|exe)$",
    re.IGNORECASE,
)

DSTU_OID_RE = re.compile(rb"1\.2\.804\.2\.1\.1\.1(?:\.\d+)+")
CKM_RE = re.compile(rb"CK[MAO]_[A-Z0-9_]{3,}")
DLL_REF_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,60}\.dll$", re.IGNORECASE)
CAP_REF_RE = re.compile(r"([A-Za-z0-9_.\-]{2,60}\.cap)\b", re.IGNORECASE)
PDB_RE = re.compile(r"^[A-Za-z]:\\.{1,240}\.pdb$", re.IGNORECASE)
ASCII_RUN_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_RUN_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")

# Рядки, що трапляються в кожному MSVC-бінарнику і не є справжніми залежностями.
_NOISE_DLLS = frozenset({"mscoree.dll", "wuser32.dll", "ekernel32.dll"})

VERSION_KEYS = ("FileVersion", "ProductVersion", "CompanyName", "ProductName",
                "FileDescription", "OriginalFilename", "InternalName")


class PEError(ValueError):
    """Файл не є коректним PE або структура пошкоджена."""


# ═══════════════════════════════════════════════════════════════
# Чистий stdlib PE-парсер
# ═══════════════════════════════════════════════════════════════

@dataclasses.dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw_ptr: int
    raw_size: int


@dataclasses.dataclass
class PEHeader:
    machine: int
    bitness: int
    timestamp: int
    is_dll: bool
    subsystem: int
    image_base: int
    opt_magic: int
    sections: list
    data_dirs: list  # [(rva, size), ...] — 16 записів


_MACHINE_NAMES = {0x014C: "i386", 0x8664: "x86_64", 0x01C4: "ARMv7", 0xAA64: "ARM64"}


def parse_pe_header(data: bytes) -> PEHeader:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PEError("not an MZ executable")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise PEError("PE signature not found")
    machine, nsec, ts, _symtab, _nsym, opt_size, chars = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4)
    opt = e_lfanew + 24
    if opt + 2 > len(data):
        raise PEError("truncated optional header")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        bitness = 32
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ndirs = struct.unpack_from("<I", data, opt + 92)[0]
        dirs_off = opt + 96
    elif magic == 0x20B:
        bitness = 64
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
        dirs_off = opt + 112
    else:
        raise PEError(f"unknown optional header magic 0x{magic:x}")
    data_dirs = []
    for i in range(16):
        if i < ndirs and dirs_off + 8 * i + 8 <= len(data):
            data_dirs.append(struct.unpack_from("<II", data, dirs_off + 8 * i))
        else:
            data_dirs.append((0, 0))
    sections = []
    sec_off = opt + opt_size
    for i in range(nsec):
        off = sec_off + 40 * i
        if off + 40 > len(data):
            break
        name, vsize, va, raw_size, raw_ptr = struct.unpack_from("<8sIIII", data, off)
        sections.append(Section(name.rstrip(b"\0").decode("latin-1"),
                                va, vsize, raw_ptr, raw_size))
    return PEHeader(machine, bitness, ts, bool(chars & 0x2000), subsystem,
                    image_base, magic, sections, data_dirs)


def rva_to_offset(hdr: PEHeader, rva: int) -> int:
    for s in hdr.sections:
        span = max(s.vsize, s.raw_size)
        if s.va <= rva < s.va + span:
            off = rva - s.va + s.raw_ptr
            if rva - s.va >= s.raw_size:
                raise PEError(f"RVA 0x{rva:x} is in uninitialised part of {s.name}")
            return off
    raise PEError(f"RVA 0x{rva:x} outside all sections")


def read_cstring(data: bytes, off: int, limit: int = 1024) -> str:
    if off < 0 or off >= len(data):
        raise PEError("string offset outside file")
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        end = min(off + limit, len(data))
    return data[off:end].decode("latin-1")


def parse_exports(data: bytes, hdr: PEHeader) -> tuple[Optional[str], list[str]]:
    """Повертає (ім'я DLL з export directory, список іменованих експортів)."""
    rva, size = hdr.data_dirs[0]
    if not rva:
        return None, []
    off = rva_to_offset(hdr, rva)
    if off + 40 > len(data):
        raise PEError("truncated export directory")
    (_chars, _ts, _maj, _min, name_rva, _base, _nfuncs, nnames,
     _addr_funcs, addr_names, _addr_ords) = struct.unpack_from("<IIHHIIIIIII", data, off)
    dll_name = read_cstring(data, rva_to_offset(hdr, name_rva)) if name_rva else None
    names = []
    if nnames and addr_names:
        tbl = rva_to_offset(hdr, addr_names)
        for i in range(min(nnames, 65535)):
            if tbl + 4 * i + 4 > len(data):
                break
            name_rva_i = struct.unpack_from("<I", data, tbl + 4 * i)[0]
            try:
                names.append(read_cstring(data, rva_to_offset(hdr, name_rva_i)))
            except PEError:
                break
    return dll_name, names


def parse_import_dlls(data: bytes, hdr: PEHeader) -> list[str]:
    """Імена DLL з import directory (dir 1) і delay-load directory (dir 13)."""
    found: list[str] = []

    def add(name: str) -> None:
        n = name.lower()
        if n and n not in found:
            found.append(n)

    rva, _ = hdr.data_dirs[1]
    if rva:
        try:
            off = rva_to_offset(hdr, rva)
            for i in range(4096):
                d = off + 20 * i
                if d + 20 > len(data):
                    break
                _oft, _ts, _fwd, name_rva, _ft = struct.unpack_from("<IIIII", data, d)
                if not name_rva:
                    break
                add(read_cstring(data, rva_to_offset(hdr, name_rva)))
        except PEError:
            pass
    rva, _ = hdr.data_dirs[13]
    if rva:
        try:
            off = rva_to_offset(hdr, rva)
            for i in range(1024):
                d = off + 32 * i
                if d + 32 > len(data):
                    break
                attrs, name_ref = struct.unpack_from("<II", data, d)
                if not name_ref:
                    break
                if not (attrs & 1) and name_ref >= hdr.image_base:
                    name_ref -= hdr.image_base  # старий формат: VA замість RVA
                add(read_cstring(data, rva_to_offset(hdr, name_ref)))
        except PEError:
            pass
    return found


_VS_SIG = b"\xBD\x04\xEF\xFE"


def parse_fixed_file_info(data: bytes) -> Optional[dict]:
    """VS_FIXEDFILEINFO: шукаємо сигнатуру у сирих байтах — без обходу ресурсів."""
    pos = -1
    while True:
        pos = data.find(_VS_SIG, pos + 1)
        if pos < 0 or pos + 52 > len(data):
            return None
        (_sig, struc_ver, fv_ms, fv_ls, pv_ms, pv_ls) = struct.unpack_from("<IIIIII", data, pos)
        if struc_ver >> 16 != 1:
            continue
        return {
            "file_version": f"{fv_ms >> 16}.{fv_ms & 0xFFFF}.{fv_ls >> 16}.{fv_ls & 0xFFFF}",
            "product_version": f"{pv_ms >> 16}.{pv_ms & 0xFFFF}.{pv_ls >> 16}.{pv_ls & 0xFFFF}",
        }


def parse_string_file_info(data: bytes, keys: Iterable[str] = VERSION_KEYS) -> dict:
    """
    StringFileInfo без обходу дерева ресурсів: для кожного ключа шукаємо його
    UTF-16LE-подання, читаємо `wValueLength` з 6-байтового заголовка String
    перед ключем і значення після вирівнювання на 4 байти.
    """
    out: dict = {}
    for key in keys:
        pat = key.encode("utf-16le") + b"\0\0"
        pos = -1
        while key not in out:
            pos = data.find(pat, pos + 1)
            if pos < 0 or pos < 6:
                break
            _wlen, wvalue_len, wtype = struct.unpack_from("<HHH", data, pos - 6)
            if wtype != 1 or wvalue_len == 0 or wvalue_len > 512:
                continue
            vpos = pos + len(pat)
            vpos += (-vpos) % 4
            raw = data[vpos:vpos + 2 * wvalue_len]
            if len(raw) < 2:
                continue
            value = raw.decode("utf-16le", errors="replace").split("\0", 1)[0].strip()
            if value:
                out[key] = value
    return out


def pe_timestamp_iso(ts: int) -> str:
    """Дата збірки з COFF-заголовка; /Brepro-хеші показуємо як repro:0x…"""
    now = int(_dt.datetime.now(_dt.timezone.utc).timestamp())
    if ts < 946684800 or ts > now + 86400:
        return f"repro:0x{ts:08x}"
    return _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime("%Y-%m-%d")


# ═══════════════════════════════════════════════════════════════
# Рядки та константи
# ═══════════════════════════════════════════════════════════════

def extract_strings(data: bytes, min_len: int = 6) -> tuple[set[str], set[str]]:
    """(ASCII-рядки, UTF-16LE-рядки) довжиною >= min_len."""
    ascii_re = ASCII_RUN_RE if min_len == 6 else re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    u16_re = UTF16_RUN_RE if min_len == 6 else re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len)
    asc = {m.group().decode("ascii") for m in ascii_re.finditer(data)}
    u16 = set()
    for m in u16_re.finditer(data):
        s = m.group().decode("utf-16le")
        # Артефакт "sCSPIBase.dll": останній символ попереднього ASCII-рядка + його
        # NUL-термінатор виглядають як перший UTF-16-символ. Якщо байт перед
        # збігом — друкований ASCII, перший символ належить тому рядку.
        start = m.start()
        if start >= 1 and 0x20 <= data[start - 1] <= 0x7E:
            s = s[1:]
        if len(s) >= min_len:
            u16.add(s)
    return asc, u16


def scan_constants(data: bytes, strings: Optional[Iterable[str]] = None) -> dict:
    if strings is None:
        asc, u16 = extract_strings(data)
        strings = asc | u16
    strings = set(strings)
    dll_refs: set[str] = set()
    cap_refs: set[str] = set()
    pdb: set[str] = set()
    for s in strings:
        t = s.strip()
        if DLL_REF_RE.match(t):
            dll_refs.add(t.lower())
        for m in CAP_REF_RE.finditer(t):
            cap_refs.add(m.group(1))
        if PDB_RE.match(t):
            pdb.add(t)
    # Імена DLL можуть сидіти всередині довших рядків (наприклад "%s\\KM.dll").
    for s in strings:
        for m in re.finditer(r"([A-Za-z0-9_.\-]{2,60}\.dll)\b", s, re.IGNORECASE):
            dll_refs.add(m.group(1).lower())
    hits = {f"0x{m:08X}": data.count(struct.pack("<I", m)) for m in IIT_MECHANISM_IDS}
    return {
        "ckm_names": sorted({m.group().decode("ascii") for m in CKM_RE.finditer(data)}),
        "oids": sorted({m.group().decode("ascii") for m in DSTU_OID_RE.finditer(data)}),
        "dll_refs": sorted(dll_refs),
        "cap_refs": sorted(cap_refs),
        "pdb": sorted(pdb),
        "mech_dword_hits": hits,
        "mech_dword_all_present": all(v > 0 for v in hits.values()),
    }


# ═══════════════════════════════════════════════════════════════
# Запис про файл, інвентар каталогів, інсталятори
# ═══════════════════════════════════════════════════════════════

@dataclasses.dataclass
class FileRecord:
    package: str
    relpath: str
    name: str
    size: int
    sha256: str
    kind: str                       # dll / exe / sys / cap / other
    is_pe: bool = False
    pe_error: Optional[str] = None
    machine: Optional[str] = None
    bitness: Optional[int] = None
    pe_timestamp: Optional[str] = None
    subsystem: Optional[int] = None
    is_dll: Optional[bool] = None
    file_version: Optional[str] = None
    product_version: Optional[str] = None
    company: Optional[str] = None
    product_name: Optional[str] = None
    description: Optional[str] = None
    original_filename: Optional[str] = None
    export_name: Optional[str] = None
    exports_count: Optional[int] = None
    exports: Optional[list] = None
    c_exports: Optional[list] = None
    is_pkcs11: Optional[bool] = None
    import_dlls: Optional[list] = None
    dll_refs: Optional[list] = None
    dynamic_deps: Optional[list] = None
    cap_refs: Optional[list] = None
    ckm_names: Optional[list] = None
    oids: Optional[list] = None
    pdb: Optional[list] = None
    mech_dword_hits: Optional[dict] = None
    mech_dword_all_present: Optional[bool] = None
    critical: bool = False
    deep: bool = False
    engine: str = "stdlib"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def norm_name(name: str) -> str:
    """Ключ порівняння: без регістру, `_` == `.` (KM_PKCS11.dll == KM.PKCS11.dll)."""
    return name.lower().replace("_", ".")


_CRITICAL_KEYS = {norm_name(n) for n in CRITICAL_FILES}


def is_critical(name: str) -> bool:
    return norm_name(name) in _CRITICAL_KEYS


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _kind(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext if ext in ("dll", "exe", "sys", "cap", "msi", "cab") else "other"


def _pefile_analyse(path: Path) -> dict:
    """Cross-check через pefile (лише за --engine pefile)."""
    import pefile  # noqa: WPS433 — optional dependency
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories()
    out = {
        "bitness": 64 if pe.FILE_HEADER.Machine == 0x8664 else 32,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "exports": [e.name.decode() for e in getattr(pe, "DIRECTORY_ENTRY_EXPORT", None).symbols if e.name]
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else [],
        "imports": sorted({d.dll.decode().lower() for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])}
                          | {d.dll.decode().lower() for d in getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])}),
        "version": {},
    }
    if getattr(pe, "VS_FIXEDFILEINFO", None):
        f = pe.VS_FIXEDFILEINFO[0]
        out["version"]["FileVersion"] = (f"{f.FileVersionMS >> 16}.{f.FileVersionMS & 0xffff}."
                                         f"{f.FileVersionLS >> 16}.{f.FileVersionLS & 0xffff}")
    for fi in getattr(pe, "FileInfo", []) or []:
        for e in fi:
            if e.Key == b"StringFileInfo":
                for st in e.StringTable:
                    for k, v in st.entries.items():
                        out["version"][k.decode()] = v.decode(errors="replace")
    return out


def inventory_file(path: Path, root: Path, package: str, deep: bool = False,
                   engine: str = "stdlib") -> FileRecord:
    data = path.read_bytes()
    rec = FileRecord(package=package, relpath=path.relative_to(root).as_posix(),
                     name=path.name, size=len(data), sha256=sha256_bytes(data),
                     kind=_kind(path.name), critical=is_critical(path.name),
                     engine=engine)
    if data[:2] != b"MZ":
        return rec
    try:
        hdr = parse_pe_header(data)
    except PEError as e:
        rec.pe_error = str(e)
        return rec
    rec.is_pe = True
    rec.machine = _MACHINE_NAMES.get(hdr.machine, f"0x{hdr.machine:04x}")
    rec.bitness = hdr.bitness
    rec.pe_timestamp = pe_timestamp_iso(hdr.timestamp)
    rec.subsystem = hdr.subsystem
    rec.is_dll = hdr.is_dll
    fixed = parse_fixed_file_info(data) or {}
    sfi = parse_string_file_info(data)
    rec.file_version = sfi.get("FileVersion") or fixed.get("file_version")
    rec.product_version = fixed.get("product_version") or sfi.get("ProductVersion")
    rec.company = sfi.get("CompanyName")
    rec.product_name = sfi.get("ProductName")
    rec.description = sfi.get("FileDescription")
    rec.original_filename = sfi.get("OriginalFilename")
    if engine == "pefile":
        pf = _pefile_analyse(path)
        rec.bitness = pf["bitness"]
        rec.pe_timestamp = pe_timestamp_iso(pf["timestamp"])
        if pf["version"].get("FileVersion"):
            rec.file_version = pf["version"]["FileVersion"]
        rec.company = pf["version"].get("CompanyName", rec.company)
        exports, imports = pf["exports"], pf["imports"]
        rec.export_name = None
    else:
        try:
            rec.export_name, exports = parse_exports(data, hdr)
        except PEError as e:
            rec.pe_error = f"exports: {e}"
            exports = []
        imports = parse_import_dlls(data, hdr)
    imports = sorted(imports)
    rec.exports_count = len(exports)
    rec.c_exports = sorted(e for e in exports if e.startswith("C_"))
    rec.is_pkcs11 = "C_GetFunctionList" in exports
    rec.import_dlls = imports
    rec.deep = deep
    if deep:
        rec.exports = sorted(exports)
        asc, u16 = extract_strings(data)
        consts = scan_constants(data, asc | u16)
        rec.dll_refs = consts["dll_refs"]
        rec.cap_refs = consts["cap_refs"]
        rec.ckm_names = consts["ckm_names"]
        rec.oids = consts["oids"]
        rec.pdb = consts["pdb"]
        rec.mech_dword_hits = consts["mech_dword_hits"]
        rec.mech_dword_all_present = consts["mech_dword_all_present"]
        rec.dynamic_deps = sorted(set(rec.dll_refs) - set(imports) - _NOISE_DLLS
                                  - {path.name.lower(), (rec.export_name or "").lower()})
    return rec


def inventory_dir(root: Path, package: str, deep_re: re.Pattern = CRYPTO_MODULE_RE,
                  engine: str = "stdlib", deep_all: bool = False) -> list[FileRecord]:
    root = Path(root)
    files = sorted(p for p in root.rglob("*") if p.is_file())
    records = []
    for p in files:
        deep = deep_all or bool(deep_re.match(p.name))
        records.append(inventory_file(p, root, package, deep=deep, engine=engine))
    return records


_OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"


def detect_installer_type(head: bytes, sample: bytes) -> str:
    """
    Тип контейнера за сигнатурами: msi / inno <ver> / nsis / cab-sfx /
    pe+msi (Delphi-обгортка з вбудованим MSI) / 7z / zip / pe / unknown.
    """
    if head.startswith(_OLE_MAGIC):
        return "msi"
    if head.startswith(b"7z\xBC\xAF\x27\x1C"):
        return "7z"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    if head.startswith(b"MZ"):
        m = re.search(rb"Inno Setup Setup Data \(([0-9.]+)\)", sample)
        if m:
            return f"inno {m.group(1).decode()}"
        if b"Nullsoft" in sample or b"NSIS" in sample:
            return "nsis"
        if _OLE_MAGIC in sample:
            return "pe+msi"
        if b"MSCF" in sample:
            return "cab-sfx"
        return "pe"
    return "unknown"


def describe_installer(path: Path) -> dict:
    data = path.read_bytes()
    rec = {
        "name": path.name, "size": len(data), "sha256": sha256_bytes(data),
        "mtime": _dt.datetime.fromtimestamp(path.stat().st_mtime, _dt.timezone.utc)
        .strftime("%Y-%m-%d %H:%M"),
        "installer_type": detect_installer_type(data[:16], data),
    }
    if data[:2] == b"MZ":
        try:
            hdr = parse_pe_header(data)
            rec["pe_timestamp"] = pe_timestamp_iso(hdr.timestamp)
            rec["bitness"] = hdr.bitness
        except PEError as e:
            rec["pe_error"] = str(e)
    return rec


def build_inventory(packages: list[tuple[str, Path]], installers: Iterable[Path] = (),
                    engine: str = "stdlib", deep_all: bool = False,
                    label: Optional[str] = None, source: Optional[str] = None) -> dict:
    pkgs = []
    for pkg_label, root in packages:
        recs = inventory_dir(Path(root), pkg_label, engine=engine, deep_all=deep_all)
        pes = [r for r in recs if r.is_pe]
        pkgs.append({
            "label": pkg_label,
            "root": Path(root).name,  # лише ім'я каталогу — без локальних абсолютних шляхів
            "summary": {
                "files": len(recs),
                "pe": len(pes),
                "x86": sum(1 for r in pes if r.bitness == 32),
                "x64": sum(1 for r in pes if r.bitness == 64),
                "dll": sum(1 for r in recs if r.kind == "dll"),
                "exe": sum(1 for r in recs if r.kind == "exe"),
                "cap": sum(1 for r in recs if r.kind == "cap"),
                "pkcs11_modules": sorted(r.name for r in pes if r.is_pkcs11),
                "critical_present": sorted(r.name for r in recs if r.critical),
            },
            "files": [r.to_dict() for r in recs],
        })
    return {
        "schema": SCHEMA, "tool": TOOL, "tool_version": TOOL_VERSION,
        "generated": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "label": label, "source": source, "engine": engine,
        "installers": [describe_installer(Path(p)) for p in installers],
        "packages": pkgs,
    }


# ═══════════════════════════════════════════════════════════════
# Diff і реєстр
# ═══════════════════════════════════════════════════════════════

def iter_files(inv: dict) -> Iterable[dict]:
    for pkg in inv.get("packages", []):
        for f in pkg.get("files", []):
            yield f


def index_records(inv: dict) -> dict:
    """{(norm_name, bitness|None): record}. Дублікати з іншим sha → suffix #2, #3…"""
    idx: dict = {}
    for f in iter_files(inv):
        key = (norm_name(f["name"]), f.get("bitness"))
        if key in idx and idx[key].get("sha256") != f.get("sha256"):
            n = 2
            while (key[0] + f"#{n}", key[1]) in idx:
                n += 1
            key = (key[0] + f"#{n}", key[1])
        idx.setdefault(key, f)
    return idx


def _lookup(idx: dict, name: str, bitness) -> Optional[dict]:
    key = norm_name(name)
    return idx.get((key, bitness)) or idx.get((key, None)) or next(
        (v for (k, b), v in idx.items() if k == key), None)


_DIFF_FIELDS = ("sha256", "size", "file_version", "pe_timestamp", "exports_count",
                "mech_dword_all_present")


def diff_inventories(baseline: dict, current: dict) -> dict:
    """Порівнює лише поля, присутні з обох боків; списки експортів — як ± множини."""
    base_idx = index_records(baseline)
    cur_idx = index_records(current)
    added, removed, changed, unchanged = [], [], [], []
    seen_base = set()
    for (key, bitness), cur in cur_idx.items():
        base = _lookup(base_idx, cur["name"], bitness)
        if base is None:
            added.append(cur["name"])
            continue
        seen_base.add(id(base))
        delta: dict = {}
        for fld in _DIFF_FIELDS:
            if fld in base and fld in cur and base[fld] is not None and cur[fld] is not None \
                    and base[fld] != cur[fld]:
                delta[fld] = [base[fld], cur[fld]]
        for fld in ("exports", "c_exports", "import_dlls", "dynamic_deps", "cap_refs"):
            if base.get(fld) is not None and cur.get(fld) is not None:
                b, c = set(base[fld]), set(cur[fld])
                if b != c:
                    delta[fld + "_added"] = sorted(c - b)
                    delta[fld + "_removed"] = sorted(b - c)
        entry = {"name": cur["name"], "bitness": bitness}
        if delta:
            entry.update(delta)
            changed.append(entry)
        else:
            unchanged.append(cur["name"])
    for base in base_idx.values():
        if id(base) not in seen_base:
            removed.append(base["name"])
    return {"baseline": baseline.get("label"), "current": current.get("label"),
            "added": sorted(added), "removed": sorted(removed),
            "changed": sorted(changed, key=lambda e: e["name"].lower()),
            "unchanged": sorted(unchanged)}


def fmt_size(n) -> str:
    return "—" if n is None else f"{n:,}".replace(",", " ")


def short_sha(s) -> str:
    return "—" if not s else f"{s[:8]}…{s[-6:]}"


def _md_table(headers: list[str], rows: list[list]) -> str:
    esc = lambda v: str(v if v is not None else "—").replace("|", "\\|")  # noqa: E731
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _delta_mark(base: Optional[dict], cur: dict) -> str:
    if base is None:
        return "new"
    if base.get("sha256") == cur.get("sha256"):
        return "="
    bv, cv = base.get("file_version"), cur.get("file_version")
    if bv and cv and bv != cv:
        return f"{bv} → {cv}"
    return "≠sha (та сама версія)" if bv and cv else "≠sha"


def render_markdown(inv: dict, diffs: Optional[list] = None, full: bool = False) -> str:
    diffs = diffs or []
    L = [f"# Інвентар IIT — {inv.get('label') or 'без мітки'}", ""]
    if inv.get("source"):
        L += [f"Джерело: {inv['source']}", ""]
    L += [f"Згенеровано `{TOOL}` v{TOOL_VERSION} ({inv.get('engine')}), {inv.get('generated')}.", ""]
    _n = [0]

    def sec(title: str) -> str:
        _n[0] += 1
        return f"## {_n[0]}. {title}"

    if inv.get("installers"):
        L += [sec("Інсталятори"), ""]
        L.append(_md_table(["Файл", "Розмір", "mtime (UTC)", "Тип", "PE build", "SHA256"],
                           [[i["name"], fmt_size(i["size"]), i.get("mtime"), i.get("installer_type"),
                             i.get("pe_timestamp"), f"`{i['sha256']}`"] for i in inv["installers"]]))
        L.append("")

    L += [sec("Пакети"), ""]
    for p in inv["packages"]:
        s = p["summary"]
        L.append(f"- **{p['label']}** (`{p['root']}`): {s['files']} файлів, PE {s['pe']} "
                 f"(x86 {s['x86']}, x64 {s['x64']}), dll {s['dll']}, exe {s['exe']}, cap {s['cap']}; "
                 f"PKCS#11: {', '.join(s['pkcs11_modules']) or '—'}")
    L.append("")

    base_idxs = [(d.get("baseline") or f"baseline{i}", idx) for i, (d, idx) in enumerate(diffs)]
    crit = [f for f in iter_files(inv) if f.get("critical")]
    L += [sec("Критичні файли"), ""]
    headers = ["Файл", "Bit", "FileVer", "Build", "Розмір", "SHA256"] + [f"Δ vs {b}" for b, _ in base_idxs]
    rows = []
    for f in crit:
        row = [f["name"], f.get("bitness"), f.get("file_version"), f.get("pe_timestamp"),
               fmt_size(f["size"]), short_sha(f["sha256"])]
        for _, idx in base_idxs:
            row.append(_delta_mark(_lookup(idx, f["name"], f.get("bitness")), f))
        rows.append(row)
    L.append(_md_table(headers, rows) if rows else "_(немає критичних файлів)_")
    L.append("")

    L += [sec("PKCS#11 / крипто-модулі (глибокий скан)"), ""]
    deep = [f for f in iter_files(inv) if f.get("deep") and f.get("is_pe")]
    rows = []
    for f in deep:
        hits = f.get("mech_dword_hits") or {}
        n_hit = sum(1 for v in hits.values() if v)
        main31 = hits.get("0x80420031", 0)
        rows.append([f["name"], f.get("bitness"), f.get("file_version"), f.get("exports_count"),
                     len(f.get("c_exports") or []), "✅" if f.get("is_pkcs11") else "—",
                     f"{n_hit}/12 (31:{main31})", len(f.get("oids") or []),
                     ", ".join(f.get("import_dlls") or []),
                     ", ".join(f.get("dynamic_deps") or []) or "—"])
    L.append(_md_table(["Модуль", "Bit", "FileVer", "Exports", "C_*", "C_GetFunctionList",
                        "Mech DWORD", "DSTU OID", "Imports", "LoadLibrary-залежності"], rows)
             if rows else "_(немає)_")
    L.append("")
    caps = sorted({c for f in deep for c in (f.get("cap_refs") or [])})
    if caps:
        L += ["`.cap`, на які посилаються модулі: " + ", ".join(f"`{c}`" for c in caps), ""]

    for d, _idx in diffs:
        L += [sec(f"Diff vs {d.get('baseline') or 'baseline'}"), ""]
        L.append(f"- Додано ({len(d['added'])}): {', '.join(d['added']) or '—'}")
        L.append(f"- Вилучено ({len(d['removed'])}): {', '.join(d['removed']) or '—'}")
        L.append(f"- Без змін ({len(d['unchanged'])}): {', '.join(d['unchanged']) or '—'}")
        L.append(f"- Змінено ({len(d['changed'])}):")
        for e in d["changed"]:
            parts = []
            for k, v in e.items():
                if k in ("name", "bitness"):
                    continue
                if isinstance(v, list) and len(v) == 2 and not k.endswith(("_added", "_removed")):
                    a, b = v
                    if k == "sha256":
                        a, b = short_sha(a), short_sha(b)
                    parts.append(f"{k}: {a} → {b}")
                elif v:
                    parts.append(f"{k}: {', '.join(map(str, v))}")
            L.append(f"  - `{e['name']}`: " + "; ".join(parts))
        L.append("")

    L += [sec("SHA256 критичних файлів"), "", "```"]
    for f in crit:
        ver = f" ({f['file_version']}, {f['pe_timestamp']})" if f.get("file_version") else ""
        L.append(f"{f['sha256']}  {f['name']}{ver}")
    L += ["```", ""]

    if full:
        L += [sec("Усі файли"), ""]
        for p in inv["packages"]:
            L += [f"### {p['label']}", ""]
            L.append(_md_table(["Файл", "Розмір", "Bit", "FileVer", "Build", "SHA256"],
                               [[f["relpath"], fmt_size(f["size"]), f.get("bitness"), f.get("file_version"),
                                 f.get("pe_timestamp"), short_sha(f["sha256"])] for f in p["files"]]))
            L.append("")
    return "\n".join(L)


def render_registry(snapshots: list[dict]) -> str:
    """Матриця файл × snapshot: версія / build / sha (короткий)."""
    labels = [s.get("label") or f"snapshot{i}" for i, s in enumerate(snapshots)]
    idxs = [index_records(s) for s in snapshots]
    names: dict[str, str] = {}
    for s in snapshots:
        for f in iter_files(s):
            names.setdefault(norm_name(f["name"]), f["name"])
    order = sorted(names, key=lambda k: (not is_critical(names[k]), k))
    L = ["# Реєстр DLL IIT — версії по snapshot-ах", "",
         "Згенеровано `scripts/iit_inventory.py --registry`. Клітинка: `версія · build · sha256[:8]`; "
         "`=` — той самий sha, що в попередній колонці; `—` — файла немає у snapshot.", ""]
    rows = []
    for key in order:
        row = [("**" if is_critical(names[key]) else "") + names[key] + ("**" if is_critical(names[key]) else "")]
        prev_sha = None
        for idx in idxs:
            f = _lookup(idx, names[key], None)
            if f is None:
                row.append("—")
                continue
            sha = f.get("sha256")
            if sha and sha == prev_sha:
                row.append("=")
            else:
                row.append(f"{f.get('file_version') or '?'} · {f.get('pe_timestamp') or '?'} · `{(sha or '')[:8]}`")
            prev_sha = sha or prev_sha
        rows.append(row)
    L.append(_md_table(["Файл"] + labels, rows))
    L.append("")
    return "\n".join(L)


def write_export_lists(inv: dict, out_dir: Path) -> list[Path]:
    """Один текстовий файл на модуль: `<Name>@<FileVersion>.txt` — відсортовані експорти."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for f in iter_files(inv):
        if not f.get("exports"):
            continue
        ver = f.get("file_version") or f.get("pe_timestamp") or "unknown"
        suffix = "-x64" if f.get("bitness") == 64 else ""
        p = out_dir / f"{f['name']}@{ver}{suffix}.txt"
        p.write_text("\n".join(f["exports"]) + "\n", encoding="utf-8")
        written.append(p)
    return written


# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Інвентаризація DLL/EXE з пакетів IIT (stdlib, без запуску бінарників)")
    p.add_argument("paths", nargs="*", help="Каталоги з розпакованими пакетами")
    p.add_argument("--label", action="append", default=[],
                   help="Мітка пакета (у порядку каталогів); за замовчуванням — ім'я каталогу")
    p.add_argument("--installers", action="append", default=[],
                   help="Файл або каталог з інсталяторами (.exe/.msi) для §1")
    p.add_argument("--baseline", action="append", default=[],
                   help="JSON попереднього snapshot для diff (можна кілька)")
    p.add_argument("--snapshot-label", help="Мітка цього snapshot, напр. S3-2026-07-web_dll")
    p.add_argument("--source", help="Звідки взято файли (URL / архів + sha256)")
    p.add_argument("--json", dest="json_out", help="Куди записати JSON-інвентар")
    p.add_argument("--md", dest="md_out", help="Куди записати Markdown-звіт")
    p.add_argument("--exports-dir", help="Каталог для списків експортів (<Name>@<ver>.txt)")
    p.add_argument("--engine", choices=["stdlib", "pefile"], default="stdlib",
                   help="pefile — лише для cross-check (pip install .[analysis])")
    p.add_argument("--full", action="store_true", help="Markdown: таблиця всіх файлів")
    p.add_argument("--deep-all", action="store_true",
                   help="Глибокий скан усіх PE, не лише крипто-модулів")
    p.add_argument("--registry", nargs="+", metavar="JSON",
                   help="Режим реєстру: матриця файл × snapshot по кількох JSON")
    return p


def _load_json(path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _installer_paths(args: list[str]) -> list[Path]:
    out = []
    for a in args:
        p = Path(a)
        if p.is_dir():
            out += sorted(q for q in p.iterdir() if q.is_file() and q.suffix.lower() in (".exe", ".msi", ".7z", ".zip"))
        elif p.is_file():
            out.append(p)
    return out


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.registry:
        snaps = [_load_json(p) for p in args.registry]
        md = render_registry(snaps)
        if args.md_out:
            Path(args.md_out).write_text(md, encoding="utf-8")
        else:
            print(md)
        return 0

    if not args.paths:
        build_parser().error("вкажи каталоги з розпакованими пакетами або --registry")
    packages = []
    for i, p in enumerate(args.paths):
        root = Path(p)
        if not root.is_dir():
            build_parser().error(f"не каталог: {p}")
        packages.append((args.label[i] if i < len(args.label) else root.name, root))

    inv = build_inventory(packages, _installer_paths(args.installers), engine=args.engine,
                          deep_all=args.deep_all, label=args.snapshot_label, source=args.source)
    diffs = []
    for b in args.baseline:
        base = _load_json(b)
        diffs.append((diff_inventories(base, inv), index_records(base)))
    if diffs:
        inv["diffs"] = [d for d, _ in diffs]

    if args.json_out:
        Path(args.json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json_out).write_text(json.dumps(inv, ensure_ascii=False, indent=1) + "\n",
                                       encoding="utf-8")
    if args.exports_dir:
        write_export_lists(inv, Path(args.exports_dir))
    md = render_markdown(inv, diffs, full=args.full)
    if args.md_out:
        Path(args.md_out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.md_out).write_text(md, encoding="utf-8")
    if not args.json_out and not args.md_out:
        print(md)
    else:
        for p in inv["packages"]:
            s = p["summary"]
            print(f"{p['label']}: {s['files']} files, PE {s['pe']}, PKCS#11 {len(s['pkcs11_modules'])}, "
                  f"critical {len(s['critical_present'])}")
        for d, _ in diffs:
            print(f"diff vs {d['baseline']}: +{len(d['added'])} -{len(d['removed'])} "
                  f"~{len(d['changed'])} ={len(d['unchanged'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
