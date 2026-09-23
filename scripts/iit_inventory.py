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
        bitness, fixed_size = 32, 96
    elif magic == 0x20B:
        bitness, fixed_size = 64, 112
    else:
        raise PEError(f"unknown optional header magic 0x{magic:x}")
    # SizeOfOptionalHeader positions the section table. It used to be trusted
    # blindly: with 0 the "sections" were read from the optional header itself,
    # and every RVA after that resolved through garbage — exports and imports
    # were reported as facts with pe_error = None.
    if opt_size < fixed_size:
        raise PEError(f"SizeOfOptionalHeader {opt_size} < {fixed_size} for magic 0x{magic:x}")
    if opt + fixed_size > len(data):
        raise PEError("truncated optional header")
    if bitness == 32:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        ndirs = struct.unpack_from("<I", data, opt + 92)[0]
    else:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    dirs_off = opt + fixed_size
    # Only the directories that fit inside the declared optional header count.
    ndirs = min(ndirs, 16, (opt_size - fixed_size) // 8)
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
            raise PEError(f"truncated section table ({i} of {nsec} sections)")
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
    """NUL-terminated string at ``off``; PEError if there is no NUL within ``limit``.

    Returning the first ``limit`` bytes instead (the old behaviour) put 1 KiB
    of arbitrary bytes into the snapshot as an export or import name.
    """
    if off < 0 or off >= len(data):
        raise PEError("string offset outside file")
    end = data.find(b"\0", off, off + limit)
    if end < 0:
        raise PEError(f"unterminated string at 0x{off:x}")
    return data[off:end].decode("latin-1")


class PETruncatedExports(PEError):
    """Export names could be read only partially; ``partial`` holds what was read."""

    def __init__(self, message: str, dll_name: Optional[str], partial: list):
        super().__init__(message)
        self.dll_name = dll_name
        self.partial = partial


def parse_exports(data: bytes, hdr: PEHeader) -> tuple[Optional[str], list[str]]:
    """
    Повертає (ім'я DLL з export directory, список іменованих експортів).

    Якщо таблиця імен читається не до кінця — PETruncatedExports з уже
    прочитаними іменами. Раніше тут був мовчазний `break`: DLL із пошкодженим
    другим RVA давала exports_count = 1 і pe_error = None, а наступний diff —
    сотні «вилучених» експортів.
    """
    rva, size = hdr.data_dirs[0]
    if not rva:
        return None, []
    off = rva_to_offset(hdr, rva)
    if off + 40 > len(data):
        raise PEError("truncated export directory")
    (_chars, _ts, _maj, _min, name_rva, _base, _nfuncs, nnames,
     _addr_funcs, addr_names, _addr_ords) = struct.unpack_from("<IIHHIIIIIII", data, off)
    dll_name = read_cstring(data, rva_to_offset(hdr, name_rva)) if name_rva else None
    names: list[str] = []
    if nnames and addr_names:
        if nnames > 65535:
            raise PETruncatedExports(f"implausible NumberOfNames {nnames}", dll_name, names)
        tbl = rva_to_offset(hdr, addr_names)
        for i in range(nnames):
            if tbl + 4 * i + 4 > len(data):
                raise PETruncatedExports(
                    f"export name table truncated at {i} of {nnames}", dll_name, names)
            name_rva_i = struct.unpack_from("<I", data, tbl + 4 * i)[0]
            try:
                names.append(read_cstring(data, rva_to_offset(hdr, name_rva_i)))
            except PEError as e:
                raise PETruncatedExports(
                    f"export name {i} of {nnames} unreadable: {e}", dll_name, names) from e
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
                # Старий (VC6) формат, attrs bit 0 = 0: поля — VA, а не RVA. Він
                # існує лише для PE32; у PE32+ ImageBase ≥ 2^32 і 32-бітне поле
                # ніколи не могло його перевищити — тому для 64 біт це завжди RVA.
                if not (attrs & 1) and hdr.bitness == 32 and name_ref >= hdr.image_base:
                    name_ref -= hdr.image_base
                add(read_cstring(data, rva_to_offset(hdr, name_ref)))
        except PEError:
            pass
    return found


_VS_SIG = b"\xBD\x04\xEF\xFE"
_VS_ROOT_KEY = "VS_VERSION_INFO".encode("utf-16le") + b"\0\0"
RT_VERSION = 16


def find_version_resource(data: bytes, hdr: PEHeader) -> Optional[bytes]:
    """
    Байти RT_VERSION-ресурсу цього PE (обхід дерева .rsrc), або None.

    Раніше версія шукалась сигнатурою по всьому файлу, і для PE, що несе
    інший PE всередині (EUSignAgent.exe, EKAlmaz1CConfiguration.exe,
    інсталятори-обгортки), у snapshot могла потрапити версія вкладеного
    файлу — а `file_version` є ключем реєстру і полем diff.
    """
    rva, _size = hdr.data_dirs[2]
    if not rva:
        return None
    base = rva_to_offset(hdr, rva)

    def entries(off: int):
        if off + 16 > len(data):
            raise PEError("truncated resource directory")
        named, ids = struct.unpack_from("<HH", data, off + 12)
        if named + ids > 4096:
            raise PEError("implausible resource directory")
        for i in range(named + ids):
            e = off + 16 + 8 * i
            if e + 8 > len(data):
                raise PEError("truncated resource directory entry")
            yield struct.unpack_from("<II", data, e)

    def leaf(off: int, depth: int) -> Optional[bytes]:
        # Level 2 (name) → level 3 (language) → IMAGE_RESOURCE_DATA_ENTRY.
        for _name, target in entries(off):
            if target & 0x80000000:
                if depth >= 3:
                    continue
                found = leaf(base + (target & 0x7FFFFFFF), depth + 1)
                if found is not None:
                    return found
                continue
            d = base + target
            if d + 8 > len(data):
                raise PEError("truncated resource data entry")
            data_rva, data_size = struct.unpack_from("<II", data, d)
            start = rva_to_offset(hdr, data_rva)
            return data[start:start + data_size]
        return None

    for name, target in entries(base):
        if name == RT_VERSION and target & 0x80000000:
            return leaf(base + (target & 0x7FFFFFFF), 2)
    return None


def _version_nodes(data: bytes, start: int, end: int):
    """
    Вузли VS_VERSIONINFO-дерева в [start, end): (key, value_off, node_end, wtype,
    wvaluelen, children_off). Кожен вузол: wLength, wValueLength, wType, ключ
    UTF-16 з NUL, вирівнювання на 4, значення, вирівнювання, діти.
    """
    pos = start
    while pos + 6 <= end:
        wlen, wvlen, wtype = struct.unpack_from("<HHH", data, pos)
        if wlen < 6 or pos + wlen > end:
            return
        key_end = data.find(b"\0\0", pos + 6, pos + wlen)
        while key_end >= 0 and (key_end - pos) % 2:
            key_end = data.find(b"\0\0", key_end + 1, pos + wlen)
        if key_end < 0:
            return
        key = data[pos + 6:key_end].decode("utf-16le", errors="replace")
        value_off = key_end + 2
        value_off += (-(value_off - start)) % 4
        value_len = wvlen * 2 if wtype == 1 else wvlen
        children = value_off + value_len
        children += (-(children - start)) % 4
        yield key, value_off, pos + wlen, wtype, wvlen, children
        pos += wlen
        pos += (-(pos - start)) % 4


def _version_root(data: bytes) -> Optional[int]:
    """Зсув вузла VS_VERSION_INFO: початок даних або перший справжній збіг."""
    pos = -1
    while True:
        pos = data.find(_VS_ROOT_KEY, pos + 1)
        if pos < 0:
            return None
        node = pos - 6
        if node < 0:
            continue
        wlen = struct.unpack_from("<H", data, node)[0]
        if wlen >= 6 + len(_VS_ROOT_KEY) and node + wlen <= len(data):
            return node


def parse_version_info(data: bytes) -> dict:
    """
    Обхід VS_VERSIONINFO: {"fixed": {...} | None, "strings": {key: value}}.

    ``data`` — сам ресурс (find_version_resource) або будь-які байти, що його
    містять. Рядки беруться лише з вузлів StringFileInfo → StringTable →
    String, а не з першого-ліпшого збігу ключа: сирий пошук міг прочитати як
    значення CompanyName текст іншого ключа.
    """
    out: dict = {"fixed": None, "strings": {}}
    root = _version_root(data)
    if root is None:
        return out
    wlen = struct.unpack_from("<H", data, root)[0]
    for key, voff, nend, _wt, wvlen, children in _version_nodes(data, root, root + wlen):
        if key != "VS_VERSION_INFO":
            return out
        if wvlen >= 52 and data[voff:voff + 4] == _VS_SIG:
            (_sig, struc_ver, fv_ms, fv_ls, pv_ms, pv_ls) = struct.unpack_from(
                "<IIIIII", data, voff)
            if struc_ver >> 16 == 1:
                out["fixed"] = {
                    "file_version": f"{fv_ms >> 16}.{fv_ms & 0xFFFF}.{fv_ls >> 16}.{fv_ls & 0xFFFF}",
                    "product_version": f"{pv_ms >> 16}.{pv_ms & 0xFFFF}.{pv_ls >> 16}.{pv_ls & 0xFFFF}",
                }
        for ckey, _cv, cend, _ct, _cw, cchildren in _version_nodes(data, children, nend):
            if ckey != "StringFileInfo":
                continue
            for _tkey, _tv, tend, _tt, _tw, tchildren in _version_nodes(data, cchildren, cend):
                for skey, sv, send, _st, swvlen, _sc in _version_nodes(data, tchildren, tend):
                    if skey in out["strings"] or not swvlen:
                        continue
                    # Value = rest of the String node up to its NUL; wValueLength
                    # is in WORDs per spec but some linkers write bytes.
                    raw = data[sv:send]
                    text = raw.decode("utf-16le", errors="replace").split("\0", 1)[0].strip()
                    if text:
                        out["strings"][skey] = text
        break
    return out


def parse_fixed_file_info(data: bytes) -> Optional[dict]:
    """VS_FIXEDFILEINFO з кореня VS_VERSIONINFO (див. parse_version_info)."""
    return parse_version_info(data)["fixed"]


def parse_string_file_info(data: bytes, keys: Iterable[str] = VERSION_KEYS) -> dict:
    """Рядки StringFileInfo (лише ``keys``) — див. parse_version_info."""
    strings = parse_version_info(data)["strings"]
    return {k: strings[k] for k in keys if k in strings}


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
        # NUL-термінатор виглядають як перший UTF-16-символ.
        #
        # Раніше перший символ відрізався, щойно байт перед збігом був
        # друкованим — і це різало справжні рядки: b"ABC" + L"KM.PKCS11.dll"
        # давало вигадану залежність "m.pkcs11.dll". Тепер відрізаємо лише
        # коли ASCII-пробіг, що закінчується на першому символі, сам є рядком
        # (довжина >= min_len), тобто його побачив би й ASCII-екстрактор.
        start = m.start()
        if start >= 1 and 0x20 <= data[start - 1] <= 0x7E:
            run, i = 1, start - 1  # data[start] + printable bytes before it
            while i >= 0 and 0x20 <= data[i] <= 0x7E and run < min_len:
                run += 1
                i -= 1
            if run >= min_len:
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
    errors: list[str] = []
    try:
        vres = find_version_resource(data, hdr)
    except PEError as e:
        errors.append(f"version resource: {e}")
        vres = None
    vinfo = parse_version_info(vres) if vres else {"fixed": None, "strings": {}}
    fixed = vinfo["fixed"] or {}
    sfi = {k: vinfo["strings"][k] for k in VERSION_KEYS if k in vinfo["strings"]}
    # Same source order for both fields — the numeric VS_FIXEDFILEINFO (what
    # Windows itself reports), the free-text StringFileInfo only as fallback.
    # file_version used to prefer the text and product_version the number, so
    # one record could mix the two. On every real IIT file the two FileVersion
    # sources agree, so committed snapshots do not change.
    rec.file_version = fixed.get("file_version") or sfi.get("FileVersion")
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
        except PETruncatedExports as e:
            errors.append(f"exports: {e}")
            rec.export_name, exports = e.dll_name, e.partial
        except PEError as e:
            errors.append(f"exports: {e}")
            exports = []
        imports = parse_import_dlls(data, hdr)
    rec.pe_error = "; ".join(errors) or None
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
            # лише ім'я каталогу — без локальних абсолютних шляхів; "." → справжнє ім'я
            "root": Path(root).name or Path(root).resolve().name,
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
    """
    {norm_name: [record, …]} — EVERY record, grouped by name.

    The previous index keyed by (name, bitness) and renamed same-key
    duplicates to "name#2", a key no lookup ever built — so those records were
    unreachable and a self-diff reported them as removed. Grouping keeps all of
    them visible; pairing is done by _pair_group().
    """
    idx: dict = {}
    for f in iter_files(inv):
        idx.setdefault(norm_name(f["name"]), []).append(f)
    return idx


def _bitness_compatible(a: dict, b: dict) -> bool:
    """Known and different bitness never match: x64 is not an update of x86."""
    ba, bb = a.get("bitness"), b.get("bitness")
    return ba is None or bb is None or ba == bb


def _find(idx: dict, name: str, bitness, sha: Optional[str] = None) -> Optional[dict]:
    """
    One record for (name, bitness) — for Δ columns and the registry.

    Order: same sha, then same bitness, then a record whose bitness is unknown
    (hand-transcribed baselines). Never a record of a different known bitness:
    the old name-only fallback turned "x64 build removed, x86 build added" into
    a fabricated downgrade 1.0.1.9 → 1.0.1.7.
    """
    group = idx.get(norm_name(name), [])
    probe = {"bitness": bitness}
    if sha:
        for r in group:
            if r.get("sha256") == sha and _bitness_compatible(r, probe):
                return r
    for r in group:
        if bitness is not None and r.get("bitness") == bitness:
            return r
    for r in group:
        if _bitness_compatible(r, probe):
            return r
    return None


def _pair_group(base: list, cur: list) -> tuple[list, list, list]:
    """
    Pair the records of one file name across two inventories.

    Returns (pairs, unmatched_base, unmatched_cur). Pairing order, most
    certain first: identical sha256 → same known bitness (and relpath when
    that disambiguates) → unknown bitness on either side. Records of different
    known bitness are never paired.
    """
    base, cur = list(base), list(cur)
    pairs = []

    def take(pred):
        for c in list(cur):
            for b in base:
                if pred(b, c):
                    pairs.append((b, c))
                    base.remove(b)
                    cur.remove(c)
                    break

    take(lambda b, c: b.get("sha256") and b.get("sha256") == c.get("sha256")
         and _bitness_compatible(b, c))
    take(lambda b, c: b.get("bitness") is not None and b.get("bitness") == c.get("bitness")
         and b.get("relpath") and b.get("relpath") == c.get("relpath"))
    take(lambda b, c: b.get("bitness") is not None and b.get("bitness") == c.get("bitness"))
    take(_bitness_compatible)
    return pairs, base, cur


def _record_label(rec: dict, dup_names: set) -> str:
    """Name, or relpath when the name repeats; "(x64)" marks the 64-bit build."""
    label = rec["name"]
    if norm_name(rec["name"]) in dup_names and rec.get("relpath"):
        label = rec["relpath"]
    return label + (" (x64)" if rec.get("bitness") == 64 else "")


def _dup_names(idx: dict) -> set:
    return {k for k, recs in idx.items() if len(recs) > 1}


_DIFF_FIELDS = ("sha256", "size", "file_version", "product_version", "pe_timestamp",
                "machine", "company", "is_pkcs11", "exports_count",
                "mech_dword_all_present", "mech_dword_hits")


def diff_inventories(baseline: dict, current: dict) -> dict:
    """
    Порівнює лише поля, присутні з обох боків; списки експортів — як ± множини.

    «Без змін» — лише коли sha256 є з обох боків і збігається. Раніше пара без
    жодного спільного поля (напр. baseline зі старою схемою) теж потрапляла в
    «без змін», хоча не було порівняно нічого; тепер це «не перевірено»
    (ключ ``unverified``, лише якщо такі є).
    """
    base_idx = index_records(baseline)
    cur_idx = index_records(current)
    base_dups, cur_dups = _dup_names(base_idx), _dup_names(cur_idx)
    added, removed, changed, unchanged, unverified = [], [], [], [], []
    pairs = []
    for name in sorted(set(base_idx) | set(cur_idx)):
        p, lone_base, lone_cur = _pair_group(base_idx.get(name, []), cur_idx.get(name, []))
        pairs += p
        removed += [_record_label(r, base_dups) for r in lone_base]
        added += [_record_label(r, cur_dups) for r in lone_cur]

    for base, cur in pairs:
        bitness = cur.get("bitness")
        label = _record_label(cur, cur_dups)
        delta: dict = {}
        for fld in _DIFF_FIELDS:
            b, c = base.get(fld), cur.get(fld)
            if b is not None and c is not None and b != c:
                delta[fld] = [b, c]
        for fld in ("exports", "c_exports", "import_dlls", "dynamic_deps", "cap_refs"):
            if base.get(fld) is not None and cur.get(fld) is not None:
                b, c = set(base[fld]), set(cur[fld])
                if b != c:
                    delta[fld + "_added"] = sorted(c - b)
                    delta[fld + "_removed"] = sorted(b - c)
        entry = {"name": cur["name"], "label": label, "bitness": bitness}
        if cur.get("relpath"):
            entry["relpath"] = cur["relpath"]
        if delta:
            entry.update(delta)
            changed.append(entry)
        elif base.get("sha256") and cur.get("sha256"):
            unchanged.append(label)
        else:
            unverified.append(label)
    out = {"baseline": baseline.get("label"), "current": current.get("label"),
           "added": sorted(added), "removed": sorted(removed),
           "changed": sorted(changed, key=lambda e: e["name"].lower()),
           "unchanged": sorted(unchanged)}
    if unverified:
        out["unverified"] = sorted(unverified)
    return out


def fmt_size(n) -> str:
    return "—" if n is None else f"{n:,}".replace(",", " ")


def short_sha(s) -> str:
    if not s:
        return "—"
    return s if len(s) <= 16 else f"{s[:8]}…{s[-6:]}"


def _md_cell(v) -> str:
    """Markdown table cell: '|' escaped, line breaks flattened (both split rows)."""
    text = str(v if v is not None else "—")
    return " ".join(text.splitlines()).replace("|", "\\|")


def _md_table(headers: list[str], rows: list[list]) -> str:
    # Headers come from snapshot labels (JSON) and cells from strings read out
    # of the binaries — neither is trusted to be Markdown-safe.
    out = ["| " + " | ".join(_md_cell(h) for h in headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _delta_mark(base: Optional[dict], cur: dict) -> str:
    if base is None:
        return "new"
    bs, cs = base.get("sha256"), cur.get("sha256")
    bv, cv = base.get("file_version"), cur.get("file_version")
    # "=" only on real evidence: None == None used to print "identical".
    if bs and cs and bs == cs:
        return "="
    if bv and cv and bv != cv:
        return f"{bv} → {cv}"
    if not (bs and cs):
        return "?"
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
            row.append(_delta_mark(_find(idx, f["name"], f.get("bitness"), f.get("sha256")), f))
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
        if d.get("unverified"):
            L.append(f"- Не перевірено — немає sha256 з обох боків "
                     f"({len(d['unverified'])}): {', '.join(d['unverified'])}")
        L.append(f"- Змінено ({len(d['changed'])}):")
        for e in d["changed"]:
            parts = []
            for k, v in e.items():
                if k in ("name", "label", "relpath", "bitness"):
                    continue
                if isinstance(v, list) and len(v) == 2 and not k.endswith(("_added", "_removed")):
                    a, b = v
                    if k == "sha256":
                        a, b = short_sha(a), short_sha(b)
                    parts.append(f"{k}: {a} → {b}")
                elif isinstance(v, dict):
                    parts.append(f"{k}: {v}")
                elif v:
                    parts.append(f"{k}: {', '.join(map(str, v))}")
            L.append(f"  - `{e.get('label', e['name'])}`: " + "; ".join(parts))
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
    # One row per (file, bitness). The previous name-only lookup took whichever
    # of an x86/x64 pair came first and silently dropped the other build.
    rows_keys: dict[tuple, str] = {}
    for s in snapshots:
        for f in iter_files(s):
            rows_keys.setdefault((norm_name(f["name"]), f.get("bitness")), f["name"])
    # A bitness-less row only survives if no snapshot knows that file's bitness.
    known = {k for (k, b) in rows_keys if b is not None}
    rows_keys = {kb: n for kb, n in rows_keys.items() if kb[1] is not None or kb[0] not in known}
    order = sorted(rows_keys, key=lambda kb: (not is_critical(rows_keys[kb]), kb[0], kb[1] or 0))
    L = ["# Реєстр DLL IIT — версії по snapshot-ах", "",
         "Згенеровано `scripts/iit_inventory.py --registry`. Клітинка: `версія · build · sha256[:8]`; "
         "`=` — той самий sha, що в попередній колонці; `—` — файла немає у snapshot.", ""]
    rows = []
    for key in order:
        name, bitness = key[0], key[1]
        shown = rows_keys[key] + (" (x64)" if bitness == 64 else "")
        crit = is_critical(rows_keys[key])
        row = [("**" if crit else "") + shown + ("**" if crit else "")]
        prev_sha = None
        for idx in idxs:
            f = _find(idx, name, bitness)
            if f is None:
                row.append("—")
                # "=" means "same as the previous column"; after a gap that
                # column is "—", so a reappearing file must print in full.
                prev_sha = None
                continue
            sha = f.get("sha256")
            same = [r for r in idx.get(name, []) if _bitness_compatible(r, {"bitness": bitness})]
            extra = f" (+{len(same) - 1})" if len(same) > 1 else ""
            if sha and sha == prev_sha and not extra:
                row.append("=")
            else:
                row.append(f"{f.get('file_version') or '?'} · {f.get('pe_timestamp') or '?'} · "
                           f"`{(sha or '')[:8]}`{extra}")
            prev_sha = sha
        rows.append(row)
    L.append(_md_table(["Файл"] + labels, rows))
    L.append("")
    return "\n".join(L)


_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._+-]")


def _safe_filename_part(text: str) -> str:
    """Version strings come out of the binary: '/', '\\', ':' are not filename-safe.

    ':' is the worst on NTFS — "X.dll@repro:0x1234.txt" writes an alternate
    data stream of "X.dll@repro" and leaves an empty visible file.
    """
    return _UNSAFE_FILENAME_RE.sub("_", text).strip(".") or "unknown"


def write_export_lists(inv: dict, out_dir: Path) -> list[Path]:
    """Один текстовий файл на модуль: `<Name>@<FileVersion>.txt` — відсортовані експорти."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for f in iter_files(inv):
        if not f.get("exports"):
            continue
        ver = f.get("file_version") or f.get("pe_timestamp") or "unknown"
        suffix = "-x64" if f.get("bitness") == 64 else ""
        stem = f"{_safe_filename_part(f['name'])}@{_safe_filename_part(ver)}{suffix}"
        p = out_dir / f"{stem}.txt"
        n = 2
        while p in written:
            # Same name + version + bitness in two directories (Libraries\x86
            # and a patch dir): the second write silently replaced the first.
            p = out_dir / f"{stem}-{n}.txt"
            n += 1
        if n > 2:
            print(f"warning: {f.get('relpath') or f['name']}: export list name "
                  f"collision, written as {p.name}", file=sys.stderr)
        p.write_text("\n".join(f["exports"]) + "\n", encoding="utf-8", newline="\n")
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


def _write_text(path: str, text: str) -> None:
    """LF on every OS: the outputs are committed, CRLF would rewrite every line."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(text, encoding="utf-8", newline="\n")


# Options that mean nothing in --registry mode (it only reads JSON snapshots).
_NON_REGISTRY_OPTS = ("label", "installers", "baseline", "snapshot_label", "source",
                      "json_out", "exports_dir", "full", "deep_all")


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.registry:
        # nargs="+" swallows everything after --registry, so "a.json b.json dir/"
        # used to end in an IsADirectoryError traceback.
        bad = [p for p in args.registry + args.paths if not Path(p).is_file()]
        if bad:
            parser.error(f"--registry expects JSON snapshot files, not: {', '.join(bad)}")
        if args.paths:
            args.registry += args.paths
        ignored = [o for o in _NON_REGISTRY_OPTS if getattr(args, o)]
        if args.engine != "stdlib":
            ignored.append("engine")
        if ignored:
            parser.error("не діє в режимі --registry: "
                         + ", ".join("--" + o.replace("_out", "").replace("_", "-")
                                     for o in ignored))
        snaps = [_load_json(p) for p in args.registry]
        md = render_registry(snaps)
        if args.md_out:
            _write_text(args.md_out, md)
        else:
            print(md)
        return 0

    if not args.paths:
        parser.error("вкажи каталоги з розпакованими пакетами або --registry")
    if len(args.label) > len(args.paths):
        parser.error(f"--label задано {len(args.label)} раз(и), а каталогів {len(args.paths)}")
    if args.label and len(args.label) < len(args.paths):
        print(f"warning: --label given for {len(args.label)} of {len(args.paths)} "
              f"directories; the rest use the directory name", file=sys.stderr)
    packages = []
    for i, p in enumerate(args.paths):
        root = Path(p)
        if not root.is_dir():
            parser.error(f"не каталог: {p}")
        default = root.name or root.resolve().name
        packages.append((args.label[i] if i < len(args.label) else default, root))

    inv = build_inventory(packages, _installer_paths(args.installers), engine=args.engine,
                          deep_all=args.deep_all, label=args.snapshot_label, source=args.source)
    diffs = []
    for b in args.baseline:
        base = _load_json(b)
        diffs.append((diff_inventories(base, inv), index_records(base)))
    if diffs:
        inv["diffs"] = [d for d, _ in diffs]

    # Render before writing anything, so a failure here does not leave a
    # half-written set of outputs behind.
    md = render_markdown(inv, diffs, full=args.full)
    if args.json_out:
        _write_text(args.json_out, json.dumps(inv, ensure_ascii=False, indent=1) + "\n")
    if args.exports_dir:
        write_export_lists(inv, Path(args.exports_dir))
    if args.md_out:
        _write_text(args.md_out, md)
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
