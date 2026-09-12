"""
Tests for scripts/iit_inventory.py — the stdlib PE parser, constant scan, diff,
markdown/registry rendering and CLI. No real IIT binaries: a tiny synthetic PE
is built in-memory (`_tiny_pe`). pefile is optional (cross-check test skips).
"""

import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "iit_inventory.py"


def _load():
    spec = importlib.util.spec_from_file_location("iit_inventory", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["iit_inventory"] = mod  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(mod)
    return mod


inv = _load()


# ─── synthetic PE builder ───────────────────────────────────

def _align(n, a):
    return (n + a - 1) // a * a


def _vs_versioninfo(file_version=(1, 0, 1, 7), strings=None):
    """Minimal VS_VERSIONINFO blob: fixed info + StringFileInfo/StringTable/String*."""
    strings = strings or {"FileVersion": ".".join(map(str, file_version)), "CompanyName": 'АТ "ІІТ"'}

    def block(key, value_bytes, wtype, children=b""):
        key_b = key.encode("utf-16le") + b"\0\0"
        head_len = 6 + len(key_b)
        pad1 = (-head_len) % 4
        body = value_bytes
        pad2 = (-(head_len + pad1 + len(body))) % 4 if children else 0
        total = head_len + pad1 + len(body) + pad2 + len(children)
        wvalue = len(value_bytes) // 2 if wtype == 1 else len(value_bytes)
        return struct.pack("<HHH", total, wvalue, wtype) + key_b + b"\0" * pad1 + body + b"\0" * pad2 + children

    ms = (file_version[0] << 16) | file_version[1]
    ls = (file_version[2] << 16) | file_version[3]
    fixed = struct.pack("<IIIIIIIIIIIII", 0xFEEF04BD, 0x00010000, ms, ls, ms, ls,
                        0x3F, 0, 4, 2, 0, 0, 0)
    items = b"".join(block(k, v.encode("utf-16le") + b"\0\0", 1) for k, v in strings.items())
    table = block("040904B0", b"", 1, items)
    sfi = block("StringFileInfo", b"", 1, table)
    return block("VS_VERSION_INFO", fixed, 0, sfi)


def _tiny_pe(bitness=32, exports=("C_GetFunctionList", "C_Initialize", "EUInit"),
             imports=("cspbase.dll", "kernel32.dll"), version=(1, 0, 1, 7),
             extra=b"", dll_name="Fake.dll", timestamp=1672531200):
    """Build a minimal but well-formed PE with one .rdata section."""
    sec_rva = 0x1000
    sec_raw = 0x400
    blob = bytearray()

    def put(b, align=4):
        while len(blob) % align:
            blob.append(0)
        off = len(blob)
        blob.extend(b)
        return sec_rva + off

    # export names first (RVAs needed by the tables)
    name_rvas = [put(n.encode() + b"\0", 1) for n in exports]
    dllname_rva = put(dll_name.encode() + b"\0", 1)
    names_tbl = put(b"".join(struct.pack("<I", r) for r in name_rvas))
    ords_tbl = put(b"".join(struct.pack("<H", i) for i in range(len(exports))))
    funcs_tbl = put(b"".join(struct.pack("<I", sec_rva + 0x3F0) for _ in exports))
    export_dir_rva = put(struct.pack("<IIHHIIIIIII", 0, timestamp, 0, 0, dllname_rva, 1,
                                     len(exports), len(exports), funcs_tbl, names_tbl, ords_tbl))
    export_size = 40
    # imports: descriptors + thunks + names
    imp_names = [put(n.encode() + b"\0", 1) for n in imports]
    hint_names = [put(b"\0\0" + b"Func\0", 2) for _ in imports]
    thunk_fmt, thunk_size = ("<Q", 8) if bitness == 64 else ("<I", 4)
    thunks = [put(struct.pack(thunk_fmt, h) + b"\0" * thunk_size, thunk_size) for h in hint_names]
    desc = b"".join(struct.pack("<IIIII", t, 0, 0, n, t) for t, n in zip(thunks, imp_names))
    import_dir_rva = put(desc + b"\0" * 20)
    import_size = len(desc) + 20
    put(_vs_versioninfo(version))
    put(extra, 1)
    put(b"\xC3", 1)  # dummy function body
    raw_size = _align(len(blob), 0x200)
    blob.extend(b"\0" * (raw_size - len(blob)))

    e_lfanew = 0x40
    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", e_lfanew)
    opt_size = 240 if bitness == 64 else 224
    chars = 0x2102 if bitness == 64 else 0x2102 | 0x0100
    coff = struct.pack("<HHIIIHH", 0x8664 if bitness == 64 else 0x014C, 1, timestamp, 0, 0, opt_size, chars)
    dirs = [(0, 0)] * 16
    dirs[0] = (export_dir_rva, export_size)
    dirs[1] = (import_dir_rva, import_size)
    dirs_b = b"".join(struct.pack("<II", *d) for d in dirs)
    if bitness == 64:
        opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, raw_size, 0, 0, sec_rva + 0x3F0, sec_rva)
        opt += struct.pack("<QIIHHHHHHIIIIHHQQQQII", 0x180000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                           0x2000, sec_raw, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        opt = struct.pack("<HBBIIIIII", 0x10B, 14, 0, raw_size, 0, 0, sec_rva + 0x3F0, sec_rva, sec_rva)
        opt += struct.pack("<IIIHHHHHHIIIIHHIIIIII", 0x10000000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0,
                           0x2000, sec_raw, 0, 2, 0, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += dirs_b
    assert len(opt) == opt_size
    section = struct.pack("<8sIIIIIIHHI", b".rdata", raw_size, sec_rva, raw_size, sec_raw,
                          0, 0, 0, 0, 0x40000040)
    headers = dos + b"PE\0\0" + coff + opt + section
    headers += b"\0" * (sec_raw - len(headers))
    return bytes(headers + blob)


EXTRA = (b"1.2.804.2.1.1.1.1.3.1.1.2.7\0" + b"CKM_DSTU4145\0" + b"CKA_VALUE\0"
         + "KM.dll".encode("utf-16le") + b"\0\0" + b"%s\\DSTU4145CacheP2.cap\0"
         + b"D:\\build\\Fake.pdb\0" + struct.pack("<I", 0x80420031) * 2
         + struct.pack("<I", 0x80420014) + b"LoadLibrary PKIFormats.dll\0")


# ─── PE header / exports / imports ──────────────────────────

class TestPEParser:
    @pytest.mark.parametrize("bits", [32, 64])
    def test_header_bitness(self, bits):
        hdr = inv.parse_pe_header(_tiny_pe(bitness=bits))
        assert hdr.bitness == bits
        assert hdr.is_dll is True
        assert hdr.sections[0].name == ".rdata"
        assert inv.pe_timestamp_iso(hdr.timestamp) == "2023-01-01"

    def test_not_pe_raises(self):
        with pytest.raises(inv.PEError):
            inv.parse_pe_header(b"not a pe at all" * 10)
        with pytest.raises(inv.PEError):
            inv.parse_pe_header(b"MZ" + b"\0" * 100)

    def test_exports_and_pkcs11_detection(self):
        data = _tiny_pe()
        hdr = inv.parse_pe_header(data)
        name, exports = inv.parse_exports(data, hdr)
        assert name == "Fake.dll"
        assert exports == ["C_GetFunctionList", "C_Initialize", "EUInit"]

    @pytest.mark.parametrize("bits", [32, 64])
    def test_import_dlls(self, bits):
        data = _tiny_pe(bitness=bits, imports=("KERNEL32.dll", "CSPBase.dll"))
        hdr = inv.parse_pe_header(data)
        assert inv.parse_import_dlls(data, hdr) == ["kernel32.dll", "cspbase.dll"]

    def test_fixed_file_info(self):
        assert inv.parse_fixed_file_info(_tiny_pe(version=(1, 3, 1, 222)))["file_version"] == "1.3.1.222"
        assert inv.parse_fixed_file_info(b"\0" * 100) is None
        # signature without a valid dwStrucVersion is rejected
        assert inv.parse_fixed_file_info(b"\xBD\x04\xEF\xFE" + b"\x00" * 60) is None

    def test_string_file_info_utf16(self):
        sfi = inv.parse_string_file_info(_tiny_pe())
        assert sfi["FileVersion"] == "1.0.1.7"
        assert sfi["CompanyName"] == 'АТ "ІІТ"'

    def test_repro_timestamp(self):
        assert inv.pe_timestamp_iso(0x12345678 + 2**31).startswith("repro:0x")
        assert inv.pe_timestamp_iso(100).startswith("repro:0x")


# ─── strings / constants ────────────────────────────────────

class TestScan:
    def test_scan_constants(self):
        c = inv.scan_constants(_tiny_pe(extra=EXTRA))
        assert "1.2.804.2.1.1.1.1.3.1.1.2.7" in c["oids"]
        assert c["ckm_names"] == ["CKA_VALUE", "CKM_DSTU4145"]
        assert "km.dll" in c["dll_refs"]            # UTF-16 string
        assert "ekm.dll" not in c["dll_refs"]       # "sCSPIBase.dll"-style artefact suppressed
        assert "pkiformats.dll" in c["dll_refs"]    # inside a longer ASCII string
        assert c["cap_refs"] == ["DSTU4145CacheP2.cap"]
        assert c["pdb"] == ["D:\\build\\Fake.pdb"]
        assert c["mech_dword_hits"]["0x80420031"] == 2
        assert c["mech_dword_hits"]["0x80420014"] == 1
        assert c["mech_dword_hits"]["0x80420032"] == 0
        assert c["mech_dword_all_present"] is False

    def test_mechanism_ids_in_sync_with_module(self):
        sys.path.insert(0, str(ROOT))
        from mechanism_ids import IIT_MECHANISMS
        assert set(inv.IIT_MECHANISM_IDS) == set(IIT_MECHANISMS)
        assert len(inv.IIT_MECHANISM_IDS) == 12

    def test_detect_installer_type(self):
        ole = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\0" * 8
        assert inv.detect_installer_type(ole, ole) == "msi"
        pe = b"MZ" + b"\0" * 14
        assert inv.detect_installer_type(pe, pe + b"...Inno Setup Setup Data (6.3.3)...") == "inno 6.3.3"
        assert inv.detect_installer_type(pe, pe + b"Nullsoft Install System") == "nsis"
        assert inv.detect_installer_type(pe, pe + b"xx" + ole) == "pe+msi"
        assert inv.detect_installer_type(pe, pe + b"MSCF") == "cab-sfx"
        assert inv.detect_installer_type(pe, pe) == "pe"
        assert inv.detect_installer_type(b"7z\xBC\xAF\x27\x1C", b"") == "7z"
        assert inv.detect_installer_type(b"garbage", b"garbage") == "unknown"


# ─── inventory of a directory ───────────────────────────────

@pytest.fixture
def pkg_dir(tmp_path):
    d = tmp_path / "pkg"
    (d / "Libraries" / "x86").mkdir(parents=True)
    (d / "Libraries" / "x86" / "PKCS11.EKeyAlmaz1C.dll").write_bytes(_tiny_pe(extra=EXTRA))
    (d / "Libraries" / "x64").mkdir()
    (d / "Libraries" / "x64" / "PKCS11.EKeyAlmaz1C.dll").write_bytes(_tiny_pe(bitness=64, version=(1, 0, 1, 9)))
    (d / "Other.dll").write_bytes(_tiny_pe(exports=("Foo",), dll_name="Other.dll"))
    (d / "DSTU4145Parameters.cap").write_bytes(b"\x30\x03\x02\x01\x00")
    (d / "broken.dll").write_bytes(b"MZ" + b"\0" * 200)
    return d


class TestInventory:
    def test_records(self, pkg_dir):
        recs = {(r.relpath): r for r in inv.inventory_dir(pkg_dir, "test")}
        x86 = recs["Libraries/x86/PKCS11.EKeyAlmaz1C.dll"]
        assert x86.is_pe and x86.bitness == 32 and x86.is_pkcs11 and x86.critical and x86.deep
        assert x86.file_version == "1.0.1.7" and x86.company == 'АТ "ІІТ"'
        assert x86.c_exports == ["C_GetFunctionList", "C_Initialize"]
        assert x86.dynamic_deps == ["km.dll", "pkiformats.dll"]  # cspbase.dll is imported
        assert x86.mech_dword_hits["0x80420031"] == 2
        assert x86.export_name == "Fake.dll"
        x64 = recs["Libraries/x64/PKCS11.EKeyAlmaz1C.dll"]
        assert x64.bitness == 64 and x64.file_version == "1.0.1.9"
        other = recs["Other.dll"]
        assert other.is_pe and not other.is_pkcs11 and not other.critical and not other.deep
        assert other.exports is None and other.exports_count == 1
        cap = recs["DSTU4145Parameters.cap"]
        assert cap.kind == "cap" and cap.is_pe is False and len(cap.sha256) == 64
        broken = recs["broken.dll"]
        assert broken.is_pe is False and broken.pe_error

    def test_build_inventory_summary(self, pkg_dir):
        out = inv.build_inventory([("test", pkg_dir)], label="S9", source="unit")
        assert out["schema"] == 1 and out["label"] == "S9"
        s = out["packages"][0]["summary"]
        assert (s["files"], s["pe"], s["x86"], s["x64"], s["cap"]) == (5, 3, 2, 1, 1)
        assert s["pkcs11_modules"] == ["PKCS11.EKeyAlmaz1C.dll", "PKCS11.EKeyAlmaz1C.dll"]
        json.dumps(out)  # serialisable

    def test_describe_installer(self, tmp_path):
        p = tmp_path / "Setup.exe"
        p.write_bytes(_tiny_pe() + b"Inno Setup Setup Data (6.2.0)")
        d = inv.describe_installer(p)
        assert d["installer_type"] == "inno 6.2.0" and d["bitness"] == 32
        assert d["pe_timestamp"] == "2023-01-01" and len(d["sha256"]) == 64

    @pytest.mark.skipif(importlib.util.find_spec("pefile") is None, reason="pefile not installed")
    def test_pefile_engine_matches_stdlib(self, pkg_dir):
        a = {r.relpath: r for r in inv.inventory_dir(pkg_dir, "t", engine="stdlib")}
        b = {r.relpath: r for r in inv.inventory_dir(pkg_dir, "t", engine="pefile")}
        for rel in ("Libraries/x86/PKCS11.EKeyAlmaz1C.dll", "Libraries/x64/PKCS11.EKeyAlmaz1C.dll", "Other.dll"):
            for fld in ("bitness", "pe_timestamp", "exports_count", "c_exports", "is_pkcs11", "import_dlls", "sha256"):
                assert getattr(a[rel], fld) == getattr(b[rel], fld), (rel, fld)


# ─── diff / registry / markdown ─────────────────────────────

def _snap(label, files):
    return {"schema": 1, "label": label, "packages": [{"label": "p", "files": files}]}


class TestDiff:
    def test_added_removed_changed_unchanged(self):
        base = _snap("A", [
            {"name": "CSPBase.dll", "bitness": 32, "sha256": "a" * 64, "file_version": "1.1.0.173", "size": 10},
            {"name": "Gone.dll", "bitness": 32, "sha256": "g" * 64},
            {"name": "Same.dll", "bitness": 32, "sha256": "s" * 64, "exports": ["X", "Y"]},
        ])
        cur = _snap("C", [
            {"name": "CSPBase.dll", "bitness": 32, "sha256": "b" * 64, "file_version": "1.1.0.174", "size": 11},
            {"name": "New.dll", "bitness": 32, "sha256": "n" * 64},
            {"name": "Same.dll", "bitness": 32, "sha256": "s" * 64, "exports": ["X", "Y"]},
        ])
        d = inv.diff_inventories(base, cur)
        assert d["added"] == ["New.dll"] and d["removed"] == ["Gone.dll"] and d["unchanged"] == ["Same.dll"]
        assert len(d["changed"]) == 1
        ch = d["changed"][0]
        assert ch["file_version"] == ["1.1.0.173", "1.1.0.174"] and ch["size"] == [10, 11]

    def test_export_set_diff_and_underscore_dot_equivalence(self):
        base = _snap("B", [{"name": "KM_PKCS11.dll", "sha256": "1" * 64, "exports": ["KMGetInterface"]}])
        cur = _snap("C", [{"name": "KM.PKCS11.dll", "bitness": 32, "sha256": "2" * 64,
                           "exports": ["KMGetInterface", "KMFinalize"]}])
        d = inv.diff_inventories(base, cur)
        assert d["added"] == [] and d["removed"] == []
        assert d["changed"][0]["exports_added"] == ["KMFinalize"]

    def test_baseline_without_bitness_matches_any(self):
        base = _snap("B", [{"name": "X.dll", "sha256": "1" * 64}])
        cur = _snap("C", [{"name": "x.DLL", "bitness": 64, "sha256": "1" * 64}])
        assert inv.diff_inventories(base, cur)["unchanged"] == ["x.DLL"]

    def test_duplicate_names_with_different_sha_are_kept(self):
        cur = _snap("C", [{"name": "A.dll", "bitness": 32, "sha256": "1" * 64},
                          {"name": "A.dll", "bitness": 32, "sha256": "2" * 64}])
        assert len(inv.index_records(cur)) == 2


class TestRender:
    def test_markdown_sections(self, pkg_dir):
        out = inv.build_inventory([("test", pkg_dir)], label="S9")
        base = _snap("A", [{"name": "PKCS11.EKeyAlmaz1C.dll", "bitness": 32, "sha256": "0" * 64,
                            "file_version": "1.0.1.5"}])
        md = inv.render_markdown(out, [(inv.diff_inventories(base, out), inv.index_records(base))], full=True)
        assert "# Інвентар IIT — S9" in md
        assert "| PKCS11.EKeyAlmaz1C.dll | 32 | 1.0.1.7 |" in md
        assert "1.0.1.5 → 1.0.1.7" in md
        assert "Diff vs A" in md and "Усі файли" in md
        assert "DSTU4145CacheP2.cap" in md
        assert "sha256" not in md.split("SHA256 критичних файлів")[1][:5]  # code block, not table

    def test_registry_matrix(self):
        s1 = _snap("S1", [{"name": "CSPBase.dll", "sha256": "a" * 64, "file_version": "1.1.0.173", "pe_timestamp": "2025-06-18"}])
        s2 = _snap("S2", [{"name": "CSPBase.dll", "sha256": "a" * 64, "file_version": "1.1.0.173", "pe_timestamp": "2025-06-18"},
                          {"name": "Other.dll", "sha256": "o" * 64}])
        md = inv.render_registry([s1, s2])
        assert "| **CSPBase.dll** | 1.1.0.173 · 2025-06-18 · `aaaaaaaa` | = |" in md
        assert "| Other.dll | — | ? · ? · `oooooooo` |" in md

    def test_fmt_helpers(self):
        assert inv.fmt_size(1239688) == "1 239 688" and inv.fmt_size(None) == "—"
        assert inv.short_sha("0123456789abcdef" * 4) == "01234567…abcdef"
        assert inv.norm_name("KM_PKCS11.DLL") == inv.norm_name("km.pkcs11.dll")


# ─── CLI ────────────────────────────────────────────────────

class TestCLI:
    def test_end_to_end(self, pkg_dir, tmp_path, capsys):
        base = tmp_path / "base.json"
        base.write_text(json.dumps(_snap("A", [{"name": "Other.dll", "sha256": "z" * 64}])), encoding="utf-8")
        inst = tmp_path / "Setup.msi"
        inst.write_bytes(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\0" * 64)
        js, md, exp = tmp_path / "out.json", tmp_path / "out.md", tmp_path / "exports"
        rc = inv.main([str(pkg_dir), "--label", "pkg", "--installers", str(inst),
                       "--baseline", str(base), "--snapshot-label", "S9", "--source", "unit",
                       "--json", str(js), "--md", str(md), "--exports-dir", str(exp)])
        assert rc == 0
        data = json.loads(js.read_text(encoding="utf-8"))
        assert data["label"] == "S9" and data["installers"][0]["installer_type"] == "msi"
        assert data["diffs"][0]["changed"][0]["name"] == "Other.dll"
        assert "Інсталятори" in md.read_text(encoding="utf-8")
        assert sorted(p.name for p in exp.iterdir()) == ["PKCS11.EKeyAlmaz1C.dll@1.0.1.7.txt",
                                                          "PKCS11.EKeyAlmaz1C.dll@1.0.1.9-x64.txt"]
        out = capsys.readouterr().out
        assert "pkg: 5 files, PE 3" in out and "diff vs A" in out

    def test_registry_mode(self, tmp_path, capsys):
        p = tmp_path / "s.json"
        p.write_text(json.dumps(_snap("S1", [{"name": "CSPBase.dll", "sha256": "a" * 64}])), encoding="utf-8")
        assert inv.main(["--registry", str(p)]) == 0
        assert "| **CSPBase.dll** |" in capsys.readouterr().out

    def test_requires_paths(self):
        with pytest.raises(SystemExit):
            inv.main([])
