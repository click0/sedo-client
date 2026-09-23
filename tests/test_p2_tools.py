"""
Regression tests for the v0.31 P2 tools audit: PE parser robustness (header,
strings, exports, version resource, delay-load), diff verdicts, Markdown and
export-list output, the CLI, and iit_unpack.sh's tool checks.
"""

import importlib.util
import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from test_iit_inventory import _tiny_pe, _vs_versioninfo

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "iit_inventory.py"
UNPACK = ROOT / "scripts" / "iit_unpack.sh"


def _load():
    if "iit_inventory" in sys.modules:
        return sys.modules["iit_inventory"]
    spec = importlib.util.spec_from_file_location("iit_inventory", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["iit_inventory"] = mod
    spec.loader.exec_module(mod)
    return mod


inv = _load()


def _e_lfanew(data):
    return struct.unpack_from("<I", data, 0x3C)[0]


def _snap(label, files):
    return {"schema": 1, "label": label, "packages": [{"label": "p", "files": files}]}


# ─── M3: SizeOfOptionalHeader is checked ───────────────────

class TestOptionalHeaderSize:
    @pytest.mark.parametrize("size", [0, 95])
    def test_too_small_is_an_error_not_garbage_sections(self, size):
        """The regression: 0 read the section table out of the optional header."""
        data = bytearray(_tiny_pe())
        struct.pack_into("<H", data, _e_lfanew(data) + 4 + 16, size)
        with pytest.raises(inv.PEError, match="SizeOfOptionalHeader"):
            inv.parse_pe_header(bytes(data))

    def test_truncated_section_table_is_an_error(self):
        data = _tiny_pe()
        cut = _e_lfanew(data) + 24 + 224 + 20  # half of the only section header
        with pytest.raises(inv.PEError, match="truncated section table"):
            inv.parse_pe_header(data[:cut])

    def test_directories_beyond_the_header_are_ignored(self):
        """NumberOfRvaAndSizes = 16, but the header only has room for 2."""
        data = bytearray(_tiny_pe())
        opt = _e_lfanew(data) + 24
        struct.pack_into("<H", data, _e_lfanew(data) + 4 + 16, 96 + 8 * 2)
        data[opt + 112:opt + 152] = data[opt + 224:opt + 264]  # move section header
        hdr = inv.parse_pe_header(bytes(data))
        assert hdr.sections[0].name == ".rdata"
        assert hdr.data_dirs[0] != (0, 0) and hdr.data_dirs[1] != (0, 0)
        assert hdr.data_dirs[2:] == [(0, 0)] * 14


# ─── M4: an unterminated string is an error ────────────────

def test_read_cstring_unterminated():
    """The regression: returned 1 KiB of arbitrary bytes as a name."""
    with pytest.raises(inv.PEError, match="unterminated"):
        inv.read_cstring(b"A" * 5000, 0)
    assert inv.read_cstring(b"abc\0def", 0) == "abc"


# ─── H3: truncated export tables are reported ──────────────

def _corrupt_second_export_name(data: bytes) -> bytes:
    hdr = inv.parse_pe_header(data)
    off = inv.rva_to_offset(hdr, hdr.data_dirs[0][0])
    addr_names = struct.unpack_from("<I", data, off + 32)[0]
    tbl = inv.rva_to_offset(hdr, addr_names)
    out = bytearray(data)
    struct.pack_into("<I", out, tbl + 4, 0x7FFFFFF0)  # RVA outside all sections
    return bytes(out)


class TestTruncatedExports:
    def test_parse_exports_raises_with_the_partial_list(self):
        data = _corrupt_second_export_name(_tiny_pe())
        with pytest.raises(inv.PETruncatedExports) as e:
            inv.parse_exports(data, inv.parse_pe_header(data))
        assert e.value.partial == ["C_GetFunctionList"]
        assert e.value.dll_name == "Fake.dll"
        assert "1 of 3" in str(e.value)

    def test_inventory_records_the_error(self, tmp_path):
        """The regression: exports_count 1 with pe_error None — 'clean'."""
        p = tmp_path / "PKCS11.X.dll"
        p.write_bytes(_corrupt_second_export_name(_tiny_pe()))
        rec = inv.inventory_file(p, tmp_path, "pkg")
        assert rec.exports_count == 1
        assert rec.pe_error and "exports" in rec.pe_error


# ─── H5: the version comes from THIS file's resource ───────

class TestVersionResource:
    def test_embedded_payload_version_is_not_used(self, tmp_path):
        """
        An outer PE with no version resource that carries another PE (installer,
        EUSignAgent.exe…). The old whole-file scan reported the payload's
        version as the outer file's.
        """
        payload = _tiny_pe(version=(9, 9, 9, 9))
        outer = bytearray(_tiny_pe(version=(1, 0, 0, 1), extra=payload))
        # Drop the outer file's own resource directory.
        opt = _e_lfanew(outer) + 24
        struct.pack_into("<II", outer, opt + 96 + 8 * 2, 0, 0)
        p = tmp_path / "Setup.exe"
        p.write_bytes(bytes(outer))
        rec = inv.inventory_file(p, tmp_path, "pkg")
        assert rec.file_version is None
        assert rec.company is None

    def test_own_resource_wins_over_embedded_payload(self, tmp_path):
        payload = _tiny_pe(version=(9, 9, 9, 9))
        p = tmp_path / "EUSignAgent.exe"
        p.write_bytes(_tiny_pe(version=(1, 3, 1, 5), extra=payload))
        rec = inv.inventory_file(p, tmp_path, "pkg")
        assert rec.file_version == "1.3.1.5"

    def test_key_text_is_not_read_as_a_value(self):
        """The regression: CompanyName resolved to the literal "FileVersion"."""
        # A String node whose value happens to be another key's name must be
        # returned as that value — and a key text elsewhere in the blob that
        # is not a String node must not be picked up at all.
        blob = _vs_versioninfo(strings={"ProductName": "CompanyName",
                                        "FileVersion": "1.0"})
        noise = "CompanyName".encode("utf-16le") + b"\0\0" + b"\x04\x00\x01\x00"
        info = inv.parse_version_info(noise + blob)
        assert info["strings"] == {"ProductName": "CompanyName", "FileVersion": "1.0"}

    def test_file_and_product_version_same_source(self, tmp_path):
        """L6: both from VS_FIXEDFILEINFO when the text disagrees."""
        blob = _vs_versioninfo(file_version=(1, 2, 3, 4),
                               strings={"FileVersion": "1.2.3", "ProductVersion": "1.2"})
        info = inv.parse_version_info(blob)
        assert info["fixed"] == {"file_version": "1.2.3.4", "product_version": "1.2.3.4"}


# ─── L10: delay-load imports in PE32+ ──────────────────────

def _with_delay_import(bitness: int, dll: str = "DelayMe.dll", old_format=False) -> bytes:
    """Put a delay-load descriptor into the section's spare tail."""
    data = bytearray(_tiny_pe(bitness=bitness))
    hdr = inv.parse_pe_header(bytes(data))
    sec = hdr.sections[0]
    tail = sec.raw_ptr + sec.raw_size - 128
    rva = sec.va + (tail - sec.raw_ptr)
    name_rva = rva + 64
    data[tail + 64:tail + 64 + len(dll) + 1] = dll.encode() + b"\0"
    ref = name_rva + (hdr.image_base if old_format else 0)
    struct.pack_into("<II", data, tail, 0 if old_format else 1, ref & 0xFFFFFFFF)
    opt = _e_lfanew(data) + 24
    dirs = opt + (112 if bitness == 64 else 96)
    struct.pack_into("<II", data, dirs + 8 * 13, rva, 64)
    return bytes(data)


class TestDelayLoad:
    @pytest.mark.parametrize("bits", [32, 64])
    def test_rva_format(self, bits):
        data = _with_delay_import(bits)
        assert "delayme.dll" in inv.parse_import_dlls(data, inv.parse_pe_header(data))

    def test_old_va_format_pe32(self):
        data = _with_delay_import(32, old_format=True)
        assert "delayme.dll" in inv.parse_import_dlls(data, inv.parse_pe_header(data))

    def test_pe32_plus_attribute_zero_is_still_an_rva(self):
        """PE32+ has no VA format; the 64-bit image base can't fit 32 bits."""
        data = bytearray(_with_delay_import(64))
        hdr = inv.parse_pe_header(bytes(data))
        rva = hdr.data_dirs[13][0]
        struct.pack_into("<I", data, inv.rva_to_offset(hdr, rva), 0)  # attrs = 0
        assert "delayme.dll" in inv.parse_import_dlls(bytes(data), hdr)


# ─── M5: nothing compared is not "unchanged" ───────────────

class TestUnverified:
    def test_no_sha_on_one_side_is_unverified(self):
        base = _snap("A", [{"name": "X.dll", "bitness": 32, "file_version": "1.0",
                            "exports_count": 5}])
        cur = _snap("B", [{"name": "X.dll", "bitness": 32, "sha256": "a" * 64}])
        d = inv.diff_inventories(base, cur)
        assert d["unchanged"] == [] and d["changed"] == []
        assert d["unverified"] == ["X.dll"]
        assert inv.diff_inventories(cur, base)["unverified"] == ["X.dll"]

    def test_equal_sha_is_still_unchanged_and_no_unverified_key(self):
        rec = {"name": "X.dll", "bitness": 32, "sha256": "a" * 64}
        d = inv.diff_inventories(_snap("A", [rec]), _snap("B", [dict(rec)]))
        assert d["unchanged"] == ["X.dll"] and "unverified" not in d

    def test_mechanism_counts_are_diffed(self):
        base = {"name": "P.dll", "bitness": 32, "sha256": "a" * 64,
                "mech_dword_all_present": True, "mech_dword_hits": {"0x80420031": 40}}
        cur = dict(base, sha256="b" * 64, mech_dword_hits={"0x80420031": 1})
        d = inv.diff_inventories(_snap("A", [base]), _snap("B", [cur]))
        assert d["changed"][0]["mech_dword_hits"] == [{"0x80420031": 40}, {"0x80420031": 1}]

    def test_unverified_is_rendered(self):
        base = _snap("A", [{"name": "X.dll", "bitness": 32}])
        cur = _snap("B", [{"name": "X.dll", "bitness": 32, "sha256": "a" * 64, "size": 1}])
        cur["packages"][0]["summary"] = {"files": 1, "pe": 0, "x86": 0, "x64": 0, "dll": 1,
                                         "exe": 0, "cap": 0, "pkcs11_modules": []}
        cur["packages"][0]["root"] = "r"
        md = inv.render_markdown(cur, [(inv.diff_inventories(base, cur), inv.index_records(base))])
        assert "Не перевірено" in md and "X.dll" in md


# ─── M7 / L9: Markdown output ──────────────────────────────

class TestMarkdown:
    def test_header_pipe_is_escaped(self):
        md = inv._md_table(["File", "a|b"], [["x", "y"]])
        assert md.splitlines()[0] == "| File | a\\|b |"

    def test_cell_newline_does_not_split_the_row(self):
        md = inv._md_table(["File"], [["ver 1.0\nEVIL |row"]])
        assert md.splitlines() == ["| File |", "|---|", "| ver 1.0 EVIL \\|row |"]

    def test_registry_label_with_pipe(self):
        s = _snap("a|b", [{"name": "A.dll", "bitness": 32, "sha256": "1" * 64}])
        header = inv.render_registry([s]).splitlines()[4]
        assert header == "| Файл | a\\|b |"

    @pytest.mark.parametrize("value,out", [("abc", "abc"), ("", "—"), (None, "—"),
                                           ("a" * 64, "aaaaaaaa…aaaaaa")])
    def test_short_sha(self, value, out):
        assert inv.short_sha(value) == out


# ─── M6 / L7: export lists ─────────────────────────────────

class TestExportLists:
    def _inv(self, *files):
        return _snap("S", list(files))

    def test_unsafe_version_characters(self, tmp_path):
        out = tmp_path / "exports"
        written = inv.write_export_lists(self._inv(
            {"name": "EU.dll", "pe_timestamp": "repro:0xdeadbeef", "exports": ["A"]},
            {"name": "X.dll", "file_version": "2026/07/01", "exports": ["B"]},
            {"name": "Y.dll", "file_version": "../../etc", "exports": ["C"]},
        ), out)
        names = sorted(p.name for p in written)
        assert names == ["EU.dll@repro_0xdeadbeef.txt", "X.dll@2026_07_01.txt",
                         "Y.dll@_.._etc.txt"]
        assert all(p.parent == out for p in written)

    def test_collision_does_not_overwrite(self, tmp_path, capsys):
        written = inv.write_export_lists(self._inv(
            {"name": "KM.dll", "file_version": "1.0.1.13", "exports": ["A"], "relpath": "x86/KM.dll"},
            {"name": "KM.dll", "file_version": "1.0.1.13", "exports": ["B"], "relpath": "patch/KM.dll"},
        ), tmp_path)
        assert [p.name for p in written] == ["KM.dll@1.0.1.13.txt", "KM.dll@1.0.1.13-2.txt"]
        assert [p.read_text() for p in written] == ["A\n", "B\n"]
        assert "collision" in capsys.readouterr().err

    def test_lf_line_endings(self, tmp_path):
        (p,) = inv.write_export_lists(self._inv(
            {"name": "A.dll", "file_version": "1", "exports": ["X", "Y"]}), tmp_path)
        assert p.read_bytes() == b"X\nY\n"


# ─── L1–L5: CLI ────────────────────────────────────────────

class TestCLI:
    def _snapfile(self, tmp_path, name="s.json"):
        p = tmp_path / name
        p.write_text(json.dumps(_snap("S", [{"name": "A.dll", "sha256": "1" * 64}])))
        return p

    def test_registry_with_a_directory_is_a_usage_error(self, tmp_path, capsys):
        """The regression: nargs='+' swallowed the directory → IsADirectoryError."""
        s = self._snapfile(tmp_path)
        with pytest.raises(SystemExit) as e:
            inv.main(["--registry", str(s), str(tmp_path)])
        assert e.value.code == 2
        assert "JSON snapshot files" in capsys.readouterr().err

    def test_registry_md_into_a_new_directory(self, tmp_path):
        s = self._snapfile(tmp_path)
        out = tmp_path / "new" / "dir" / "R.md"
        assert inv.main(["--registry", str(s), "--md", str(out)]) == 0
        assert out.read_bytes().startswith("# Реєстр".encode())
        assert b"\r\n" not in out.read_bytes()

    @pytest.mark.parametrize("extra", [["--json", "x.json"], ["--full"], ["--engine", "pefile"],
                                       ["--baseline", "b.json"]])
    def test_registry_rejects_options_it_would_ignore(self, tmp_path, extra, capsys):
        s = self._snapfile(tmp_path)
        with pytest.raises(SystemExit):
            inv.main(["--registry", str(s)] + extra)
        assert "--registry" in capsys.readouterr().err

    def test_more_labels_than_directories(self, tmp_path):
        with pytest.raises(SystemExit):
            inv.main([str(tmp_path), "--label", "a", "--label", "b"])

    def test_fewer_labels_warns(self, tmp_path, capsys):
        (tmp_path / "d1").mkdir()
        (tmp_path / "d2").mkdir()
        inv.main([str(tmp_path / "d1"), str(tmp_path / "d2"), "--label", "only",
                  "--json", str(tmp_path / "o.json")])
        assert "1 of 2" in capsys.readouterr().err
        labels = [p["label"] for p in json.loads((tmp_path / "o.json").read_text())["packages"]]
        assert labels == ["only", "d2"]

    def test_dot_directory_gets_a_real_label(self, tmp_path, monkeypatch):
        d = tmp_path / "web_dll"
        d.mkdir()
        (d / "a.cap").write_bytes(b"x")
        monkeypatch.chdir(d)
        inv.main([".", "--json", str(tmp_path / "o.json")])
        pkg = json.loads((tmp_path / "o.json").read_text())["packages"][0]
        assert pkg["label"] == "web_dll" and pkg["root"] == "web_dll"

    def test_outputs_use_lf(self, tmp_path):
        d = tmp_path / "pkg"
        d.mkdir()
        (d / "PKCS11.Fake.dll").write_bytes(_tiny_pe())
        inv.main([str(d), "--json", str(tmp_path / "o.json"), "--md", str(tmp_path / "o.md")])
        for f in ("o.json", "o.md"):
            assert b"\r\n" not in (tmp_path / f).read_bytes()


# ─── unpack S2: missing strings / grep -P are reported ─────

@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("bash"),
                    reason="needs bash")
def test_unpack_reports_missing_strings(tmp_path):
    """The regression: without binutils Inno detection silently did nothing."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # A PATH with the basics but no `strings`.
    for tool in ("head", "od", "tr", "grep", "mkdir", "tail", "find", "wc", "cat"):
        src = shutil.which(tool)
        if src:
            os.symlink(src, bindir / tool)
    src = tmp_path / "Setup.exe"
    src.write_bytes(b"MZ" + b"\0" * 100)
    r = subprocess.run([shutil.which("bash"), str(UNPACK), str(src), str(tmp_path / "o")],
                       capture_output=True, text=True, env={"PATH": str(bindir)})
    assert r.returncode == 2
    assert "missing tool: strings" in r.stderr
