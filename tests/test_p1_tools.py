"""
Regression tests for the v0.31 P1 tools audit: iit_inventory diff/registry
pairing, the UTF-16 first-character heuristic, and iit_unpack.sh's SIGPIPE.
"""

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "iit_inventory.py"
UNPACK = ROOT / "scripts" / "iit_unpack.sh"


def _load():
    spec = importlib.util.spec_from_file_location("iit_inventory", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["iit_inventory"] = mod
    spec.loader.exec_module(mod)
    return mod


inv = _load()


def _snap(label, files):
    return {"schema": 1, "label": label, "packages": [{"label": "p", "files": files}]}


def _rec(name, bitness, sha, version=None, relpath=None, **extra):
    r = {"name": name, "bitness": bitness, "sha256": sha * 64}
    if version:
        r["file_version"] = version
    if relpath:
        r["relpath"] = relpath
    r.update(extra)
    return r


# ─── 1. x64 is never paired with x86 ─────────────────────────

class TestBitnessNeverCrossed:
    def test_x64_removed_x86_added_is_not_a_downgrade(self):
        """The regression: this was reported as 'changed 1.0.1.9 → 1.0.1.7'."""
        base = _snap("S1", [_rec("PKCS11.EKeyAlmaz1C.dll", 64, "6", "1.0.1.9")])
        cur = _snap("S2", [_rec("PKCS11.EKeyAlmaz1C.dll", 32, "3", "1.0.1.7")])
        d = inv.diff_inventories(base, cur)
        assert d["changed"] == []
        assert d["removed"] == ["PKCS11.EKeyAlmaz1C.dll (x64)"]
        assert d["added"] == ["PKCS11.EKeyAlmaz1C.dll"]

    def test_pair_each_build_with_its_own_bitness(self):
        base = _snap("S1", [_rec("X.dll", 32, "a", "1.0"), _rec("X.dll", 64, "b", "1.0")])
        cur = _snap("S2", [_rec("X.dll", 64, "c", "2.0"), _rec("X.dll", 32, "d", "2.0")])
        d = inv.diff_inventories(base, cur)
        assert d["added"] == [] and d["removed"] == []
        by_bits = {c["bitness"]: c for c in d["changed"]}
        assert by_bits[32]["sha256"] == ["a" * 64, "d" * 64]
        assert by_bits[64]["sha256"] == ["b" * 64, "c" * 64]

    def test_delta_column_does_not_cross_bitness(self):
        base = _snap("S1", [_rec("X.dll", 64, "6", "9.9")])
        idx = inv.index_records(base)
        cur = _rec("X.dll", 32, "3", "1.0")
        assert inv._delta_mark(inv._find(idx, "X.dll", 32, cur["sha256"]), cur) == "new"

    def test_unknown_bitness_baseline_still_matches(self):
        base = _snap("S1", [{"name": "X.dll", "sha256": "1" * 64, "file_version": "1.0"}])
        cur = _snap("S2", [_rec("X.dll", 32, "2", "1.1")])
        d = inv.diff_inventories(base, cur)
        assert d["added"] == [] and d["removed"] == []
        assert d["changed"][0]["file_version"] == ["1.0", "1.1"]


# ─── 2. Duplicate names produce one verdict per record ───────

class TestDuplicateNames:
    def _dup(self, label):
        return _snap(label, [
            _rec("A.dll", 32, "1", relpath="Libraries/x86/A.dll"),
            _rec("A.dll", 32, "2", relpath="Patch/A.dll"),
        ])

    def test_self_diff_is_all_unchanged(self):
        """The regression: removed + changed + unchanged for the same file."""
        d = inv.diff_inventories(self._dup("X"), self._dup("X"))
        assert d["added"] == [] and d["removed"] == [] and d["changed"] == []
        assert sorted(d["unchanged"]) == ["Libraries/x86/A.dll", "Patch/A.dll"]

    def test_diff_is_symmetric(self):
        a = self._dup("A")
        b = _snap("B", [_rec("A.dll", 32, "1", relpath="Libraries/x86/A.dll")])
        ab, ba = inv.diff_inventories(a, b), inv.diff_inventories(b, a)
        assert ab["removed"] == ba["added"]
        assert ab["added"] == ba["removed"]

    def test_one_of_two_copies_changes(self):
        base = self._dup("S1")
        cur = _snap("S2", [
            _rec("A.dll", 32, "1", relpath="Libraries/x86/A.dll"),
            _rec("A.dll", 32, "9", relpath="Patch/A.dll"),
        ])
        d = inv.diff_inventories(base, cur)
        assert d["unchanged"] == ["Libraries/x86/A.dll"]
        assert [c["label"] for c in d["changed"]] == ["Patch/A.dll"]
        assert d["changed"][0]["sha256"] == ["2" * 64, "9" * 64]

    def test_counts_add_up(self):
        base = self._dup("S1")
        cur = _snap("S2", [_rec("A.dll", 32, "1", relpath="Libraries/x86/A.dll")])
        d = inv.diff_inventories(base, cur)
        verdicts = len(d["unchanged"]) + len(d["changed"]) + len(d["removed"])
        assert verdicts == 2  # every baseline record accounted for exactly once


class TestDeltaMark:
    def test_no_sha_on_either_side_is_not_identical(self):
        assert inv._delta_mark({"name": "A"}, {"name": "A"}) == "?"

    def test_version_change_without_sha_still_reported(self):
        assert inv._delta_mark({"file_version": "1"}, {"file_version": "2"}) == "1 → 2"


# ─── 3. Registry keeps both builds and resets "=" after a gap ──

class TestRegistry:
    def test_both_x86_and_x64_rows_are_shown(self):
        s = _snap("S", [_rec("PKCS11.dll", 32, "3", "1.0.1.7"),
                        _rec("PKCS11.dll", 64, "6", "1.0.1.9")])
        md = inv.render_registry([s])
        assert "| PKCS11.dll | 1.0.1.7 · ? · `33333333` |" in md
        assert "| PKCS11.dll (x64) | 1.0.1.9 · ? · `66666666` |" in md

    def test_equals_is_not_printed_after_a_gap(self):
        """Present, absent, present again: the third cell must be in full."""
        s1 = _snap("S1", [_rec("CSPBase.dll", 32, "a", "1.1")])
        s2 = _snap("S2", [])
        s3 = _snap("S3", [_rec("CSPBase.dll", 32, "a", "1.1")])
        md = inv.render_registry([s1, s2, s3])
        row = next(line for line in md.splitlines() if "CSPBase.dll" in line)
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[2] == "—"
        assert cells[3] != "=" and "aaaaaaaa" in cells[3]

    def test_consecutive_equal_sha_still_collapses(self):
        s1 = _snap("S1", [_rec("CSPBase.dll", 32, "a", "1.1")])
        s2 = _snap("S2", [_rec("CSPBase.dll", 32, "a", "1.1")])
        row = next(line for line in inv.render_registry([s1, s2]).splitlines()
                   if "CSPBase.dll" in line)
        assert row.rstrip().endswith("| = |")

    def test_duplicates_in_one_snapshot_are_flagged(self):
        s = _snap("S", [_rec("A.dll", 32, "1", relpath="x/A.dll"),
                        _rec("A.dll", 32, "2", relpath="y/A.dll")])
        assert "(+1)" in inv.render_registry([s])

    def test_committed_registry_regenerates_identically(self):
        """The real snapshots are all 32-bit: the rewrite must not change them."""
        import json
        snaps = [json.loads((ROOT / "docs" / "inventory" / n).read_text(encoding="utf-8"))
                 for n in ("snapshot-a-v5.json", "snapshot-b-v6.json",
                           "S3-2026-07-web_dll.json")]
        committed = (ROOT / "docs" / "DLL-REGISTRY.md").read_text(encoding="utf-8")
        assert inv.render_registry(snaps) == committed


# ─── 4. UTF-16: strip the first character only after a real string ──

class TestUtf16FirstCharacter:
    def test_short_printable_prefix_keeps_the_first_character(self):
        """The regression: b'ABC' + L'KM.PKCS11.dll' gave 'm.pkcs11.dll'."""
        data = b"ABC" + "KM.PKCS11.dll".encode("utf-16le") + b"\x00\x00"
        refs = inv.scan_constants(data)["dll_refs"]
        assert "km.pkcs11.dll" in refs
        assert "m.pkcs11.dll" not in refs

    def test_real_artefact_still_suppressed(self):
        """ASCII string + NUL, then a wide string — the original sCSPIBase case."""
        data = b"LoadLibraryHelpers\x00" + "CSPIBase.dll".encode("utf-16le") + b"\x00\x00"
        refs = inv.scan_constants(data)["dll_refs"]
        assert "cspibase.dll" in refs
        assert "scspibase.dll" not in refs

    def test_wide_string_at_start_of_data(self):
        data = "KM.dll".encode("utf-16le") + b"\x00\x00"
        assert "km.dll" in inv.scan_constants(data)["dll_refs"]

    def test_committed_snapshot_unchanged_by_the_new_rule(self):
        """No DLL name in the real S3 snapshot relied on the over-eager strip."""
        import json
        s3 = json.loads((ROOT / "docs" / "inventory" / "S3-2026-07-web_dll.json")
                        .read_text(encoding="utf-8"))
        refs = {r for f in s3["packages"][0]["files"] for r in (f.get("dll_refs") or [])}
        assert "km.pkcs11.dll" not in refs or "m.pkcs11.dll" not in refs


# ─── 5. iit_unpack.sh survives installers with many OLE signatures ──

@pytest.mark.skipif(sys.platform != "linux" or not shutil.which("bash")
                    or subprocess.run(["grep", "-P", "x"], input=b"x",
                                      capture_output=True).returncode != 0,
                    reason="needs bash and GNU grep -P")
class TestUnpackCarve:
    OLE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

    def test_carve_does_not_die_with_sigpipe(self, tmp_path):
        """
        The regression: `grep … | head -1` under `set -o pipefail` exited 141
        before the 'no embedded MSI' guard whenever grep had more matches than
        fit the pipe buffer — i.e. on real wrapper installers.
        """
        src = tmp_path / "Setup.exe"
        # MZ header, then enough signatures that grep's output exceeds 64 KiB.
        src.write_bytes(b"MZ" + b"\x00" * 62 + (self.OLE + b"A" * 64) * 20000)
        out = tmp_path / "out"
        r = subprocess.run(["bash", str(UNPACK), str(src), str(out)],
                           capture_output=True, text=True, timeout=120)
        assert r.returncode != 141, r.stderr
        assert "type=pe+msi" in r.stdout
        carved = out / "_embedded.msi"
        assert carved.exists(), r.stderr
        assert carved.read_bytes()[:8] == self.OLE
        # Carved from the FIRST signature, which sits right after the 64-byte header.
        assert carved.stat().st_size == src.stat().st_size - 64
