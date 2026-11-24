"""Mutation fuzz of the two PE readers: sedo/check.py pe_bitness and scripts/iit_inventory.py."""
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import N, SEED, TESTS, TMP, finding, main, rnd, save, tb_key  # noqa: E402

import sedo.check as chk  # noqa: E402

# The PE images are built in memory by the tests' own builder: no binary of
# any vendor is read, and none is ever written outside the private temp dir.
sys.path.insert(0, str(TESTS))
import test_iit_inventory as tii  # noqa: E402

inv = tii.inv

SEEDS = [tii._tiny_pe(32), tii._tiny_pe(64), tii._tiny_pe(32, exports=()), tii._tiny_pe(64, imports=()),
         tii._tiny_pe(32, extra=b"CKM_DSTU4145\0PKCS11.EKeyAlmaz1C.dll\0" + struct.pack("<I", 0x80420031)),
         tii._tiny_pe(32, exports=tuple(f"C_F{i}" for i in range(40)))]
INTERESTING = [0, 1, 2, 4, 8, 0x10, 0x28, 0x3C, 0x40, 0x7F, 0x80, 0xFF, 0x100, 0x400, 0x1000, 0x1001, 0x7FFF, 0x8000,
               0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFF000]


def mutate(data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rnd.choice([1, 1, 1, 2, 3, 6])):
        kind = rnd.randrange(8)
        if not b:
            break
        pos = rnd.randrange(len(b))
        if kind == 0:
            b[pos] = rnd.randrange(256)
        elif kind == 1 and pos + 4 <= len(b):
            struct.pack_into("<I", b, pos & ~3 if rnd.random() < .7 else pos, rnd.choice(INTERESTING))
        elif kind == 2 and pos + 2 <= len(b):
            struct.pack_into("<H", b, pos & ~1, rnd.choice(INTERESTING) & 0xFFFF)
        elif kind == 3:
            del b[pos:]                                    # truncate
        elif kind == 4:
            del b[pos:pos + rnd.choice([1, 2, 4, 40, 512])]
        elif kind == 5:
            b[pos:pos] = bytes(rnd.randrange(256) for _ in range(rnd.choice([1, 4, 40])))
        elif kind == 6 and pos + 4 <= len(b):
            v = struct.unpack_from("<I", b, pos & ~3)[0]
            struct.pack_into("<I", b, pos & ~3, (v + rnd.choice([-1, 1, 4, -4, 0x1000, -0x1000])) & 0xFFFFFFFF)
        else:
            span = rnd.choice([2, 4, 8, 40])
            src = rnd.randrange(len(b))
            b[pos:pos + span] = b[src:src + span]
    return bytes(b)


def one(data: bytes, i: int):
    f = TMP / "PKCS11.EKeyAlmaz1C.dll"                    # the name of a crypto module → deep scan
    f.write_bytes(data)
    # 1. sedo/check.py: must answer 32 / 64 / None, whatever the file is.
    try:
        bits = chk.pe_bitness(f)
        if bits not in (32, 64, None):
            finding("pe_bitness returns something else than 32/64/None", data[:80], repr(bits))
    except Exception as e:
        finding("pe_bitness: " + tb_key(e), data[:120].hex(), e)
    # 2. the inventory: one unreadable DLL must become pe_error, not abort the snapshot.
    t0 = time.monotonic()
    try:
        rec = inv.inventory_file(f, TMP, "fuzz", deep=True)
        json.dumps(rec.to_dict())
        md = inv.render_markdown({"label": "x", "generated": "x", "packages": [
            {"name": "fuzz", "root": str(TMP), "files": [rec.to_dict()], "summary": {}}], "installers": []})
        assert isinstance(md, str)
    except KeyError:
        pass                                             # render_markdown wants a full snapshot; not the target
    except Exception as e:
        finding("iit_inventory: " + tb_key(e), f"seed {SEED} case {i}, {len(data)} bytes", e)
        save(f"pe_crash_{SEED}_{i}.bin", data)
    dt = time.monotonic() - t0
    if dt > 2.0:
        finding("iit_inventory: one small file takes seconds (parser loop driven by file content?)",
                f"seed {SEED} case {i}: {dt:.1f}s for {len(data)} bytes")
        save(f"pe_slow_{SEED}_{i}.bin", data)
    # 3. direct calls: only PEError may leave the parsers.
    for name in ("parse_exports", "parse_import_dlls", "find_version_resource"):
        try:
            hdr = inv.parse_pe_header(data)
            getattr(inv, name)(data, hdr)
        except inv.PEError:
            pass
        except Exception as e:
            finding(f"{name}: " + tb_key(e), f"seed {SEED} case {i}", e)
            save(f"pe_{name}_{SEED}_{i}.bin", data)
    for name in ("parse_version_info", "parse_fixed_file_info", "parse_string_file_info"):
        try:
            getattr(inv, name)(data[rnd.randrange(max(1, len(data))):][:600])
        except inv.PEError:
            pass
        except Exception as e:
            finding(f"{name}: " + tb_key(e), f"seed {SEED} case {i}", e)
    try:
        inv.detect_installer_type(data[:4096], data)
    except Exception as e:
        finding("detect_installer_type: " + tb_key(e), f"seed {SEED} case {i}", e)


def fuzz_pe():
    # check.pe_bitness has its own tiny seed: the header the tests build, cut everywhere.
    head = bytearray(b"MZ" + b"\0" * 0x3E)
    struct.pack_into("<I", head, 0x3C, 0x40)
    tiny = bytes(head) + b"PE\0\0" + struct.pack("<H", 0x8664) + b"\0" * 20
    for cut in range(len(tiny) + 1):
        one(tiny[:cut], -cut)
    for i in range(N):
        seed = rnd.choice(SEEDS)
        one(mutate(seed) if rnd.random() < .9 else mutate(mutate(seed)), i)


if __name__ == "__main__":
    main("PE readers: sedo/check.py, scripts/iit_inventory.py", fuzz_pe)
