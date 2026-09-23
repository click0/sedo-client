# Minimum deployment files

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

**Confirmed via LIEF + static analysis + ADDENDUM v1, v5, v6.**

---

## Scenario A: HW Almaz-1K (USB token)

### Required DLLs (4 files, ~2.6 MB)

Sizes are the measured 32-bit files from `docs/inventory/*.json` (S1 = v5
batch 2025, S2 = v6 batch 2023-24, S3 = web batch 2026-07).

```
PKCS11.EKeyAlmaz1C.dll      356 KB   1.0.1.7 (S2)                entry point (C_GetFunctionList)
CSPBase.dll               1 211 KB   1.1.0.173 (S1), 1.1.0.174 (S3)  DSTU 4145/7564/7624 crypto
CSPExtension.dll             80 KB   1.1.0.17                    RNG self-test (BSI AIS 31)
PKIFormats.dll              982 KB   1.2.0.171 (S1, S3)          ASN.1 / X.509 parser
                          ────────
                          ~2 630 KB
```

### Curve parameters (`.cap` files)

```
# 9 small files — all present in the 2026 web batch (S3), 3 750 B together
DSTU4145Parameters.cap      352 B     OID mapping
DSTU7624SBox.cap          1 089 B     Kalyna S-box             (new in 2026 batch, EUSignCP loads it)
DSTU8845SBox.cap          1 089 B     Strumok S-box            (new in 2026 batch, EUSignCP loads it)
ECDHParameters.cap          352 B     ECDH params
ECDSAParameters.cap         572 B     ECDSA params (legacy)
GOST28147SBox.cap            80 B     GOST 28147 SBOX
GOST34311Parameters.cap      96 B     GOST 34.311 SBOX
PRNGParameters.cap           80 B     PRNG init
RSAParameters.cap            40 B     RSA (legacy)

# 2 large point caches — NOT in the 2026 web batch (see below)
DSTU4145CacheP2.cap       1 725 KB    Polynomial Basis points  (was DSTU4145CachePB.cap in 2023-25 batches)
DSTU4145CacheN2.cap         784 KB    Normal Basis points      (was DSTU4145CacheNB.cap)
```

The names are what the DLLs actually look for (strings in `CSPBase.dll` 1.1.0.174
and `EUSignCP.dll` 1.3.1.222 — see `docs/IIT-ANALYSIS-ADDENDUM-v7.md` §7). Take
the `.cap` set from the **same** installer as the DLLs; whether the two big
`Cache*` files are still shipped by the 2026 packages must be checked on a live
install (the web component archive did not contain them).

**Total HW: 4 DLL (~2.6 MB) + 9 small `.cap` (~4 KB), plus the 2 cache `.cap`
(~2.5 MB) if your installer ships them ≈ 2.6–5.1 MB.** A 4 KB `.cap` set is
therefore complete for the 9 small files; a missing cache shows up as
`CKR_GENERAL_ERROR` (ADDENDUM v7 §9.2). All files must be in the same directory.

### System dependencies

- Windows 10/11 x64 (DLLs are 32-bit, run via WoW64)
- Smart Card service (`SCardSvr`) running
- Almaz-1K USB connected and recognized

---

## Scenario B: Virtual token (Key-6.dat, no USB)

The shared crypto DLLs and `.cap` files from Scenario A (`CSPBase`,
`CSPExtension`, `PKIFormats`, the `.cap` set) — **without** `PKCS11.EKeyAlmaz1C.dll`,
which is the HW entry point and is not used — **plus** these additional DLLs
(see the directory layout below for what is HW-only / Virtual-only):

```
PKCS11.Virtual.EKeyAlmaz1C.dll     995 KB   1.0.1.10 (S2)                   virtual entry point
EUSignCP.dll                     1 800 KB   1.3.1.209 (S1, S2)              main crypto library
                                 1 821 KB   1.3.1.222 (S3)
CSPIBase.dll                     1 075 KB   1.0.0.29                        AES/SHA/RSA/DH/ECDSA (145 fns)
KM.dll                             166 KB   1.0.1.1 (2017-09)               base dispatcher
KM.FileSystem.dll                   83 KB   1.0.1.2 (2017-09)               Key-N.dat reader
```

The Virtual module reads `Key-6.dat` (first slot = `Key-6`, pattern `Key-%X.dat`).

**Names use a dot, not an underscore:** `KM.dll` loads its sub-modules by the
literal name `KM.<Type>.dll` (`KM.FileSystem.dll`, `KM.PKCS11.dll`). Older
guides wrote `KM_FileSystem.dll`; a file renamed that way is never found, and
the virtual token has no key-file backend.

**No USB token or Smart Card service needed.**

### Additional EUSignCP runtime dependencies

EUSignCP.dll lazy-loads optional modules via `LoadLibrary`:
`CAConnectors.dll`, `CAGUI.dll`, `LDAPClient.dll`, `QRCode.dll`,
`RF.dll`, `eXMLSecurity.dll`, `ePDFSecurity.dll`.
These are NOT required for sign/verify and can be omitted.

---

## Directory layout

```
libs/
├── PKCS11.EKeyAlmaz1C.dll          # HW
├── PKCS11.Virtual.EKeyAlmaz1C.dll  # Virtual only
├── CSPBase.dll
├── CSPExtension.dll
├── CSPIBase.dll                     # Virtual only
├── PKIFormats.dll
├── EUSignCP.dll                     # Virtual only
├── KM.dll                           # Virtual only
├── KM.FileSystem.dll                # Virtual only (dot, not underscore)
├── *.cap                            # 9 small + (if shipped) 2 cache files
└── Key-6.dat                        # Virtual only, private key
```

## Bitness: do not mix 32-bit and 64-bit

All IIT DLLs in a deployment **must be the same bitness** (all 32-bit or all
64-bit). Mixing causes `LoadLibrary` / `GetProcAddress` failures.

- HW module: 32-bit = ~356 KB, 64-bit = ~418 KB
- `pkcs11-tool` must also match the DLL bitness (32-bit OpenSC for 32-bit DLLs)
- Wine deployments: **always use 32-bit** (`WINEARCH=win32`)

## Not required

Despite older guides, these are **NOT needed** for sedo-client PKCS#11 operation:

- `KM.EKeyAlmaz1C.dll` — the PKCS#11 module has its own USB path
- `KM.PKCS11.dll` — only needed if using IIT's internal PKCS#11 router
- `EUSignAgent.dll` — only for JSON-RPC (iit_agent backend)
- `NCHostCP.dll` — CA Gateway
- `CAGUI.dll` — GUI components
- IIT "User CSP" GUI — not needed for PKCS#11 backends

## Version drift warning

Three known DLL batches exist (full matrix: `docs/DLL-REGISTRY.md`,
generated from `docs/inventory/*.json`):

| DLL | S1 = v5 batch (2025) | S2 = v6 batch (2023-2024) | S3 = web batch (2026-07) |
|---|---|---|---|
| CSPBase.dll | 1.1.0.173 (2025-06) | 1.1.0.172 (2023-08) | **1.1.0.174** (2026-06) |
| PKIFormats.dll | 1.2.0.171 (2025-08) | 1.2.0.163 (2024-01) | 1.2.0.171 (2026-07) — **same version, different sha256** |
| EUSignCP.dll | 1.3.1.209 (2025-11) | = S1 | **1.3.1.222** (2026-07) |
| KM.PKCS11.dll | — | 1.0.1.37 (2025-02) | **1.0.1.39** (2026-06) |
| KM.EKeyAlmaz1C.dll | — | 1.0.1.9 | **1.0.1.13** (2026-07) |
| KM.dll, KM.FileSystem.dll | — | 2017-09 | unchanged in the 2026 update (= S2) |
| PKCS11.EKeyAlmaz1C.dll | — | 1.0.1.7 | unchanged in the 2026 update (= S2) |

Mixing DLLs from different batches may cause version mismatches.
Use a single snapshot of all files from the same IIT installation, and
compare **sha256**, not the version string (PKIFormats 1.2.0.171 exists as two
different binaries).

## Verification

```powershell
python -c "
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load(r'C:\sedo-client\libs\PKCS11.EKeyAlmaz1C.dll')
print('OK:', lib.getInfo().libraryDescription.strip())
"
```

Expected output:
```
OK: E.key_Almaz-1C_Library
```

If you see `DLL was not found` — check that CSPBase.dll and PKIFormats.dll
are in the same directory as the PKCS11 module.
