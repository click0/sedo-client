# Minimum deployment files

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.26
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

**Confirmed via LIEF + static analysis + ADDENDUM v1, v5, v6.**

---

## Scenario A: HW Almaz-1K (USB token)

### Required DLLs (4 files, ~2.0 MB)

```
PKCS11.EKeyAlmaz1C.dll    356-418 KB  v1.0.1.7   entry point (C_GetFunctionList)
CSPBase.dll               1 150 KB    v1.1.0.172  DSTU 4145/7564/7624 crypto
CSPExtension.dll             80 KB    v1.1.0.17   RNG self-test (BSI AIS 31)
PKIFormats.dll              975 KB    v1.2.0.163  ASN.1 / X.509 parser
                          ────────
                           ~2 560 KB
```

### Curve parameters (9 `.cap` files, ~2.5 MB)

```
DSTU4145Parameters.cap      352 B     OID mapping
DSTU4145CachePB.cap       1 725 KB    Polynomial Basis points
DSTU4145CacheNB.cap         784 KB    Normal Basis points
ECDHParameters.cap          352 B     ECDH params
ECDSAParameters.cap         572 B     ECDSA params (legacy)
GOST28147SBox.cap            80 B     GOST 28147 SBOX
GOST34311Parameters.cap      96 B     GOST 34.311 SBOX
PRNGParameters.cap           80 B     PRNG init
RSAParameters.cap            40 B     RSA (legacy)
```

**Total HW: ~4.6 MB.** All files must be in the same directory.

### System dependencies

- Windows 10/11 x64 (DLLs are 32-bit, run via WoW64)
- Smart Card service (`SCardSvr`) running
- Almaz-1K USB connected and recognized

---

## Scenario B: Virtual token (Key-6.dat, no USB)

All of Scenario A **plus** these additional DLLs:

```
PKCS11.Virtual.EKeyAlmaz1C.dll   968-1019 KB  v1.0.1.10  virtual entry point
EUSignCP.dll                     1 700 KB     v1.3.1.209 main crypto library
CSPIBase.dll                       ~600 KB               AES/SHA/RSA/DH/ECDSA (145 fns)
KM.dll                             170 KB    (2017-09)   base dispatcher
KM_FileSystem.dll                    84 KB    (2017-09)   Key-N.dat reader
```

The Virtual module reads `Key-6.dat` (first slot = `Key-6`, pattern `Key-%X.dat`).

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
├── KM_FileSystem.dll                # Virtual only
├── *.cap                            # 9 curve parameter files
└── Key-6.dat                        # Virtual only, private key
```

## Not required

Despite older guides, these are **NOT needed** for sedo-client PKCS#11 operation:

- `KM.EKeyAlmaz1C.dll` — the PKCS#11 module has its own USB path
- `KM.PKCS11.dll` — only needed if using IIT's internal PKCS#11 router
- `EUSignAgent.dll` — only for JSON-RPC (iit_agent backend)
- `NCHostCP.dll` — CA Gateway
- `CAGUI.dll` — GUI components
- IIT "User CSP" GUI — not needed for PKCS#11 backends

## Version drift warning

Two known DLL batches exist:

| DLL | v5 batch (2025) | v6 batch (2023-2024) |
|---|---|---|
| CSPBase.dll | 1.1.0.173 (2025-06) | 1.1.0.172 (2023-08) |
| PKIFormats.dll | 1.2.0.171 (2025-08) | 1.2.0.163 (2024-01) |
| KM*.dll | — | 2017-09 |

Mixing DLLs from different batches may cause version mismatches.
Use a single snapshot of all files from the same IIT installation.

## Verification

```powershell
python -c "
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load(r'C:\sedo-automation\libs\PKCS11.EKeyAlmaz1C.dll')
print('OK:', lib.getInfo().libraryDescription.strip())
"
```

Expected output:
```
OK: E.key_Almaz-1C_Library
```

If you see `DLL was not found` — check that CSPBase.dll and PKIFormats.dll
are in the same directory as the PKCS11 module.
