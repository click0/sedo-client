# PKCS#11 Mechanism IDs для Алмаз-1К

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.26
License:  BSD 3-Clause
Year:     2025-2026
```

## Джерело

Значення **підтверджено на живому токені** 2026-04-16 командою:

```powershell
pkcs11-tool.exe --module "C:\...\EKeys\Almaz1C\PKCS11.EKeyAlmaz1C.dll" --list-mechanisms
```

## Повний перелік mechanism IDs

| ID | Flags (з output pkcs11-tool) | Key size | Призначення |
|---|---|---|---|
| `0x80420011` | `hw, encrypt, decrypt` | {32,32} байт | Kalyna/ГОСТ симетричний шифр A |
| `0x80420012` | `hw, encrypt, decrypt` | {32,32} байт | симетричний шифр B |
| `0x80420013` | `hw, encrypt, decrypt` | {32,32} байт | симетричний шифр C |
| `0x80420014` | `hw, sign, verify` | {32,32} байт | **MAC** (HMAC/CMAC) — НЕ DSTU 4145! |
| `0x80420016` | `hw, wrap, unwrap` | {32,32} байт | DSTU 7624 key wrap |
| `0x80420021` | `hw, digest` | — | Kupyna хеш (DSTU 7564) |
| **`0x80420031`** | **`hw, sign, verify, EC F_2M, EC parameters, EC OID, EC compressed`** | **{163,509} біт** | **★ DSTU 4145 підпис (primary)** |
| `0x80420032` | `hw, sign, verify, EC F_2M, EC parameters, EC OID, EC compressed` | {163,509} біт | DSTU 4145 підпис (alternative) |
| `0x80420041` | `hw, generate` | {32,32} байт | symmetric key generation |
| `0x80420042` | `hw, generate_key_pair, EC F_2M, EC parameters, EC OID, EC compressed` | {163,509} біт | **DSTU 4145 KeyPair generation** |
| `0x80420043` | `hw, derive, EC F_2M, EC compressed` | {163,509} біт | DSTU ECDH derive A |
| `0x80420044` | `hw, derive, EC F_2M, EC compressed` | {163,509} біт | DSTU ECDH derive B |

## Ключові висновки

### DSTU 4145 підпис — `0x80420031`

Цей mechanism для підпису на Алмаз-1К. Flags:
- `sign, verify` — можна підписувати і верифікувати
- `EC F_2M` — elliptic curve над binary field GF(2^m)
- `EC parameters` — приймає `CK_ECDH1_DERIVE_PARAMS` з OID кривої
- `EC OID` — параметри через OID 1.2.804.2.1.1.1.1.3.1.1.2.{0-9}
- `EC compressed` — підтримує compressed public key
- Key size {163, 509} біт — всі 10 ДСТУ 4145 кривих (m=163, 167, 173, 179, 191, 233, 239, 257, 307, 367)

### Увага: `0x80420014` ≠ DSTU 4145

Попередній аналіз декомпозицією `C_GetMechanismInfo` помилково ідентифікував `0x80420014` як DSTU 4145. Насправді:
- Key size = 32 байти = 256 біт = **симетричний ключ**
- Немає прапорців `EC_F_2M`, `EC_OID`
- Це **HMAC/CMAC** (MAC на основі симетричного ключа)

### ДСТУ 4145 криві (OIDs)

| Короткий OID | m | Поле | Використання |
|---|---|---|---|
| `1.2.804.2.1.1.1.1.3.1.1.2.0` | 163 | GF(2^163) | legacy, short keys |
| `1.2.804.2.1.1.1.1.3.1.1.2.1` | 167 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.2` | 173 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.3` | 179 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.4` | 191 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.5` | 233 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.6` | 239 | | |
| **`1.2.804.2.1.1.1.1.3.1.1.2.7`** | **257** | **GF(2^257)** | **найпоширеніша для КЕП** |
| `1.2.804.2.1.1.1.1.3.1.1.2.8` | 307 | | |
| `1.2.804.2.1.1.1.1.3.1.1.2.9` | 367 | | |

## Порівняння з іншими PKCS#11 модулями

| Модуль | Виробник | DSTU 4145 ID | Підхід |
|---|---|---|---|
| **`PKCS11.EKeyAlmaz1C.dll`** | **IIT** | **0x80420031** | Vendor-defined (CKM_VENDOR_DEFINED + IIT tag) |
| `avcryptokinxt.dll` | ТОВ "Автор" | `0x00000352` | Standard PKCS#11 v3.0 `CKM_DSTU4145` |
| `efitkeynxt.dll` | EFIT | невідомо | |

У `mechanism_ids.py` є автоматичний detection через `detect_dstu4145_mechanism()`.

## Як використати

### OpenSC напряму

```powershell
pkcs11-tool.exe --module "...\PKCS11.EKeyAlmaz1C.dll" `
    --login --pin XXXX `
    --sign --mechanism 0x80420031 `
    --input-file data.bin --output-file sig.bin
```

### Python через PyKCS11

```python
import PyKCS11
from mechanism_ids import CKM_IIT_DSTU4145  # = 0x80420031

lib = PyKCS11.PyKCS11Lib()
lib.load(r"C:\...\PKCS11.EKeyAlmaz1C.dll")
session = lib.openSession(slot, PyKCS11.CKF_RW_SESSION | PyKCS11.CKF_SERIAL_SESSION)
session.login("XXXX")

key = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY)])[0]
mech = PyKCS11.Mechanism(CKM_IIT_DSTU4145, None)
signature = session.sign(key, data_bytes, mech)
```

### Python через OpenSC subprocess

```python
from opensc_signer import OpenSCSigner

signer = OpenSCSigner(
    module_path=r"C:\...\PKCS11.EKeyAlmaz1C.dll",
    mechanism="0x80420031"  # default
)
signer.login("XXXX")
signature = signer.sign(data_bytes)
```

## Reference

- PKCS#11 v2.40 Base specification: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
- PKCS#11 v3.0 Ukrainian addition (DSTU): https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/
- ДСТУ 4145-2002 (офіційно недоступний, платний)
