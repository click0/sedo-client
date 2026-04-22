# IIT-ANALYSIS — Addendum 2026-04-22

> **Вхід:** 5 DLL, отриманих окремо від Web.zip.
> **Метод:** статичний аналіз (pefile, objdump, strings ASCII + UTF-16LE, RTTI class extraction, disasm окремих прологів).
> **Призначення:** доповнення до `docs/IIT-ANALYSIS.md` v0.26.

---

## 0. Summary найголовнішого

1. ✅ **`PKCS11.EKeyAlmaz1C.dll` знайдено.** Шлях В1 більше не заблокований.
2. ⚠️ **PKCS11-модуль має 3 runtime-LoadLibrary-залежності**, яких немає у статичному імпорт-таблиці → Мінімальний Список Файлів треба розширити.
3. ⚠️ **Усі 5 файлів — тільки 64-bit.** 32-bit варіант для `opensc_signer.py` (який ваш README вимагає через "32-bit OpenSC") відсутній.
4. ℹ️ Знайдено **Bluetooth LE варіант Алмаз-1К** — `KM.EKeyAlmaz1CBTA.dll`, використовує GATT замість WinSCard.
5. ℹ️ Два файли з набору — `EKeyCr1.dll` + `EKeyCr1CCID.dll` — **не для Алмаз-1К**, а для токена **Crystal-1** (старіший продукт IIT). До sedo-client не стосуються.

---

## 1. Ідентифікація файлів

Імена у сховищі Claude при передачі замінили `.` на `_` (підкреслення). Справжні імена взяті з `VS_VERSIONINFO.OriginalFilename`:

| Файл як надіслано | OriginalFilename | Ver | Build (UTC) | Size | Machine |
|---|---|---|---|---|---|
| `PKCS11_EKeyAlmaz1C.dll` | **`PKCS11.EKeyAlmaz1C.dll`** | 1.0.1.7 | 2023-02-02 16:30 | 418 832 | x64 |
| `KM_EKeyAlmaz1C.dll` | **`KM.EKeyAlmaz1C.dll`** | 1.0.1.9 | 2024-05-31 20:26 | 599 056 | x64 |
| `KM_EKeyAlmaz1CBTA.dll` | **`KM.EKeyAlmaz1CBTA.dll`** | 1.0.1.7 | 2021-06-17 15:30 | 292 280 | x64 |
| `EKeyCr1.dll` | `EKeyCr1.dll` | 1.1.2.8 | 2018-06-20 11:50 | 69 120 | x64 |
| `EKeyCr1CCID.dll` | `EKeyCr1CCID.dll` | 1.1.2.2 | 2019-05-16 16:10 | 125 968 | x64 |

SHA256:
```
3195e46a0f0e9b7e30fc0ae5bf06f9aeb93e1a37a5f9893e6082c3ca4365d53b  PKCS11.EKeyAlmaz1C.dll
03d34ac778737a895ec35197e0b8e4324705ba016e54b7ec91dc4f5a7f685765  KM.EKeyAlmaz1C.dll
f018b9aa710c602dedbe17399e3c4ad1263bd403a01513cd0a7bbc1ca08416ee  KM.EKeyAlmaz1CBTA.dll
eba73e280466546ab2a646e332871176ff6b5fe7c7d549a42b9503e74e893d69  EKeyCr1.dll
a3e1e9237cb19f241367d5813969dd1b0af6fd75ec428b5bc73ba4809cb0a7a7  EKeyCr1CCID.dll
```

PDB-шляхи з `.rdata` (дерево збірки IIT):
```
D:\Hardware\KeyMedias\EKeyAlmaz1C\x64\Release\PKCS11\PKCS11EKeyAlmaz1C64.pdb
D:\Hardware\KeyMedias\EKeyAlmaz1C\x64\Release\KMEKeyAlmaz1C64.pdb
D:\Hardware\KeyMedias\EKeyAlmaz1CBTA\x64\Release\KMEKeyAlmaz1CBTA64.pdb
```

Про `SysWOW64` vs `System32` у вашому XML: на Windows SysWOW64 зберігає 32-bit, System32 зберігає 64-bit. Цей набір — тільки вміст System32.

---

## 2. `PKCS11.EKeyAlmaz1C.dll` — детальний аналіз

### 2.1. Експорт — стандартний PKCS#11 v2.40 ABI

68 символів `C_*`. Вхідна точка `C_GetFunctionList` присутня і **реалізована** (disasm нижче). OpenSC / PyKCS11 / pkcs11-provider можуть завантажити DLL стандартним способом.

**Дизасемблювання `C_GetFunctionList` (RVA 0x106d0):**
```asm
sub     rsp, 0x18
mov     [rsp], 0xfffffffffffffffe       ; SEH frame init
test    rcx, rcx                         ; rcx = CK_FUNCTION_LIST_PTR_PTR
jnz     .valid
lea     eax, [rcx+7]                     ; null → return 7 = CKR_ARGUMENTS_BAD
jmp     .done
.valid:
lea     rax, [rip+.ck_function_list]
mov     [rcx], rax                       ; *ppFunctionList = &ck_function_list
xor     eax, eax                         ; return CKR_OK (0)
jmp     .done
...
.done:
add     rsp, 0x18
ret
```

Код стандартний, без сюрпризів.

### 2.2. Реалізовані vs заглушені функції

Stub-функція живе за RVA `0x0000f510`. Її байти:
```
b8 54 00 00 00    mov eax, 0x54      ; CKR_FUNCTION_NOT_SUPPORTED
c3                ret
```

Це підтверджує: **усі експорти, що вказують на `0x0000f510`, заздалегідь повертають CKR_FUNCTION_NOT_SUPPORTED**.

**Реалізовано (унікальні адреси):**

| Категорія | Функції |
|---|---|
| Життєвий цикл | Initialize, Finalize, GetInfo, GetFunctionList |
| Slot / token | GetSlotList, GetSlotInfo, GetTokenInfo, GetMechanismList, GetMechanismInfo, InitToken, InitPIN, SetPIN, WaitForSlotEvent(stub) |
| Session | OpenSession, CloseSession, CloseAllSessions, GetSessionInfo, Login, Logout |
| Objects | CreateObject, DestroyObject, GetObjectSize, GetAttributeValue, SetAttributeValue, FindObjectsInit, FindObjects, FindObjectsFinal |
| Digest | DigestInit, Digest, DigestUpdate, DigestFinal |
| **Sign** | **SignInit, Sign, SignUpdate, SignFinal** ← повний stream API |
| Verify | VerifyInit, Verify, VerifyUpdate, VerifyFinal |
| Key | DeriveKey (для ECDH), WrapKey, UnwrapKey |
| RNG | GenerateRandom, SeedRandom |
| Misc | GetFunctionStatus, CancelFunction |

**Заглушено (`CKR_FUNCTION_NOT_SUPPORTED`):**

| Чому не працює | Функції |
|---|---|
| Encrypt/Decrypt | `C_Encrypt*`, `C_Decrypt*`, `C_DigestEncryptUpdate`, `C_SignEncryptUpdate`, `C_DecryptDigestUpdate`, `C_DecryptVerifyUpdate`, `C_DigestKey` |
| Recover | `C_SignRecover*`, `C_VerifyRecover*` |
| Generate | `C_GenerateKey` (повна версія), `C_CopyObject` |
| State save/restore | `C_GetOperationState`, `C_SetOperationState` |

**Для sedo-client:** потрібен тільки Login → FindObjects(certificate) → SignInit/SignUpdate/SignFinal. Усе є.

### 2.3. 🔴 Критично: **runtime LoadLibrary залежності**

У статичному imports PKCS11.EKeyAlmaz1C.dll показує тільки `WinSCard.dll`, `KERNEL32.dll`, `ADVAPI32.dll`. Але в `.rdata` лежать UTF-16LE імена **ще трьох DLL**, які завантажуються динамічно через `LoadLibraryW`:

| DLL | Призначення (підтверджено рядками навколо) | В вашому README |
|---|---|---|
| **`CSPBase.dll`** | DSTU 4145 state API + `DSTU4145AcquireState`, `DSTU4145SelfTest` навколо рядка | ✅ згаданий |
| **`CSPExtension.dll`** | GOST 28147 wrap, ECDH, `GOST28147Un/WrapSharedKey`, `ECDHCalculateSharedKey` | ✅ згаданий |
| **`PKIFormats.dll`** | `PKIGetInterface`, `PKIInitialize`, `PKIFinalize` навколо рядка | ❌ **НЕ згаданий** |

Також у рядках фігурує `mscoree.dll` — це лише фоллбек у CRT `__crt_debugger_hook` для `CorExitProcess`; реально не вантажиться якщо процес не .NET. Ігнорувати. `USER32.DLL` — delay-load, для `MessageBoxW` у фатал-хендлерах; у headless-режимі не завантажиться.

**Імена крипто-функцій у `.rdata`** (що лінкуються з CSPBase.dll імпорту-за-іменем):
- DSTU 4145 (10 функцій): `SignHash`, `VerifySignature`, `CoupleMakeSignR/S`, `GenerateParameters`, `HalfTrace`, `Trace`, `SolveQuadEqual`, `AcquireState`, `ReleaseState`, `SelfTest`
- DSTU 7564 "Купина" (15 функцій, hash + HMAC + PBKDF2)
- DSTU 7624 "Калина" (23 функції: 9 режимів Encrypt, 9 Decrypt, CMAC, GMAC, wrap)
- DSTU 8845 "Струмок" (6 функцій, stream cipher)
- GOST 28147-89 (10 функцій)
- GOST 34.311-95 (10 функцій)
- ECDH + DSTU 7564 KDF (4 функції)

Ці функції — в **CSPBase.dll / CSPExtension.dll**, не в PKCS11.EKeyAlmaz1C.dll. Остання лише делегує.

**Оновлений Мінімальний Список Файлів для Linux (шлях В1):**

```
PKCS11.EKeyAlmaz1C.dll     ← інтерфейс PKCS#11
CSPBase.dll                ← крипто-примітиви DSTU 4145/7564/7624/8845
CSPExtension.dll           ← GOST, ECDH, wrap
PKIFormats.dll             ← формати PKI-об'єктів  ← ДОДАНО
+ будь-які *.cap на які посилається CSPBase (IIT-applet blobs, якщо є)
```

Це вплине на ваш `docs/MINIMUM-FILES-LIST.md`.

### 2.4. Транспорт

```
WinSCard.dll:
  SCardEstablishContext, SCardReleaseContext
  SCardListReadersA, SCardConnectA, SCardDisconnect
  SCardTransmit, SCardGetAttrib
  g_rgSCardT1Pci (T=1 protocol PCI)
```

Рівно 8 символів. На Linux еквівалент — PCSC-Lite (`libpcsclite.so`) з ідентичним API.

### 2.5. C++ класи (RTTI `.?AV…@@`)

37 класів у PKCS#11-модулі. Ієрархія видимих верхніх імен:

```
PKCS11EKeyAlmaz1C               ← верхівка, об'єкт-обгортка слота
├── PKCS11SlotManager           ← керує списком слотів
│   └── PKCS11Slot              ← один слот
│       └── PKCS11Token
│           ├── PKCS11TokenManager
│           │   └── PKCS11TokenManagerPool
│           ├── PKCS11TokenConnector    ← прошарок до KM_EKeyAlmaz1C.dll
│           ├── PKCS11TokenCotext       ← (sic, помилка у коді IIT — Cotext замість Context)
│           ├── PKCS11TokenStorage
│           └── PKCS11SessionManager
│               └── PKCS11Session
│                   └── PKCS11Operation
├── PKCS11ObjectManager
│   └── PKCS11Object
│       ├── PKCS11StorageObject
│       │   ├── PKCS11DataObject
│       │   ├── PKCS11CertificateObject
│       │   ├── PKCS11KeyObject
│       │   │   ├── PKCS11PrivateKeyObject
│       │   │   ├── PKCS11PublicKeyObject
│       │   │   └── PKCS11SecretKeyObject
│       │   └── PKCS11ObjectPtr
│       └── PKCS11Template + PKCS11TemplateAttribute
├── PKCS11Attribute             ← базовий клас атрибута
│   ├── PKCS11BooleanAttribute
│   ├── PKCS11IntegerAttribute
│   ├── PKCS11IntegerArrayAttribute
│   ├── PKCS11DateAttribute
│   └── PKCS11ECParamsAttribute
├── PKCS11Lock + PKCS11RWLock   ← mutex wrapper
├── PKCS11Device + PKCS11Entity
├── CSP + CSPParameters         ← shim до CSPBase.dll
```

Опечатка `PKCS11TokenCotext` (замість Context) присутня у бінарнику як є — це внутрішня "signature" IIT-коду, корисна для грepування.

### 2.6. DSTU 4145 OID-и у `.rdata`

Named curves (польський базис, 10 штук):
```
1.2.804.2.1.1.1.1.3.1.1.2.0
1.2.804.2.1.1.1.1.3.1.1.2.1
...
1.2.804.2.1.1.1.1.3.1.1.2.9
```

Normal basis, 5 штук:
```
1.2.804.2.1.1.1.1.3.1.2.2.0
...
1.2.804.2.1.1.1.1.3.1.2.2.4
```

Перегляд OID-дерева IIT (root `1.2.804.2.1.1.1.1`):
- `.3.1.1.*` — DSTU 4145 polynomial basis curves
- `.3.1.2.*` — DSTU 4145 normal basis curves

### 2.7. Mutex-и та shared memory

```
Global\EKAlmaz1COpenMutex          ← основний open-lock (глобально у системі)
Global\EKAlmaz1CMutex              ← операційний lock
Global\EKAlmaz1CMemory             ← shared memory для пристрою
Global\EKAlmaz1CKeysMemory         ← shared memory для ключів (обмежує паралелізм!)
Local\EKAlmaz1CMemory              ← per-session
Local\EKAlmaz1CKeysMemory          ← per-session ключі
```

**Наслідок:** два процеси не можуть одночасно тримати відкритим токен. Для sedo-client у cron — це не проблема (один запуск раз на день), але якщо ви колись захочете паралельні сесії, треба буде queue перед PKCS11-модулем.

### 2.8. Ідентифікатори

- Reader pattern (substring matching через `SCardListReadersA`): `IIT E.Key Almaz-1C`
- Token label: `E.key_Almaz-1C`
- Slot name: `E.key_Almaz-1C_Slot`
- Library description: `E.key_Almaz-1C_Library`
- Manufacturer: `JSC_IIT`

---

## 3. `KM.EKeyAlmaz1C.dll` — оновлення §5 оригінального аналізу

Підтверджує все, що вже описано, з уточненнями:

| Поле | Оригінальний аналіз | Факт з отриманого файлу |
|---|---|---|
| Розмір | 676 KB | **585 KB (599 056 b)** — менше |
| Версія | не вказано | **1.0.1.9** |
| Build | не вказано | **2024-05-31** |
| Експорти | `KMEnumDeviceTypes`, `KMGetInterface`, `KMFinalize` | підтверджено |
| WinSCard imports | 8 функцій | підтверджено |

**LoadLibrary в цьому файлі:** тільки `PKIFormats.dll` (без `CSPBase/CSPExtension` — вони підтягаються через вище розташований EUSignCP, а не KM).

**C++ класи KM-шару:**
```
CSPHardwareImplementationEKeyAlmaz1C   ← CSP API (для EUSignCP через KM.PKCS11)
HRNGImplementationEKeyAlmaz1C          ← апаратний RNG
EKeyAlmaz1C                            ← верхній об'єкт
EKeyAlmaz1CCarrier                     ← обгортка носія
EKeyAlmaz1CPKI                         ← PKI-шар
EKeyAlmaz1CAliasApplication            ← applet alias
IKMEKAlmaz1C                           ← interface, що повертає KMGetInterface
KMDevice                               ← абстракція пристрою
ICSPHardware + ICSPHardwareRNG         ← interface contracts
IKMAliasApplication + IKMDeviceInfoApplication
```

---

## 4. 🆕 `KM.EKeyAlmaz1CBTA.dll` — Bluetooth-варіант Алмаз-1К

**Нова знахідка.** Існує варіант пристрою Алмаз-1К який з'єднується через **BLE GATT**, а не USB CCID. FileDescription з VS_VERSIONINFO:

> `Бібліотека взаємодії із НКІ "е.ключ ІІТ Алмаз-1К" (Bluetooth)`

### 4.1. Транспорт

Статичні імпорти:
```
BluetoothApis.dll:
  BluetoothGATTGetServices
  BluetoothGATTGetCharacteristics
  BluetoothGATTRegisterEvent
  BluetoothGATTUnregisterEvent
  BluetoothGATTSetCharacteristicValue
SETUPAPI.dll (SetupDiEnumDeviceInfo/Interfaces — пошук BLE пристроїв)
```

**WinSCard відсутній.** Цей транспорт повністю обходить PC/SC. З точки зору `EUSignCP.dll` це той самий токен (ті самі reader patterns, mutex-и), просто інша транспортна DLL.

### 4.2. Додаткові OID-и

Окрім "звичайних" `1.2.804.2.1.1.1.1.3.*`, BTA DLL містить ще `1.2.804.2.1.1.1.11.1.4.{1,2,3,4,5,6,7,11}.1` — це нова гілка, пов'язана з **ДСТУ 9041:2020** (оновлення DSTU 4145 від 2020 року).

### 4.3. Релевантність для sedo-client

**Ігнорувати.** sedo-client автоматизується з Linux-cron → Ansible → Windows worker з USB-токеном. BLE для headless-серверної автоматизації не підходить (pairing, PIN, GATT connection lifecycle — інтерактивні).

Рядок у BTA, що цікавий для reverse: `BTAdapter.fwi.ver` — ймовірно, GATT-характеристика з версією прошивки адаптера.

### 4.4. Authenticode підпис

У `.rdata` BTA DLL містить референси на DigiCert CRL/OCSP endpoints:
- `http://crl3.digicert.com/sha2-assured-cs-g1.crl`
- `http://ocsp.digicert.com`
- `http://cacerts.digicert.com/DigiCertSHA2AssuredIDCodeSigningCA.crt`

Отже збірка підписана SHA2 Assured ID Code Signing CA від DigiCert. Інші DLL (старіші) використовують VeriSign Class 3 — теж Authenticode, просто старша CA.

---

## 5. 🆕 `EKeyCr1.dll` + `EKeyCr1CCID.dll` — це **НЕ Алмаз-1К**, це **Crystal-1**

**VS_VERSIONINFO:**
```
FileDescription = "ІІТ Е.ключ Кристал-1. Бібліотека"
ProductName     = "ІІТ Е.ключ Кристал-1"
```

`Cr1` = Crystal-1, старіший токен IIT. Обидві DLL експортують 56-58 функцій з префіксом **`C1*`** (не `C_*`) — це власницьке API, не PKCS#11.

### 5.1. Відмінність між двома файлами — тільки транспорт

| | `EKeyCr1.dll` | `EKeyCr1CCID.dll` |
|---|---|---|
| Транспорт | прямий USB/HID через SetupDi + `DeviceIoControl` | WinSCard (smart-card) |
| Імпорти | `SETUPAPI.SetupDi*`, `KERNEL32.DeviceIoControl`, `CreateFileA` | `WinSCard.SCard*`, `g_rgSCardT0Pci` + `g_rgSCardT1Pci` |
| Формат Crystal | "USB HID native" | CCID smartcard reader |

Crystal-1 hardware існує у двох форм-факторах, і IIT підтримує обидва окремими DLL.

### 5.2. Експорти (обидва файли)

```
C1OpenDevice / C1CloseDevice / C1EnumDevices
C1QueryName / C1QuerySerialNumber / C1GetFirmwareMac
C1LogOn / C1LogOff                              ← вхід/вихід з токена (PIN)
C1ChangePassword / C1ChangeAdminPassword / C1ChangeUserPassword
C1GenerateKeys / C1ActivateFutureKeys / C1DeactivateFutureKeys
C1SignHash / C1SignHashDH                       ← підпис
C1CheckPublicKey / C1RecoverPublicKey
C1CalculateSharedKey / C1CalculateSharedKeyUA  ← ECDH
C1WrapKey / C1UnwrapKey
C1ProtectData / C1UnprotectData
C1Format / C1PartialFormat                      ← форматування токена
C1StoreKeyData / C1LoadKeyData / C1EraseKeyData
C1StoreUserData / C1LoadUserData / C1EraseUserData
C1GetLogData                                    ← audit log з токена
C1SelfTest
...
```

### 5.3. Як Crystal-1 інтегрується в IIT-стек

За таблицею маршрутизації `KM.PKCS11.dll` з §6 оригінального аналізу:

```
PKCS11.EKeyCrystal1.dll           ← PKCS#11 обгортка (в цьому наборі ВІДСУТНЯ)
    │
    ├── EKeyCr1.dll               ← USB HID native transport
    └── EKeyCr1CCID.dll           ← CCID transport
```

Вам надіслали **нижній** рівень, без PKCS#11-обгортки. Якщо захочете підтримувати Crystal-1 в sedo-client (для зворотної сумісності зі старими користувачами) — треба знайти `PKCS11.EKeyCrystal1.dll`. Але це **не пріоритет**: SEDO ЗСУ використовує Алмаз-1К.

### 5.4. Рекомендація

У README/SETUP-WINDOWS.md додати примітку:

> ⚠️ Якщо ви бачите у своїй системі `EKeyCr1.dll` або `EKeyCr1CCID.dll` — це бібліотеки для токена **Crystal-1**, а не Алмаз-1К. sedo-client з ними не працюватиме. Для Алмаз-1К потрібні `PKCS11.EKeyAlmaz1C.dll`, `CSPBase.dll`, `CSPExtension.dll`, `PKIFormats.dll`.

---

## 6. Оновлення планів

### Шлях В1 — "знайти PKCS11.EKeyAlmaz1C.dll"

**Статус: частково розблоковано.** Основний артефакт є, але у 64-bit. Для Linux через Wine це не проблема. Для native Linux — залежить від того, чи існує `PKCS11.EKeyAlmaz1C.so` у повному інсталяторі IIT (у минулому IIT випускав Linux-нативні варіанти).

**Checklist для тесту (Linux + Wine):**

```bash
# 1. Мінімальні файли — скопіювати у Wine prefix
mkdir -p ~/.wine/drive_c/iit
cp PKCS11.EKeyAlmaz1C.dll CSPBase.dll CSPExtension.dll PKIFormats.dll \
   ~/.wine/drive_c/iit/

# 2. Переконатися що pcscd запущено і токен видно
pcsc_scan
# очікуємо: "IIT E.Key Almaz-1C 0"

# 3. Прокинути PC/SC у Wine (winscard.dll wrapper)
# Wine вже має winscard.dll який мостить до нативного libpcsclite.so

# 4. Тест через Wine
wine pkcs11-tool.exe --module C:\\iit\\PKCS11.EKeyAlmaz1C.dll --list-slots
wine pkcs11-tool.exe --module C:\\iit\\PKCS11.EKeyAlmaz1C.dll --list-mechanisms
wine pkcs11-tool.exe --module C:\\iit\\PKCS11.EKeyAlmaz1C.dll --login --pin XXXX --list-objects
```

Якщо Wine-підхід спрацює — Ansible playbook може робити все на Linux без Windows worker. Це скорочує архітектуру.

### Шлях Б (гібрид через JSON-RPC агент)

**Не змінюється.** Усе так, як описано в оригінальному §7. Ці 5 DLL агент не використовує — агент комунікує тільки з EUSignAgent/EUSignRPC/EUSignCP, а ті вже самі підвантажують KM/PKCS11/CSPBase.

### Шлях В2 (open-almaz з нуля)

**Тепер низького пріоритету.** Якщо В1 через Wine спрацює — В2 можна відкласти або повністю закрити.

---

## 7. Запропоновані правки в існуючі файли репо

**`docs/IIT-ANALYSIS.md`:**
- §5 (KM.EKeyAlmaz1C.dll): оновити розмір до 585 KB, додати версію 1.0.1.9 і build date
- §6 (KM.PKCS11.dll router table): змінити статус `PKCS11.EKeyAlmaz1C.dll` з "НЕ у Web.zip" на "✅ Отримано. SHA256: `3195e46a...`"
- Додати §9 "Bluetooth-варіант Алмаз-1К"
- Додати §10 "Не плутати Crystal-1 з Алмаз-1К"
- Додати §11 "Runtime LoadLibrary залежності PKCS11-модуля"

**`docs/MINIMUM-FILES-LIST.md`:**
- Додати `PKIFormats.dll` у список обов'язкових файлів
- Позначити, що всі перелічені DLL потрібні у **тій же бітності** (32 або 64), що й процес, який їх вантажить

**`SETUP-WINDOWS.md`:**
- Додати warning про Crystal-1 vs Алмаз-1К
- Додати хеш-перевірку (SHA256) для ідентифікації правильної версії `PKCS11.EKeyAlmaz1C.dll`

**`README.md` / `README_uk.md`:**
- У блоці "PKCS11.EKeyAlmaz1C.dll + CSPBase.dll + CSPExtension.dll + *.cap" додати `PKIFormats.dll`

---

## 8. Що все ще не вистачає

1. **32-bit `PKCS11.EKeyAlmaz1C.dll`** — потрібен для `opensc_signer.py` через 32-bit OpenSC
2. **`CSPBase.dll`, `CSPExtension.dll`, `PKIFormats.dll`** як фізичні файли — без них 64-bit PKCS11-модуль не стартує
3. **`PKCS11.EKeyCrystal1.dll`** — якщо захочете підтримку Crystal-1 (низький пріоритет)
4. **Будь-які `*.cap`-файли з інсталятора IIT** — IIT applet-blobs, потенційно потрібні для деяких mechanism-initializations
5. **Runtime APDU-трейс** — для документування wire-протоколу Алмаз-1К на рівні SCardTransmit (не потрібно для sedo-client)

---

## 9. Метадані

- **Дата аналізу:** 2026-04-22
- **Інструменти:** pefile 2024.8.26, objdump (binutils), GNU strings, Python 3
- **Вхід:** 5 файлів, загалом 1 506 456 байт
- **Звіт згенеровано для:** `github.com/click0/sedo-client` v0.26
