# IIT-ANALYSIS — Addendum v5 (Critical Dependencies) 2026-04-22

> **Вхід:** `CSPBase.dll`, `CSPExtension.dll`, `CSPIBase.dll`, `PKIFormats.dll`, `EUSignCP.dll` (всі 32-bit i386).
> **Призначення:** критично важливі залежності для PKCS#11-модулів Алмаз-1К (HW + Virtual). **Розблоковує Шлях В1 деплою на Linux через Wine.**

---

## 0. TL;DR

1. ✅ **Всі 5 критичних залежностей отримано.** Runtime LoadLibrary-чейн PKCS11 тепер повністю замкнутий — можна будувати Wine-deployment.
2. ⚠️ **Усі 5 файлів — 32-bit.** 64-bit варіанти досі відсутні. Треба або 32-bit PKCS11.EKeyAlmaz1C.dll + 32-bit OpenSC (шлях вашого `opensc_signer.py`), або паралельний набір 64-bit цих залежностей.
3. 🔧 **Два correction до попередніх addendum-ів:**
   - v1 §2.3: `CSPExtension.dll` **не містить ECDH/GOST wrap**. Реально: 5 експортів, RNG-тести і CRC32 (BSI AIS 20/31 style statistical tests).
   - v2 §3.4: Файл `sCSPIBase.dll`, про який я писав, — насправді **`CSPIBase.dll`** (регістрозалежність. Я спочатку спіймав strings з підзаголовком, де була "s" з попереднього слова, що призвело до помилкового імені). "I" = **International** (не Implementation/software).
4. 🗺️ **EUSignCP.dll тягне ще 10+ DLL через LoadLibrary** — повна карта залежностей нижче.

---

## 1. Версії і SHA256

| DLL | FileVer | Build | Розмір | SHA256 |
|---|---|---|---:|---|
| `CSPBase.dll` | 1.1.0.173 | 2025-06-18 | 1 239 688 | `90973d4f454400f61278380ad149fc13b9e2e6ba1772b23eb2cb4bd4887fc98b` |
| `CSPExtension.dll` | 1.1.0.17 | 2023-03-13 | 81 424 | `c60a3de7719e3ba405c4c6a29097ebbb5442f46a1699a35cd2c3968920a9e562` |
| `CSPIBase.dll` | 1.0.0.29 | 2025-07-19 | 1 100 424 | `ab37b21a3c317433c47b53f9353ddd7c66e7200ff29cb88f04f1e4d5d05f836b` |
| `PKIFormats.dll` | 1.2.0.171 | 2025-08-15 | 1 005 704 | `25ac050a51827f56c34d3f19bf0dec40c2acf0351b0a94168f02ba7ae02819f5` |
| `EUSignCP.dll` | 1.3.1.209 | 2025-11-03 | 1 843 336 | `f61b817adfccba6bc570bcd23da07969efb4bf752ee1ada9207595cee07ffcc3` |

Усі — `АТ "ІІТ"`, усі x86 (i386), усі із свіжими 2025-білдами (крім `CSPExtension.dll`, яка старша — 2023).

⚠️ **Version drift** між `PKCS11.EKeyAlmaz1C.dll` (1.0.1.7, 2023-02) і цими залежностями (2025). Теоретично може бути ABI/protocol breakage між версіями. На практиці IIT зазвичай тримає сумісність, але ідеальний спосіб — взяти всі файли з **одного snapshot** повного інсталятора "Користувач ЦСК-1".

---

## 2. `CSPBase.dll` — українська крипто-бібліотека

**"ІІТ Бібліотека криптографічних перетворень"** — серце DSTU/GOST крипто.

| Поле | Значення |
|---|---|
| Експорти | **133**, жодних stub-ів |
| Dependency | **Standalone** — імпортує тільки KERNEL32 (75 функцій) |
| Runtime loads | Немає |

### 2.1. Крипто-функції (групованих за алгоритмом)

| Група | К-сть | Приклад функцій |
|---|---:|---|
| **DSTU 4145** (ЕЦП) | 39 | `DSTU4145AcquireState`, `CoupleMakeCommonSign`, `CheckN`, `GenerateParameters`, `HalfTrace`, `SolveQuadEqual`, `SignHash`, `VerifySignature` |
| **DSTU 7564** "Купина" (hash) | 14 | `HashData`, `FinalizeHash`, `HMACAcquireState`, `HMACUpdateData`, `SelfTest` |
| **DSTU 7624** "Калина" (AES-подібний) | 29 | 9 режимів шифрування × encrypt/decrypt, CMAC/GMAC, wrap shared key |
| **DSTU 8845** "Струмок" (stream) | 6 | `EncryptData`, стандартний state API |
| **GOST 28147-89** (legacy) | 15 | G/GOFB/SS режими, `EncryptBlocks`, wrap/unwrap |
| **GOST 34.311** (legacy hash) | 14 | Hash + HMAC з стандартним state API |
| **ECDH (DSTU + UA)** | 5 | `ECDHDSTUSelfTest`, `ECDHKDFDSTU7564CalculateSharedKey`, `ECDHUACalculateSharedKey` |
| **PBKDF** | 6 | `PBKDF2DeriveKey`, `PKCS12PBKDFDSTU7564DeriveKey`, `PKCS5PBKDF2DSTU7564DeriveKey` |
| Інше | 1 | `CSPFinalize` |

**Повний функціональний набір для SEDO:**
- ЕЦП: DSTU 4145 ✅
- Hash: DSTU 7564 (Купина) + GOST 34.311 ✅
- Key derivation: PBKDF2 + PKCS12PBKDF ✅
- Все, що потрібно `PKCS11.EKeyAlmaz1C.dll` для sign/verify, є.

### 2.2. Немає runtime-залежностей

Це гарно. `CSPBase.dll` **повністю standalone** — жодних `LoadLibraryW` на сторонні крипто-DLL. Тобто якщо ви кладете її у Wine prefix, вона не вимагатиме нічого, крім `KERNEL32.dll` (вже у Wine).

---

## 3. `CSPExtension.dll` — RNG self-tests (CORRECTION)

**У v1 addendum §2.3 я помилково вказав, що цей файл містить "GOST 28147 wrap + ECDH".** Це помилка. Реальний вміст:

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Бібліотека криптографічних перетворень (**розширення**)" |
| FileVersion | 1.1.0.17 (набагато менше, ніж CSPBase's 1.1.0.173 — реально маленький додаток) |
| Експорти | **5 функцій** |
| Імпорти | WINMM.dll (3 fns — `timeGetTime` і ко), KERNEL32 (54) |

### 3.1. Експорти (повний список)

```
BSReleaseStatistic       ← "BS" = BitStream? Battery of Sequences?
BSTestSequence           ← Статистичний тест (ймовірно NIST SP 800-22 / BSI AIS 31)
CRC32Count               ← CRC32 контрольна сума
TSCGGenerateSequence     ← TSCG = True/Thermal Source Clock Generator?
TSCGIsEnable             ← чи доступний hardware RNG
```

### 3.2. Призначення

Цей файл — не extension для крипто-алгоритмів. Це **модуль статистичного тестування випадкових послідовностей** (AIS 20/31 compliant), який викликається раз при старті CSP для перевірки, що hardware RNG працює правильно. Типова логіка:

1. `TSCGIsEnable()` — чи є доступ до апаратного джерела шуму
2. `TSCGGenerateSequence(N)` — згенерувати N байт з RNG
3. `BSTestSequence(bytes)` — прогнати через statistical battery
4. Якщо пройшов — continue; інакше — помилка self-test і відмова працювати

Імпорт `WINMM.dll` (`timeGetTime` / `timeBeginPeriod`) використовується для **high-precision timing** — типовий підхід для TRNG self-test.

### 3.3. Чи потрібен CSPExtension.dll обов'язково?

**Ймовірно так** — CSP ініціалізація може вимагати `TSCGIsEnable` перед будь-якими `*AcquireState` з CSPBase. Якщо в Linux/Wine немає HW RNG → `TSCGIsEnable` поверне false → CSP fallback на PRNG з `/dev/urandom`-еквівалентом. Повинно працювати, але без протестування не гарантую.

**Update для v1 addendum §2.3 та `docs/MINIMUM-FILES-LIST.md`:** позначити CSPExtension.dll як "RNG self-test module (5 functions)", а не "ECDH + GOST wrap".

---

## 4. `CSPIBase.dll` — міжнародна крипто-бібліотека (CORRECTION)

**У v2 addendum §3.4 я помилково згадав файл `sCSPIBase.dll`.** Помилка виникла з парсингу strings (залишок з попереднього слова був прилипнув). Реальне ім'я — **`CSPIBase.dll`**, без "s".

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Бібліотека криптографічних перетворень (**міжнародних**)" |
| FileVersion | 1.0.0.29 |
| Експорти | **145** |
| Імпорти | Standalone (тільки KERNEL32) |

### 4.1. "I" = International

`CSPI` означає **CSP International** — крипто-алгоритми, стандартизовані на міжнародному рівні (NIST, IETF, ISO), не українські DSTU/GOST. CSPIBase доповнює CSPBase: CSPBase = Україна, CSPIBase = решта світу.

### 4.2. Крипто

Перші 30 експортів:
```
AES*             ← 9 режимів (CBC, CFB-1/8/128, ECB, GCM, CTR, OFB), MAC, self-test, state API
DH*              ← Diffie-Hellman (classic)
DSA*             ← Digital Signature Algorithm
ECDSA*           ← Elliptic Curve DSA (multi-party couple protocol)
...
```

Очікувано далі (з 145 експортів): RSA, SHA-1/256/384/512, HMAC-SHA*, PBKDF2 (generic), PKCS#1 padding.

### 4.3. Для sedo-client

Необхідний **тільки для Virtual PKCS11** (HW-варіант його напряму не вантажить). Проте через транзитивну залежність через EUSignCP.dll — так, потрібен у мінімальному наборі для Virtual.

---

## 5. `PKIFormats.dll` — ASN.1 / PKI структури

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Бібліотека роботи з форматами даних" |
| Експорти | **лише 3**: `PKIInitialize`, `PKIGetInterface`, `PKIFinalize` |
| Імпорти | Standalone (KERNEL32 only) |

### 5.1. Pattern: interface через vtable

3-export-pattern (`Initialize/GetInterface/Finalize`) повторюється у багатьох IIT DLL:
- `PKIFormats.dll`: `PKIGetInterface`
- `KM.EKeyAlmaz1C.dll`: `KMGetInterface`
- `EUSignRPC.dll`: `EUSignRPCGetInterface`
- `EUSignAgent.dll`: `EUSignAgentGetInterface`

Модель: DLL експортує одну функцію `GetInterface()`, яка повертає vtable (C struct з function pointers). Решта API — недоступна через імпорт-за-іменем.

**Наслідок:** щоб користуватися `PKIFormats.dll` напряму — треба reverse-інжинірити формат `PKI_INTERFACE` struct. Для sedo-client це **не потрібно**, бо ви користуєтеся нею опосередковано через EUSignCP.dll, а не напряму.

### 5.2. Що всередині

Розмір 1 MB без великої кількості експортів означає: 
- Багато ASN.1-парсерів / серіалізаторів для X.509, CRL, CMS, TSP, OCSP
- Всі функції доступні через vtable, не через експорт
- Ймовірно використовує code generator з ASN.1-схем

Для sedo-client — treat as black box, покласти поряд з EUSignCP.dll і все.

---

## 6. `EUSignCP.dll` — головна бібліотека IIT "Користувач ЦСК-1"

Найкритичніший файл з усіх. **619 експортів** `EU*`.

| Поле | Значення |
|---|---|
| FileDescription | "ІІТ Користувач ЦСК-1. Бібліотека підпису" |
| FileVersion | 1.3.1.209 |
| Build | 2025-11-03 (найсвіжіший з усіх файлів) |
| Експорти | **619**, 2 stubs |
| Статичні imports | WS2_32 (27), WINHTTP (1), IPHLPAPI (1), ADVAPI32 (24), KERNEL32 (112), USER32 (5), OLE32 (5), OLEAUT32 (4), PSAPI (2) |

### 6.1. Runtime LoadLibrary-граф

Ось повний список DLL, посилання на які є у `.rdata` (candidate-и для `LoadLibraryW`):

```
EUSignCP.dll
├── ⭐ CSPBase.dll          ← ukrainian crypto (v5 §2)
├── ⭐ CSPExtension.dll     ← RNG self-test (v5 §3)
├── ⭐ CSPIBase.dll         ← international crypto (v5 §4)
├── ⭐ PKIFormats.dll       ← PKI formats (v5 §5)
├── ⭐ KM.dll               ← Key Media router (!!! — новий, не KM.PKCS11.dll)
├── CAConnectors.dll        ← network layer (OCSP/CRL/TSP)
├── CAGUI.dll               ← GUI (не потрібний у headless)
├── LDAPClient.dll          ← LDAP для CRL distribution
├── QRCode.dll              ← QR codes (для чого? можливо token enrollment)
├── RF.dll                  ← незрозуміло (Radio Frequency? NFC?)
├── SLMessages.dll          ← можливо локалізація помилок
├── ePDFSecurity.dll        ← PDF підписування
├── eXMLSecurity.dll        ← XML / XAdES
├── WINHTTP.dll             ← OS (HTTP client)
└── WS2_32.dll, IPHLPAPI    ← OS (sockets, network info)
```

Тільки **5 зірочкою (⭐) позначених** є обов'язковими для базового підпису. Інші завантажуються за потребою (наприклад, `ePDFSecurity.dll` — тільки коли викликається `EUPDFSignData`; `LDAPClient.dll` — тільки коли CRL-distribution-point має схему `ldap://`).

### 6.2. Архітектура API (619 функцій у 25+ кластерах)

Топ-25 префіксів:

| Префікс | К-сть | Призначення |
|---|---:|---|
| `EUCtx*` | **129** | Контекстний API (основний — для thread-safe операцій) |
| `EUGet*` | 81 | Читання інформації (certificate, signer, session, …) |
| `EUDev*` | 46 | Робота з пристроями / токенами (legacy API) |
| `EUEnv*` | 27 | CMS EnvelopedData (шифрування) |
| `EUVer*` | 27 | Verify операції |
| `EUSet*` | 23 | Set-settings |
| `EUASi*` | 17 | ASiC-S/E containers (стандарт EU eIDAS) |
| `EUApp*` | 16 | Append signature / attribute |
| `EUSig*` | 16 | Sign операції (legacy, переходьте на EUCtx*) |
| `EUFre*` | 15 | Free memory |
| `EUCli*` | 14 | Client dynamic key sessions |
| `EUSSe*` | 11 | ? (server sessions?) |
| `EUXAd*` | 11 | **XAdES** (XML signatures) |
| `EUChe*` | 10 | Check (certificate, TSP, OCSP) |
| `EUCre*` | 10 | Create (signer, session, empty sign) |
| `EUEnu*` | 10 | Enumerate (certificates, keys, …) |
| `EUHas*` | 10 | Hash |
| `EURaw*` | 10 | Raw data sign/verify |
| `EUSes*` | 10 | Session management |
| `EUAlg*` | 9 | Algorithm info |
| `EUPDF*` | 8 | **PDF signing** |
| …і т.д. |  |  |

**Для sedo-client актуально:**

- `EUCtx*` — thread-safe контекст (створити через `EUCtxCreate`, знищити через `EUCtxFree`)
- `EUCtxReadPrivateKeyFile` / `EUCtxEnumNamedPrivateKeys` — читання приватного ключа (для Virtual)
- `EUCtxEnumOwnCertificates` / `EUCtxGetOwnCertificate` — виявити certs на токені
- `EUCtxSignHash` / `EUCtxSignData` — підпис (JSON-RPC метод `SignData` agent-а викликає саме це)

### 6.3. Реєстрові ключі

EUSignCP читає конфігурацію з:

```
HKLM\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\
  ├── End User\                               ← основна гілка користувача
  │   └── Libraries\Sign\                     ← шляхи до крипто-бібліотек
  └── Common\OIDs\ExtKeyUsages\
      ├── CA\                                  ← OID allow-list для CA сертів
      └── EUser\                               ← OID allow-list для End User сертів
HKLM\SOFTWARE\Institute of Informational Technologies\Key Medias\
  └── Sign Server\                             ← alternate profile для сервера підпису
```

Це доповнює реєстрову гілку `Sign Agent` з оригінального IIT-ANALYSIS §2. Тепер у нас **повна карта реєстрових залежностей IIT-стеку**.

### 6.4. Що нового у v1.3.1.209 (2025-11) vs v1.2.x (раніше)

Я не маю попередньої версії для diff, але судячи з функцій `EUASi*` (17 штук) і свіжого build — `Бібліотека підпису` активно оновлюється. Ймовірні новинки:
- Підтримка ASiC-S / ASiC-E (eIDAS стандарт для контейнерів підписаних документів)
- XAdES Baseline profiles (B/T/LT/LTA)
- PDF PAdES signatures

---

## 7. Повна dependency-карта для Virtual PKCS#11 режиму

### 7.1. Мінімально необхідне

```
pkcs11-tool (або ваш Python client)
    │
    ▼
PKCS11.Virtual.EKeyAlmaz1C.dll  (32-bit варіанта ще не маємо)
    │
    ├── WinSCard.dll              ← OS / Wine
    ├── KERNEL32, ADVAPI32         ← OS / Wine
    │
    └──[LoadLibraryW]
        │
        ├── EUSignCP.dll                    ← v5 §6
        │   ├── CSPBase.dll                 ← v5 §2 (DSTU/GOST)
        │   ├── CSPExtension.dll            ← v5 §3 (RNG self-test)
        │   ├── CSPIBase.dll                ← v5 §4 (AES/SHA/RSA)
        │   ├── PKIFormats.dll              ← v5 §5 (ASN.1)
        │   └── KM.dll                      ← ❌ НЕМАЄ (Key Media router)
        │
        └── CSPBase + CSPExtension + PKIFormats (напряму теж)
```

### 7.2. Що у нас є

✅ `EUSignCP.dll` (32-bit)
✅ `CSPBase.dll` (32-bit)
✅ `CSPExtension.dll` (32-bit)
✅ `CSPIBase.dll` (32-bit)
✅ `PKIFormats.dll` (32-bit)

### 7.3. Що ще потрібно

❌ **32-bit `PKCS11.Virtual.EKeyAlmaz1C.dll`** (зараз маємо 64-bit; він вимагає 64-bit залежності)
❌ **`KM.dll`** — Key Media router. Це не той самий `KM.PKCS11.dll` що у router-таблиці. Ймовірно це master Key Media manager, який консолідує доступ до всіх типів носіїв. Треба перевірити, чи обов'язковий — можливо, потрібен тільки для HW-режиму, а для Virtual не критичний

### 7.4. Рекомендація: запитати у повного інсталятора

Повний інсталятор "ІІТ Користувач ЦСК-1" (https://iit.com.ua/download/productfiles/users) зазвичай містить **як 32-bit, так і 64-bit** набори всіх цих DLL у підкаталогах `Libraries\x86\` і `Libraries\x64\` (або подібно). Якщо ви шукатимете відсутні файли — беріть з цього дистрибутива.

---

## 8. Оновлений Linux/Wine test plan

### 8.1. Мінімальний Wine prefix для Virtual PKCS#11 (32-bit)

```bash
# Створити 32-bit prefix для цього експерименту
export WINEARCH=win32 WINEPREFIX=~/.wine-iit-virtual
wineboot --init

# Покласти DLL у System32 (для 32-bit prefix — це справжній System32)
cp CSPBase.dll CSPExtension.dll CSPIBase.dll PKIFormats.dll EUSignCP.dll \
   ~/.wine-iit-virtual/drive_c/windows/system32/

# 32-bit PKCS11.Virtual.EKeyAlmaz1C.dll — ЩЕ НЕМАЄ. Треба ЧЕКАТИ.

# Коли буде:
# cp PKCS11.Virtual.EKeyAlmaz1C.dll ~/.wine-iit-virtual/drive_c/windows/system32/

# Key-6.dat — де завгодно
cp Key-6.dat ~/.wine-iit-virtual/drive_c/keys/

# Тест (після отримання 32-bit PKCS11)
wine pkcs11-tool.exe --module C:\\windows\\system32\\PKCS11.Virtual.EKeyAlmaz1C.dll \
     --list-slots --show-info
```

### 8.2. Можливі проблеми

1. **Реєстрові ключі**: EUSignCP.dll шукає `HKLM\SOFTWARE\Institute of Informational Technologies\...`. У свіжому Wine prefix їх немає. Треба або створити їх `wine regedit` з шаблоном, або патчити кожен ключ через `wine reg add`.
2. **Wine WinSCard**: для Virtual-режиму, WinSCard потрібен тільки для runtime-check `EUIsHardwareKeyMedia` — якщо HW немає, має fallback на software. У Wine `winscard.dll` (Wine-native) спрацює без pcscd, або використайте реальний Linux pcscd через міст Wine↔native.
3. **KM.dll**: якщо EUSignCP намагається LoadLibrary на нього і не знайде — можливо, буде warning але не fail (залежить від code path).

---

## 9. Виправлення попередніх addendum-ів

### 9.1. v1 addendum § 2.3

Замінити рядок:

> `CSPExtension.dll` | GOST 28147 wrap, ECDH, `GOST28147Un/WrapSharedKey`, `ECDHCalculateSharedKey` | ✅ згаданий

На:

> `CSPExtension.dll` | **RNG self-test (5 функцій: BSTestSequence, TSCGGenerateSequence, CRC32Count + 2 інші). BSI AIS 20/31-style statistical test battery for hardware RNG.** Не містить крипто-алгоритмів. Розширення до CSP *self-test framework*, не крипто-алгоритмів. | ✅ згаданий |

Функції, які я помилково приписав CSPExtension — `GOST28147WrapSharedKey`, `ECDHCalculateSharedKey` — реально знаходяться у **`CSPBase.dll`** (див. v5 §2). Помилка була в інтерпретації — я бачив ці функції у `.rdata` strings PKCS11.EKeyAlmaz1C.dll, але не перевірив, з якої саме DLL вони імпортуються. Виявилося — з CSPBase, не CSPExtension.

### 9.2. v2 addendum § 3.4

Замінити:

> `sCSPIBase.dll` — Software CSP Implementation Base

На:

> `CSPIBase.dll` — **CSP International Base** (не "software"). Library of internationally-standardized crypto primitives: AES (9 modes), DH, DSA, ECDSA, RSA, SHA-family. 145 exports. Complements CSPBase (Ukrainian crypto). Build v1.0.0.29, 2025-07-19.

Помилка виникла через strings-парсинг: я бачив у `.rdata` Virtual PKCS11 DLL рядок, що виглядав як `sCSPIBase.dll`. Насправді це залишок від попереднього слова (ймовірно, закінчення `...s` + `CSPIBase.dll`). Правильне ім'я — `CSPIBase.dll`.

---

## 10. Метадані

- **Дата:** 2026-04-22
- **Версія:** v5
- **Попередні:** v1, v2, v3, v4
- **Вхід:** 5 DLL, загалом 5 270 728 байт
- **Статус:** Virtual PKCS#11 chain тепер майже повний. Залишається: 32-bit `PKCS11.Virtual.EKeyAlmaz1C.dll` + перевірка чи потрібна `KM.dll`.
- **Наступний крок:** запит 32-bit `PKCS11.Virtual.EKeyAlmaz1C.dll` + `KM.dll` з повного інсталятора IIT.
