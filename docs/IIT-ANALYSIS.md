# IIT Binary Analysis — Повний звіт реверс-інжинірингу

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Phone:    +38(099)6053340
Version:  0.25
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

**Дата:** 2026-04-16  
**Вхід:** Web.zip (36 DLL, 11.7 MB)  
**Метод:** статичний аналіз (objdump, strings, binary pattern matching)  
**Для:** проект sedo-automation, ua-sign-verify  

---

## Головний висновок

**Шлях Б (гібрид) радикально спрощується**: від 6 тижнів → 2-3 тижні.  
**Шлях В (open-almaz) має легший альтернативний варіант** — якщо знайти `PKCS11.EKeyAlmaz1C.dll` окремо, реверс-інжиніринг APDU взагалі не потрібен.

---

## 1. Архітектура підтверджена

```
Браузер (Edge/Chrome, JS на sedo.mod.gov.ua)
     │
     │ HTTP POST на 127.0.0.1:<port>/json-rpc
     ▼
EUSignAgent.dll  ──── Mongoose HTTP/WebSocket server ────
     │ TrustedSites whitelist (реєстр)
     │ CORS: Access-Control-Allow-Origin
     │ SSL через ssl.dll
     │
     ▼  IRPCServerDelegate
EUSignRPC.dll   ──── JSON-RPC 2.0 dispatcher ────────────
     │ 500+ зареєстрованих методів
     │ Формат: {"jsonrpc":"2.0","id":N,"method":"X","params":[],"session_id":"..."}
     │
     ▼  EUSignRPCGetInterface
EUSignCP.dll   ──── головна крипто-бібліотека ────────────
     │ 606 експортованих функцій EU*
     │ Підпис / верифікація / управління ключами
     │
     ▼  EUGetInterface
KM.PKCS11.dll (router для зовнішніх PKCS#11 модулів)
     │ Таблиця маршрутизації: ім'я пристрою → модуль
     │
     ├──▶ PKCS11.EKeyAlmaz1C.dll  [НЕМА в Web.zip!]
     │       ↓
     │    Алмаз-1К (USB CCID)
     │
     ├──▶ avcryptokinxt.dll (SecureToken 337/338 від "Автор")
     │       ↓ WinSCard
     │    SecureToken USB
     │
     └──▶ KM.EKeyAlmaz1C.dll (прямий драйвер, fallback)
             ↓ WinSCard (8 функцій)
             Алмаз-1К (USB CCID)
```

---

## 2. EUSignAgent.dll — локальний HTTP сервер

| Властивість | Значення |
|---|---|
| Роль | HTTP/HTTPS сервер на localhost |
| Web-сервер | **Mongoose / CivetWeb** (embedded C) |
| Розмір | 159 KB |
| Експорти | `EUSignAgentGetInterface` |
| Imports | WS2_32 (accept, bind, connect — і сервер, і клієнт), ADVAPI32 (реєстр) |
| Endpoint | `POST /json-rpc` |
| Протокол | JSON-RPC 2.0 |
| WebSocket | підтримка Upgrade, Sec-WebSocket-Key |
| CORS headers | `Access-Control-Allow-Origin`, `Access-Control-Max-Age`, `Access-Control-Allow-Private-Network` |
| TrustedSites | whitelist з реєстру (куди занесено `sedo.mod.gov.ua` тощо) |

**C++ класи (RTTI):**
- `EUHTTPWebServer`, `EUHTTPWebServerConnection`, `EUHTTPWebServerDelegate`
- `EUHTTPWebRequest`, `EUHTTPWebResponse`
- `EUSignAgent`, `IEUSignAgent`
- `RPCServer`, `IRPCServerDelegate` (делегує EUSignRPC.dll)

### Конфігурація — реєстр

```
HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User\Libraries\Sign Agent
├── HTTPPort          (DWORD)  — порт HTTP (не default, читається)
├── HTTPSPort         (DWORD)  — порт HTTPS
├── AutoRun           (DWORD)  — автозапуск
├── RunAsProcess      (DWORD)  — процес vs DLL режим
├── CertPath          (SZ)     — шлях до сертифіката агента
├── PrivKeyPath       (SZ)     — шлях до приватного ключа агента
├── SSLKeyPath        (SZ)     — SSL ключ
├── CACertPath        (SZ)     — корінь CA
├── CertImportedSystem     (DWORD) — чи імпортовано в Windows Store
├── CertImportedMozillaFF  (DWORD) — чи імпортовано в Firefox NSS
└── TrustedSites\
    └── <origin>            — дозволені JS origins для CORS
```

**Default порт не захардкожений** — якщо ключ відсутній, агент не стартує.

---

## 3. EUSignRPC.dll — JSON-RPC диспетчер

| Властивість | Значення |
|---|---|
| Експорт | Єдиний: `EUSignRPCGetInterface` |
| Розмір | 466 KB |
| Формат RPC | **JSON-RPC 2.0** + кастомне поле `session_id` |
| C++ класи | `JSONRPCArray`, `JSONRPCObject`, `JSONRPCItem`, `RPCSession`, `JSONValue`, `RPCBaseObject` |

### Схема запиту (підтверджена зі строк)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "<MethodName>",
  "params": [...],
  "session_id": "<uuid>"
}
```

### Схема відповіді

```json
// Успіх
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {...}
}

// Помилка
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": <number>,
    "message": "Server error. Requested method not found"
  }
}
```

Коди помилок (видно зі строк):
- `Server error. Invalid method parameters`
- `Server error. Requested method not found`
- `Server error. Invalid rpc. Not conform`
- `Server error. Internal rpc error`

### Методи для авторизації в СЕДО

Життєвий цикл з диспатч-таблиці:

```
1. Initialize()                 — перша функція в таблиці
2. SetSettings(opts)
3. SetUIMode(noGui=true)
4. GetHostInfo()                — інфо про робочу станцію
5. EnumKeyMediaDevices()        — знайти підключений Алмаз
6. ReadPrivateKey(dev, pin)     — login, PIN передається
7. IsPrivateKeyReaded()         — перевірка успіху
8. EnumOwnCertificates()        — перелік сертів
9. GetOwnCertificate(idx)       — повний сертифікат
10. SignData(data, opts)         — підпис challenge від СЕДО
    — або SignHash(hash)         — якщо вже відомий хеш
11. ResetPrivateKey()           — logout
12. Finalize()
```

### Поля відповіді (повний JSON schema)

```
Сертифікат (subject / issuer):
  signSerial, signIssuer, issuerCN, issuerPublicKeyID
  subjCN, subjFullName, subjOrg, subjOrgUnit, subjTitle
  subjAddress, subjLocality, subjState, subjCountry
  subjEMail, subjPhone, subjDNS
  subjType, subjSubType

Україна-специфічні:
  subjDRFOCode, subjEDRPOUCode, subjUNZR
  subjOCode, subjOUCode, subjNBUCode, subjSPFMCode
  subjUserCode, subjUserID

Ключ:
  publicKey, publicKeyBits, publicKeyID, publicKeyType
  privateKey, privateKeyInfo
  ECDHPublicKey, ECDHPublicKeyID
  keyUsage, keyUsageType, extKeyUsages

Час:
  certBeginTime, certEndTime
  privKeyBeginTime, privKeyEndTime
  signTimeStamp, timeInfo, thisUpdate, nextUpdate

CRL / OCSP:
  crlNumber, crlDistribPoint1, crlDistribPoint2, revokedItemsCount
  ownCRLsOnly, fullAndDeltaCRLs
  useOCSP, useLDAP, useCMP, useTSL
  autoDownloadCRLs, autoDownloadTSL
  checkCRLs, tslAddress

Статус:
  isSelfSigned, isSubjCA, isQSCD, isPowerCert
  isCertTimesAvail, isPrivKeyTimesAvail, isSignTimeStampAvail
  isECDHPublicKeyAvail, isTimeAvail, isFilled

Інше:
  keyMedia, requestType, caType, chainLength
  activeSessions, gatedSessions, savePassword
```

---

## 4. EUSignCP.dll — крипто-бібліотека

606 експортованих функцій з префіксом `EU*`. Ключові:

**Життєвий цикл:**
- `EUInitialize`, `EUFinalize`, `EUIsInitialized`, `EUGetVersion`

**Ключі:**
- `EUReadPrivateKey`, `EUReadPrivateKeyBinary`, `EUReadPrivateKeyFile`
- `EUIsPrivateKeyReaded`, `EUResetPrivateKey`, `EUDestroyPrivateKey`
- `EUEnumKeyMediaDevices`, `EUEnumKeyMediaTypes`
- `EUChangePrivateKeyPassword`, `EUBackupPrivateKey`

**Сертифікати:**
- `EUEnumOwnCertificates`, `EUGetOwnCertificate`
- `EUCheckCertificate`, `EUCheckCertificateByOCSP`, `EUCheckCertificateByIssuerAndSerial`
- `EUParseCertificate`, `EUGetCertificateInfo`, `EUGetCertificateChain`

**Підпис (CAdES):**
- `EUSignData`, `EUSignFile`, `EUSignHash`
- `EUSignDataBegin`, `EUSignDataContinue`, `EUSignDataEnd` (stream API)
- `EUAppendSign` (приєднати другий підпис), `EUCreateSigner`

**Верифікація:**
- `EUVerifyData`, `EUVerifyFile`, `EUVerifyHash`
- `EUVerifyDataInternal`, `EUVerifyDataOnTime` (з timestamp check)
- `EUGetSigner`, `EUGetSignerInfo`, `EUGetSignsCount`, `EUGetSignTimeInfo`

**Інші формати:**
- `EUASiCSignData`, `EUASiCVerifyData` (ASiC-S/E контейнери)
- `EUPDFSignData`, `EUPDFVerifyData` (PDF підпис)
- `EUXAdESSignData`, `EUXAdESVerifyData` (XML підпис)
- `EUCOSESignData`, `EUCOSEVerifyData` (COSE/CBOR)

**Шифрування:**
- `EUEnvelopData`, `EUDevelopData` (CMS EnvelopedData)
- `EUProtectDataByPassword`, `EUUnprotectDataByPassword`

---

## 5. KM.EKeyAlmaz1C.dll — прямий драйвер Алмаза

| Властивість | Значення |
|---|---|
| Роль | Прямий CCID driver для Алмаз-1К |
| Розмір | 676 KB |
| Експорти | `KMEnumDeviceTypes`, `KMGetInterface`, `KMFinalize` |
| Imports | **Тільки WinSCard (8 функцій) + KERNEL32 + ADVAPI32** |

### WinSCard імпорти (виключний список)

```
SCardEstablishContext
SCardListReadersA
SCardConnectA
SCardTransmit          ← APDU tx/rx
SCardGetAttrib
SCardDisconnect
SCardReleaseContext
g_rgSCardT1Pci         ← T=1 protocol PCI
```

**Висновок:** drop-in заміна на Linux = використати `pcscd + libccid` замість `WinSCard.dll`. API ідентичне через PCSC Lite.

### APDU в коді

APDU формуються динамічно на стеці (не byte-literals в .rdata), тому статичний strings-пошук не дає повної картини. Потрібен runtime трейс через API Monitor на `SCardTransmit`.

Ідентифікатор mutex: `Global\EKAlmaz1COpenMutex` — синхронізація доступу до пристрою між процесами.  
Reader name pattern: `IIT E.Key Almaz-1C`.

---

## 6. KM.PKCS11.dll — маршрутизатор PKCS#11

**Це НЕ PKCS#11 модуль**, а **завантажувач PKCS#11 модулів** — викликає `C_GetFunctionList` на зовнішніх .dll.

### Таблиця маршрутизації (з .rdata)

| Модуль | Токен | Примітка |
|---|---|---|
| `PKCS11.EKeyAlmaz1C.dll` | E.key_Almaz-1C | **НЕ у Web.zip** — ключовий артефакт! |
| `PKCS11.Virtual.EKeyAlmaz1C.dll` | E.key_Almaz-1C | Віртуальний (без HW) |
| `PKCS11.EKeyCrystal1.dll` | E.key_Crystal-1 | |
| `PKCS11.NCMGryada301.dll` | NCM_Gryada301 | OID 1.3.6.1.4.1.19398.1.1.8.31 |
| `PKCS11.CModGryada61.dll` | C.mod_Gryada-61 | |
| `Av337CryptokiD.dll` | CC-337 / ST-338 | **Є в Web.zip** |
| `avcryptokinxt.dll` | AvestKey / EfitKey | **Є в Web.zip** |
| `efitkeynxt.dll` | EfitKey | **Є в Web.zip** |
| `plcpkcs11.dll` | TEllipse3 | Є в Web.zip |
| `jcPKCS11ua.dll` | JaCarta | |
| `pkcs11.dll` | iToken | |
| `eTPKCS11.dll` / `asepkcs.dll` / `aetpkss1.dll` | eToken (Aladdin) | |
| `dkck201.dll` | (Aladdin PKI) | |
| `cihsm.dll` | Cipher-HSM | OID 1.3.6.1.4.1.19398.1.1.8.25 |

**Критично:** якщо дістати `PKCS11.EKeyAlmaz1C.dll` з повного інсталятора IIT:
1. Це стандартний PKCS#11 модуль
2. Може бути завантажений у OpenSSL 4.0 через pkcs11-provider
3. Може бути скопійований на Linux (можливо через wine або після перекомпіляції, якщо знайдеться .so варіант)
4. Шлях В (20 тижнів) зменшується до **1-2 тижнів**

---

## 7. Оновлення планів

### Шлях Б (гібрид) — тепер 2-3 тижні замість 6

**Було:** розвідка Fiddler + реверс протоколу + написання агента.  
**Стало:** протокол JSON-RPC 2.0 відомий повністю, залишилось:

1. **Тиждень 1:** Дамп реєстру `HKLM\...\Sign Agent` → отримати `HTTPPort`, `HTTPSPort`, `TrustedSites`
2. **Тиждень 1-2:** Fiddler на localhost — зняти точний порядок викликів СЕДО (не WHAT а WHICH методи з 500 викликаються)
3. **Тиждень 2:** Python клієнт:

```python
import requests

class IITClient:
    def __init__(self, port=None):
        if port is None:
            port = self._read_port_from_registry()
        self.base = f"http://127.0.0.1:{port}/json-rpc"
        self.session = requests.Session()
        self.session_id = None
        self.rpc_id = 0

    def call(self, method, params=None):
        self.rpc_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.rpc_id,
            "method": method,
            "params": params or [],
        }
        if self.session_id:
            payload["session_id"] = self.session_id
        r = self.session.post(self.base, json=payload,
                              headers={"Origin": "https://sedo.mod.gov.ua"})
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise Exception(f"RPC error {data['error']['code']}: {data['error']['message']}")
        return data.get("result")

    def authorize(self, pin):
        self.call("Initialize")
        self.call("SetUIMode", [True])  # no GUI prompts
        devices = self.call("EnumKeyMediaDevices")
        self.call("ReadPrivateKey", [devices[0], pin])
        certs = self.call("EnumOwnCertificates")
        return certs

    def sign(self, data: bytes):
        return self.call("SignData", [data.hex(), {...}])
```

**Ansible змінюється** — замість Selenium (який я пропонував) викликаємо Python напряму на Windows worker:

```yaml
- name: Авторизація в СЕДО
  ansible.windows.win_command:
    cmd: python sedo_client.py --pin {{ vault_pin }} --url https://sedo.mod.gov.ua
  no_log: true
```

### Шлях В (pure Linux) — два варіанти

**Варіант В1 — знайти PKCS11.EKeyAlmaz1C.dll:**
- Завантажити повний IIT інсталятор (не Web-subset)
- Виділити `PKCS11.EKeyAlmaz1C.dll`
- Запустити через Wine на Linux, з pcscd для USB доступу
- Або: експортувати як ctypes бібліотеку
- **Оцінка: 1-2 тижні** замість 20

**Варіант В2 — open-almaz з нуля (оригінальний план):**
- Реверс-інжиніринг APDU через API Monitor на SCardTransmit
- Написати `open_almaz.so` на C++
- Розробити PKCS#11 інтерфейс з нуля
- **Оцінка: 13-20 тижнів**

Рекомендація: спочатку спробувати В1 — він швидший і менш ризикований.

---

## 8. Що робити зараз

### Негайно (без нової інформації)

1. Написати Python JSON-RPC клієнт (скелет вище) — 1-2 дні
2. Додати до проекту ua-sign-verify модуль `iit_client.py`
3. Підготувати Ansible playbook для WinRM-виклику агента

### Потребує Windows-машини з IIT + Алмаз

1. **Дамп реєстру:**
   ```
   reg export "HKLM\SOFTWARE\Institute of Informational Technologies" iit_registry.reg
   ```
   Шукаємо: HTTPPort, HTTPSPort, TrustedSites

2. **Fiddler capture** під час логіну на sedo.mod.gov.ua:
   - `GET <sedo>/auth`
   - `GET` на 127.0.0.1:port (challenge/init)
   - `POST /json-rpc` з Initialize, потім ReadPrivateKey, потім SignData
   - Відповідь на СЕДО

3. **Файл `ospus.ini`** — знайти (зазвичай `%PROGRAMDATA%\IIT` або `%APPDATA%\IIT`)

4. **Повний інсталятор IIT** (не Web.zip):
   - Перевірити наявність `PKCS11.EKeyAlmaz1C.dll`
   - Якщо є — одразу відкриває Шлях В1

### Додаткові бібліотеки які б допомогли

- `ospus.ini` — точна конфігурація
- `PKCS11.EKeyAlmaz1C.dll` — ключ до Linux-шляху
- JS-файл IIT віджета (у коді Edge extension або локально) — фактичні виклики з браузера
- Будь-який інший DLL не з Web-підмножини (бо він робочий, а Web — це для вбудовування)

