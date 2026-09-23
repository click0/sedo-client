# IIT EUSignAgent JSON-RPC Protocol

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.30
License:  BSD 3-Clause
Year:     2025-2026
```

## Джерело

Документи протоколу IIT публічно не оприлюднюють. Відомості нижче отримано
реверс-інжинірингом DLL (EUSignAgent, EUSignRPC) + аналізом web-розширення
"ІІТ Користувач ЦСК-1 (web-р.)".

Референсне online: http://js.sign.eu.iit.com.ua/

## Транспорт

- **Endpoint:** `http://127.0.0.1:8081/json-rpc` (HTTP)
- **Альтернатива:** `https://127.0.0.1:8083/json-rpc` (з self-signed `EUSignAgent.cer`)
- **Method:** POST
- **Content-Type:** `application/json`
- **WebSocket альтернатива:** Upgrade на тому самому порту (reverse-engineered)
- **CORS:** `Origin` header перевіряється проти whitelist у реєстрі
  (`HKLM\...\Sign Agent\TrustedSites`)

### Порти з реєстру (підтверджено)

```
HKLM\SOFTWARE\WOW6432Node\Institute of Informational Technologies\
    Certificate Authority-1.3\End User\Libraries\Sign Agent\Common
        HTTPPort     = 8081
        HTTPSPort    = 8083
        AutoRun      = 0   (ручний запуск)
        RunAsProcess = 1   (окремий процес)
```

## Формат запиту

```json
{
    "jsonrpc": "2.0",
    "id": <integer>,
    "method": "<method_name>",
    "params": [...],
    "session_id": "<opaque string>"
}
```

`session_id` — розширення IIT, не стандартний JSON-RPC. Опціональний для перших
викликів, повертається сервером після `Initialize`.

## Формат відповіді (успіх)

```json
{
    "jsonrpc": "2.0",
    "id": <integer>,
    "result": <any>
}
```

## Формат помилки

```json
{
    "jsonrpc": "2.0",
    "id": <integer>,
    "error": {
        "code": <integer>,
        "message": "<string>"
    }
}
```

### Коди помилок RPC (з EUSignRPC.dll)

Рядки в DLL ідуть рівно в порядку специфікації кодів помилок xmlrpc-epi
("Fault Code Interoperability"), тож коди — з неї:

| Код | Повідомлення (дослівно з DLL) |
|---|---|
| `-32700` | Parse error. Not well formed |
| `-32701` | Parse error. Unsupported encoding |
| `-32702` | Parse error. Invalid character for encoding |
| `-32600` | Server error. Invalid rpc. Not conforming to spec |
| `-32601` | Server error. Requested method not found |
| `-32602` | Server error. Invalid method parameters |
| `-32603` | Server error. Internal rpc error |
| `-32500` | Application error |
| `-32400` | System error |
| `-32300` | Transport error |
| ? | Application error. Invalid session (розширення ІІТ; код невідомий) |

### Коди помилок крипто-операцій (з EUSignCP.dll)

```
Error at opening private key (an incorrect password or key is damaged)
Cryptographic operation failed
Error at parsing or generating data (data corrupted or wrong format)
Certificate not found
Certificate is invalid (while verifying in CRL)
Certificate or corresponding private key invalid by time
TSP-server's certificate invalid (may be no valid CRLs found)
TSP-server's certificate not found
Error at loading base libraries       ← CSPBase.dll / CSPExtension.dll не знайдено
Error at reading private key from the key media
Error at access to the key media
Error at cleaning key media           ← УВАГА: можна знищити ключ
Error at the writing settings
Error during work with key media
Authentication error (authentication data corrupted)
```

## Послідовність авторизації

```
1. Initialize()
      → {}  (empty result)

2. SetUIMode(false)
      → true   // вимикає GUI prompts

3. GetHostInfo()
      → {"os": "Windows", "arch": "x86", "version": "...", ...}

4. EnumKeyMediaDevices()
      → [{"devIndex": 0, "typeIndex": 7, "keyMedia": "E.key_Almaz-1C", ...}]

5. ReadPrivateKey(device, pin)
      → true
      // (або error -32603 якщо PIN неправильний)

6. IsPrivateKeyReaded()
      → true

7. EnumOwnCertificates()
      → [{"index": 0, "serial": "...", "issuer": "...", ...}]

8. GetOwnCertificate(0)
      → {
          "data": "<hex-encoded DER certificate>",
          "subjCN": "Іванов Іван Іванович",
          "subjDRFOCode": "1234567890",
          "subjEDRPOUCode": "...",
          ...
        }

9. Sign(b64_data, {internal: true})
      → "<base64 CMS SignedData>"
      // у таблиці методів EUSignRPC 1.3.1.109 є "Sign", "SignHash", "SignFile",
      // "SignInternal" — методу "SignData" немає; iit_client пробує "Sign",
      // а на -32601 (method not found) — "SignData" для старих агентів

10. ResetPrivateKey()
      → true

11. Finalize()
      → true
```

## Каталог методів (EUSignRPC.dll 1.3.1.109, 2026-07)

Таблиця імен методів витягнута з `.rdata` диспетчера (суцільний блок ASCII-рядків
поруч із `Initialize`/`Finalize`): **354 записи**, повний список —
`docs/inventory/exports/EUSignRPC.dll@1.3.1.109-methods.txt`. Правило іменування:
RPC-метод = експорт `EUSignCP` без префікса `EU` і без суфікса `Data`
(`EUSignData` → `Sign`, `EUVerifyData` → `Verify`, `EUEnvelopData` → `Envelop`,
`EUSignHash` → `SignHash`). Раніше в цьому документі стояли вгадані імена
(`SignData`, `VerifyData`, `EnvelopData`, `GetTSPStamp`, `OCSPCheckCertificate`,
`DeletePrivateKey`, `AddCertificate`…) — **їх у таблиці немає**. Сигнатури
параметрів нижче — з JS-віджета ІІТ і Fiddler-нотаток, не з бінарника.

Відтворити: `strings -n 3 EUSignRPC.dll`, взяти суцільний блок ідентифікаторів
навколо `GetOwnCertificate` (у 1.3.1.109 — рядки 5268–5621 виводу `strings`).

### Ініціалізація (8)
- `Initialize()`, `Finalize()`, `IsInitialized()` → bool
- `SetUIMode(bool)`, `GetVersion()` → "1.3.x", `GetHostInfo()` → {os, arch, …}
- `ResetOperation()`, `ResetOperationCtx()`

### Носії ключів і приватний ключ (35)
- `EnumKeyMediaDevices()`, `EnumKeyMediaTypes()`, `GetKeyMediaDevices()`,
  `GetKeyMediaTypes()`, `GetKeyMediaDeviceInfo()`, `IsHardwareKeyMedia()`
- `ReadPrivateKey(device, pin)`, `ReadPrivateKeySilently()`, `ReadPrivateKeyFile()`,
  `ReadPrivateKeyBinary()`, `IsPrivateKeyReaded()` → bool, `ResetPrivateKey()`
- `ChangePrivateKeyPassword()`, `ChangeSoftwarePrivateKeyPassword()`,
  `GetPrivateKeyOwnerInfo()`, `IsPrivateKeyExists()`, `BackupPrivateKey()`,
  **`DestroyPrivateKey()`** ⚠️ знищує ключ (не `DeletePrivateKey`)
- `GeneratePrivateKeyEx()`, `GetJKSPrivateKey*()`, `EnumJKSPrivateKeys*()`,
  `SetKeyMediaPassword()`, `SetKeyMediaUserPassword()`, `Get/SetKeyMediaSettings()`
- `Ctx*`: `CtxReadPrivateKey()`, `CtxReadPrivateKeyBinary()`, `CtxFreePrivateKey()`,
  `CtxEnumPrivateKeyInfo()`, `CtxExportPrivateKeyPFXContainer()`
- `SServerClient*` (6): серверний підпис/генерація ключа, async + `Check*Status`

### Сертифікати (23)
- `EnumOwnCertificates()`, `GetOwnCertificate(index)` → {data: hex DER, subjCN, …},
  `ShowOwnCertificate()`
- `GetCertificate()`, `GetCertificateInfo()`, `GetCertificateInfoEx()`,
  `GetCertificates()`, `GetCertificatesCount()`, `EnumCertificates()`,
  `ShowCertificates()`, `SelectCertificateInfo()`
- `GetCertificateByKeyInfo()`, `GetCertificatesByKeyInfo()`, `GetCertificateByFingerprint()`,
  `GetCertificateByEmail()`, `GetCertificateByNBUCode()`,
  `GetCertificatesByEDRPOUAndDRFOCode()`, `GetCertificatesFromLDAPByEDRPOUCode()`
- `GetSignerCertificate()`, `GetFileSignerCertificate()`,
  `GetCertificateFromSignedData()`, `GetCertificateFromSignedFile()`,
  `GetReceiversCertificates()`

### Підпис (8 + Ctx/Raw/Append)
- **`Sign(b64_data, options)`** → base64 CMS — те, що викликає `iit_client.sign_data`
- `SignHash(b64_hash)`, `SignFile(path)`, `SignInternal()`,
  `SignRSA()`, `SignHashRSA()`, `SignRSAFile()`, `SignECDSA()`
- потокові: `ContinueSign()`, `EndSign()` (+ `*Ctx`, `*RSA*`)
- `AppendSign()`, `AppendSignHash()`, `AppendSignFile()`, `AppendSigner()`,
  `AppendValidationDataToSignerEx()`, `CreateSignerEx()`, `CreateEmptySign()`
- `RawSign()`, `RawSignHash()`, `RawSignFile()`; `CtxSign()`, `CtxSignHash()`,
  `CtxSignFile()`, `CtxAppendSign*()`
- контейнери: `ASiC*` (12), `XAdES*` (9), `PDF*` (6), `CtxASiC*`, `CtxXAdES*`, `CtxPDF*`
- `NBUSign()` / `NBUVerify()`

### Верифікація (14 + Raw/Ctx)
- **`Verify(b64_data, b64_sign)`** (не `VerifyData`), `VerifyHash()`, `VerifyFile()`,
  `VerifyInternal()`, `VerifySpecific*()`, `VerifyDataOnTimeEx()`, `VerifyFileOnTimeEx()`,
  `VerifyHashOnTimeEx()`, `VerifyDataInternalOnTimeEx()`
- потокові: `BeginVerify()`, `ContinueVerify()`, `EndVerify()` (+ `*Ctx`)
- `RawVerify()`, `RawVerifyHash()`, `RawVerifyFile()`
- інформація: `GetSignerInfo()`, `GetFileSignerInfo()`, `GetSignsCount()`,
  `GetFileSignsCount()`, `GetSignTimeInfo()`, `GetSignType()`, `IsSigned()`,
  `IsSignedFile()`, `IsAlreadySigned()`, `IsDataInSignedDataAvailable()`…

### Шифрування (18 + 3 + Raw)
- **`Envelop(b64_data, recipients)`** (не `EnvelopData`), `EnvelopEx()`, `EnvelopFile()`,
  `EnvelopToRecipients*()`, `Envelop*RSA*()`, `Envelop*WithDynamicKey()`,
  `EnvelopToRecipientsWithOCode()`, `EnvelopToRecipientsWithSettings()`
- `Develop()`, `DevelopEx()`, `DevelopFile()`; `RawEnvelop()`, `RawDevelop()`
- `ProtectDataByPassword()` / `UnprotectDataByPassword()`
- сесії: `ClientSessionCreateStep1/2()`, `ServerSessionCreate*()`,
  `SessionEncrypt()`, `SessionDecrypt()`, `SessionLoad()`, `SessionSave()`…

### TSP / OCSP / CMP / налаштування (17)
- `CheckTSP()`, `GetTSPByAccessInfo()`, `Get/SetTSPSettings()`
- `CheckOCSPResponse()`, `GetOCSPResponseByAccessInfo()`, `Get/SetOCSPSettings()`,
  `*OCSPAccessInfoSettings()`, `*OCSPAccessInfoModeSettings()`, `SetOCSPResponseExpireTime()`
- `Get/SetCMPSettings()`, `Get/SetProxySettings()`, `Get/SetLDAPSettings()`,
  `Get/SetModeSettings()`, `Get/SetFileStoreSettings()`, `SetSettings()`, `SaveSettings()`
- хеш: `Hash()`, `HashFile()`, `ContinueHash()`, `EndHash()`, `GetDataHashFromSigned*()`

Три останні записи таблиці (`ProxyType`, `SaveSettings`, `StringEncoding`) можуть
бути ключами налаштувань, а не методами — межа блоку визначена евристично.

## 110+ JSON полів сертифіката

З аналізу `EUSignRPC.dll` / `EUSignCP.dll` витягнуто повний набір полів:

### Сертифікат
```
signSerial, signIssuer
issuerCN, issuerPublicKeyID
```

### Суб'єкт (людина або організація)
```
subjCN, subjFullName, subjGivenName, subjSurname
subjOrg, subjOrgUnit, subjTitle
subjAddress, subjLocality, subjState, subjCountry, subjPostal
subjEMail, subjPhone, subjDNS
```

### Українські ідентифікатори
```
subjDRFOCode       — ДРФО/ІПН фізичної особи (10 цифр)
subjEDRPOUCode     — ЄДРПОУ юридичної особи (8 цифр)
subjUNZR           — унікальний номер запису в ЄДДР
subjOCode          — код організації (1 цифра)
subjOUCode         — код підрозділу
subjNBUCode        — код НБУ
subjSPFMCode       — код ДФС
subjUserCode       — внутрішній код користувача
subjUserID         — ID у ЦСК
```

### Часові мітки
```
certBeginTime, certEndTime
privKeyBeginTime, privKeyEndTime
signTimeStamp, timeInfo
```

### Флаги
```
isSelfSigned       — самопідписаний
isSubjCA           — є CA
isQSCD             — Qualified Signature Creation Device
isPowerCert        — кваліфікована печатка
```

## Приклад повного запиту

```python
import requests
import json
import base64

url = "http://127.0.0.1:8081/json-rpc"
headers = {
    "Content-Type": "application/json",
    "Origin": "https://sedo.mod.gov.ua",
    "User-Agent": "sedo-client/0.30",
}

# 1. Initialize
r = requests.post(url, headers=headers, json={
    "jsonrpc": "2.0",
    "id": 1,
    "method": "Initialize",
    "params": []
})
session_id = r.json().get("session_id")

# 2. Login на токен
r = requests.post(url, headers=headers, json={
    "jsonrpc": "2.0",
    "id": 2,
    "method": "ReadPrivateKey",
    "params": [
        {"devIndex": 0, "typeIndex": 7, "keyMedia": "E.key_Almaz-1C"},
        "XXXXX"  # PIN
    ],
    "session_id": session_id
})

# 3. Підписати дані
data = b"hello world"
r = requests.post(url, headers=headers, json={
    "jsonrpc": "2.0",
    "id": 3,
    "method": "Sign",   # не "SignData" — див. каталог методів
    "params": [
        base64.b64encode(data).decode(),
        {"internal": True}  # CAdES-BES
    ],
    "session_id": session_id
})
signature = base64.b64decode(r.json()["result"])
```
