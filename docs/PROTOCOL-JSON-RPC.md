# IIT EUSignAgent JSON-RPC Protocol

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.26
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

| Код | Повідомлення |
|---|---|
| `-32600` | Invalid rpc. Not conforming to spec |
| `-32601` | Requested method not found |
| `-32602` | Invalid method parameters |
| `-32603` | Internal rpc error |
| `-32700` | Parse error |
| custom | Application error. Invalid session |

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

9. SignData(b64_data, {internal: true})
      → "<base64 CMS SignedData>"

10. ResetPrivateKey()
      → true

11. Finalize()
      → true
```

## Каталог методів (вибіркова)

EUSignRPC диспетчер містить ~500 методів. Найважливіші:

### Ініціалізація
- `Initialize()` — ініціалізує бібліотеку
- `Finalize()` — звільняє ресурси
- `SetUIMode(bool)` — GUI prompts on/off
- `IsInitialized()` → bool
- `GetVersion()` → "1.3.x"
- `GetHostInfo()` → {os, arch, ...}

### Ключі та токени
- `EnumKeyMediaDevices()` → list
- `EnumKeyMediaTypes()` → list
- `GetKeyMediaType(devIndex)` → type info
- `ReadPrivateKey(device, pin)` → bool
- `ReadPrivateKeyByIndex(...)` → variant
- `IsPrivateKeyReaded()` → bool
- `ResetPrivateKey()` → bool
- `ChangePrivateKeyPassword(old, new)` → bool
- `DeletePrivateKey(device)` → bool  // ⚠️ знищує ключ!

### Сертифікати
- `EnumOwnCertificates()` → list
- `GetOwnCertificate(index)` → cert with metadata
- `GetCertificateInfo(cert)` → detailed info
- `GetCertificate(issuer, serial)` → cert
- `AddCertificate(cert, isCA)` → bool
- `DeleteCertificate(serial, issuer)` → bool

### Підпис
- `SignData(data, options)` → signature
- `SignHash(hash, options)` → signature
- `SignFile(path, options)` → signature
- `SignDataWithTSP(data, options)` → signature + TSP
- `AppendSign(existing_sig, new_key)` → combined signature

### Верифікація
- `VerifyData(data, signature, cert)` → bool
- `VerifyHash(hash, signature, cert)` → bool
- `VerifySignedFile(path)` → verification result

### Шифрування
- `EncryptData(data, cert)` → encrypted
- `DecryptData(encrypted)` → data
- `EnvelopData(data, recipients)` → enveloped

### Тайм-стемпи та OCSP
- `GetTSPStamp(hash)` → TSP response
- `OCSPCheckCertificate(cert)` → status
- `CMPGetCertificate(request)` → cert

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
    "User-Agent": "sedo-client/0.26",
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
    "method": "SignData",
    "params": [
        base64.b64encode(data).decode(),
        {"internal": True}  # CAdES-BES
    ],
    "session_id": session_id
})
signature = base64.b64decode(r.json()["result"])
```
