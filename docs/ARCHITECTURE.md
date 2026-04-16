# Архітектура sedo-client

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.25
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

## Огляд

```
Linux Ansible controller
    │
    │ WinRM over HTTPS (port 5986)
    │ auth: CredSSP + ansible_operator
    ▼
Windows worker
    │
    ├── Python Runtime (3.11/3.12)
    │       ↓
    │   sedo_client.py — бізнес-логіка СЕДО
    │       ↓
    │   [backend вибирається авто або явно]
    │       │
    │       ├── opensc_signer.py ─── subprocess ─▶ pkcs11-tool.exe (32-bit OpenSC)
    │       │                                          ↓
    │       │                                     --module PKCS11.EKeyAlmaz1C.dll
    │       │
    │       ├── pkcs11_signer.py ─── PyKCS11 (ctypes) ──▶ PKCS11.EKeyAlmaz1C.dll
    │       │
    │       └── iit_client.py ─── HTTP POST ──▶ http://127.0.0.1:8081/json-rpc
    │                                                ↓
    │                                           EUSignAgent.exe (GUI Користувач ЦСК)
    │                                                ↓
    │                                           EUSignCP.dll → KM.PKCS11.dll →
    │                                                ↓
    │                                           PKCS11.EKeyAlmaz1C.dll
    │
    └── IIT бінарки (усі 32-bit PE32)
            │
            ├── C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C\
            │       ├── PKCS11.EKeyAlmaz1C.dll    (356 KB)
            │       ├── CSPBase.dll               (1.15 MB)
            │       └── CSPExtension.dll          (80 KB)
            │
            ├── *.cap параметри (розкидані по кількох директоріях)
            │
            └── C:\ProgramData\Institute of Informational Technologies\
                Certificate Authority-1.3\End User\Sign Agent\
                    ├── EUSignAgent.cer       (self-signed)
                    ├── EUSignAgent.pem
                    └── EUSignAgentCA.cer
                        │
                        ▼
                    WinSCard → pcscd → CCID driver → USB
                        │
                        ▼
                    Алмаз-1К (IIT E.Key Almaz-1C, VID:PID=0x03EB:0x9324)
```

## Розподіл відповідальностей

### Linux controller

| Компонент | Роль |
|---|---|
| Ansible playbook | Оркестрація: запуск, моніторинг, ротація |
| Ansible Vault | Зберігання PIN токена, Telegram bot token |
| ua-sign-verify | Post-fetch верифікація підписів документів |
| Cron | Тригер (щодня о 8:00 або аналогічно) |
| Telegram bot | Нотифікації про статус виконання |

### Windows worker

| Компонент | Роль |
|---|---|
| WinRM HTTPS | Приймає команди від Ansible |
| Python 3.11/3.12 | Виконує sedo_client.py |
| sedo_client | Бізнес-логіка: login, fetch, завантаження |
| 32-bit OpenSC | pkcs11-tool (основний шлях через subprocess) |
| IIT бібліотеки | PKCS11 модуль + криптографія |
| Алмаз-1К USB | Приватний ключ оператора |

## Data flow — один запуск playbook

```
1. Linux:  cron → ansible-playbook
2. Linux:  ansible-vault decrypt PIN
3. WinRM:  передача команди + PIN (no_log!)
4. Win:    sedo_client.py запускається
5. Win:    auto-discover backend → OpenSC (найчастіше)
6. Win:    login на Алмаз (C_Login з PIN)
7. Win:    GET https://sedo.mod.gov.ua/auth/... (з Cert)
8. Win:    challenge/response через PKCS#11 sign
9. Win:    session cookies збережені
10. Win:   fetch список документів
11. Win:   для кожного — download .zip з підписами
12. Win:   логаут з токена (C_Logout)
13. WinRM: fetch файлів назад на Linux
14. Linux: для кожного ZIP — ua-sign-verify
15. Linux: формування звіту
16. Linux: Telegram post з результатами
```

## Вибір backend

Логіка `sedo_client.py::_pick_backend()`:

```
якщо --backend=auto (або не вказано):
    спробувати opensc → PyKCS11 → iit_agent
якщо --backend=opensc: 
    потребує pkcs11-tool.exe (32-bit)
якщо --backend=pkcs11: 
    потребує PyKCS11 (може бути складно компілювати)
якщо --backend=iit_agent: 
    потребує запущеної "Користувач ЦСК" GUI (HTTP на 8081)
```

Рекомендація: **opensc** — простіший у деплойменті, менше залежностей.

## Потік авторизації — три варіанти

**Fiddler capture потрібен** для точної ідентифікації (див. `FIDDLER-CAPTURE-GUIDE.md`).

### Варіант A — OIDC через id.gov.ua
```
Client → GET sedo.mod.gov.ua/auth/login
       ← 302 to id.gov.ua/?client_id=...&state=...
Client → GET id.gov.ua/oauth2/authorize  
       ← HTML з JS викликом IIT підпису
Client → підпис виклику (через PKCS#11)
Client → POST id.gov.ua/callback (signed)
       ← 302 to sedo.mod.gov.ua/auth/callback?code=X
Client → GET sedo.mod.gov.ua/auth/callback?code=X
       ← Set-Cookie: session=...
```

### Варіант Б — Direct KEP challenge
```
Client → POST sedo.mod.gov.ua/api/auth/kep/init
       ← {challenge: "base64...", session_id: "..."}
Client → PKCS#11 sign(challenge)
Client → POST sedo.mod.gov.ua/api/auth/kep/verify
         body: {signature, certificate, session_id}
       ← 200 OK + Set-Cookie
```

### Варіант В — CMS POST
```
Client → POST sedo.mod.gov.ua/signin 
         body: повний CMS SignedData (CAdES-BES)
       ← 200 OK + session
```

## Безпека

### PIN
- **Ніколи** не в коді, скриптах, чи git
- **Тільки** у Ansible Vault
- `no_log: true` на всіх tasks з PIN
- 15 невдалих спроб → ключ знищено Алмазом

### WinRM
- Тільки HTTPS (порт 5986)
- Обмежений user (`Remote Management Users`, не `Administrators`)
- SSL сертифікат на Windows worker

### Сертифікати агента
- `EUSignAgent.cer` — self-signed, для localhost HTTPS
- Не потребують спеціального догляду — створюються автоматично IIT ЦСК

### Коди помилок DLL
Вилучено з `EUSignRPC.dll`:
```
-32600  Invalid request
-32601  Requested method not found  
-32602  Invalid method parameters
-32603  Internal rpc error
-32700  Parse error
```

З `EUSignCP.dll`:
```
Error at opening private key (incorrect password or damaged key)
Certificate not found
TSP-server's certificate invalid
Error at access to the key media
Error at cleaning key media (!)
```
