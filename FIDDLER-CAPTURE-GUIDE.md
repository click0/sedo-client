# Fiddler Capture Guide — SEDO ЗСУ auth flow

**Мета:** зафіксувати точний flow авторизації на sedo.mod.gov.ua для уточнення 
sedo_client.py (заповнити TODO у _flow_oidc / _flow_direct_kep / _flow_cms_post).

**Час:** ~30 хвилин однієї ручної сесії входу.

## Встановити Fiddler

```powershell
winget install Telerik.Fiddler.Classic
# Або онлайн: https://www.telerik.com/download/fiddler
```

## Налаштувати перехоплення HTTPS

1. Tools → Options → HTTPS
2. ✓ Capture HTTPS CONNECTs
3. ✓ Decrypt HTTPS traffic
4. Actions → Trust Root Certificate
5. Applies to → All processes

## Налаштувати перехоплення localhost (для IIT Agent)

За замовчанням Windows не роутить localhost через проксі Fiddler.

**Workaround:** використовувати `127.0.0.1.` (з крапкою в кінці) 
або налаштувати proxy явно:

```powershell
# Додати в Fiddler OnBeforeRequest (QuickExec box):
# oSession.host = "ipv4.fiddler:" + oSession.port;
```

## Процедура захоплення

### Фаза 1: Звичайний логін (еталон)

1. **Clear Sessions** у Fiddler (Ctrl+X)
2. Відкрити Chrome/Edge → sedo.mod.gov.ua
3. Увійти нормально через "Користувач ЦСК" (GUI prompt)
4. Дочекатись завантаження робочого простору
5. **Зберегти sessions** (File → Save → All Sessions) як `sedo_login_reference.saz`

### Фаза 2: Аналіз

Виберіть в історії запити з виглядом:
- `GET https://sedo.mod.gov.ua/` — headers, cookies
- `GET https://sedo.mod.gov.ua/auth*` — початок логіну
- `POST https://127.0.0.1:<port>/json-rpc` — всі виклики до агента
- `POST https://sedo.mod.gov.ua/auth/callback` або схожі — відправка підпису назад
- `Location:` headers redirect-ів

### Ключові питання:

**1. Який flow?**
- Якщо бачимо redirect на `id.gov.ua` → **OIDC flow**
- Якщо бачимо POST на `sedo.mod.gov.ua/api/auth/...` з `challenge` у response → **Direct KEP**
- Якщо бачимо POST з повним CMS SignedData → **CMS POST**

**2. Конкретний endpoint path?**
- Може бути: `/auth/kep/init`, `/api/login/kep`, `/signon/kep/init` — різні варіанти
- Fiddler покаже точний.

**3. Що саме підписується?**
- Random challenge (16-32 байт)?
- JWT-token від сервера?
- Повний JSON об'єкт з `timestamp, nonce, cert_fingerprint`?

**4. Яка JSON-схема?**

Приклад очікуваного response від `/kep/init`:
```json
{
  "challenge": "base64...",
  "session_id": "abc123",
  "algorithm": "DSTU4145-257"
}
```

Приклад очікуваного request на `/kep/verify`:
```json
{
  "session_id": "abc123",
  "signature": "base64...",
  "certificate": "base64..."
}
```

## Що записати

Створіть файл `/opt/sedo-automation/docs/sedo-flow.md` з:

```markdown
## SEDO.MOD.GOV.UA Auth Flow

### Step 1: Entry
GET https://sedo.mod.gov.ua/
→ Redirect to: <URL>

### Step 2: Challenge
POST https://<...>/api/... 
Request body: (if any)
Response body: 
```json
{ ... }
```

### Step 3: Signature
JSON-RPC call to local agent:
Method: "SignData" / "SignHash" / ...
Params: [<base64 of challenge>, { ... options }]

### Step 4: Verify
POST https://<...>/api/...
Request body:
```json
{ "signature": "...", "certificate": "..." }
```
Response: Set-Cookie + 200 OK

### Cookies set:
- `sedo_session=...` (HTTP-only, Secure)
- ...
```

Потім оновити `sedo_client.py` — замінити TODO placeholders реальними URL/JSON.

## Фаза 3: Повторний прогон з Python клієнтом

Після оновлення sedo_client.py, запустити з логуванням:

```powershell
python sedo_client.py `
    --url https://sedo.mod.gov.ua `
    --backend pkcs11 `
    --pin <PIN> `
    --verbose 2>&1 | Tee-Object sedo_test.log
```

Порівняти sedo_test.log з sedo_login_reference.saz (те саме?).

## Корисні фільтри в Fiddler

```javascript
// Show only SEDO + localhost IIT
oSession.HostnameIs("sedo.mod.gov.ua") || 
oSession.HostnameIs("127.0.0.1") ||
oSession.HostnameIs("id.gov.ua")
```

## Що робити якщо IIT Agent не видно

Fiddler не перехоплює localhost за замовчуванням. Альтернативи:

1. **Chrome DevTools Network tab** — бачить fetch() до localhost
2. **Wireshark + SSL key log** — якщо HTTPS:
```powershell
$env:SSLKEYLOGFILE = "C:\temp\ssl.log"
# Потім стартувати Chrome з цим env
```
3. **Проксі Fiddler на явний порт** — налаштувати в системних proxy settings

## Приклад очікуваного результату

Після 30-хв сесії у вас має бути:
- `sedo_login_reference.saz` — повний захоплений лог
- `docs/sedo-flow.md` — документація flow
- Оновлений `sedo_client.py` з правильними URL

Це дозволить повністю автоматизувати авторизацію.
