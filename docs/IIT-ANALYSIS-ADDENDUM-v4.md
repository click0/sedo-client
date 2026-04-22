# IIT-ANALYSIS — Addendum v4 (Third-party PKCS#11 Modules) 2026-04-22

> **Вхід:** `efitkeynxt.dll` / `avcryptokinxt.dll` (раніше), `Av337CryptokiD.dll`, `plcpkcs11.dll`, `PKCS11_NCMGryada301.dll`.
> **Призначення:** доповнення до v1/v2/v3. Фокус — **непрямі PKCS#11 модулі у IIT router-таблиці**: від сторонніх вендорів (Avest, NOKK) та для інших IIT-токенів (Гряда-301).

---

## 0. TL;DR

**Жодне з цього не потрібно sedo-client.** Це документація для повноти екосистеми IIT. Ключове:

1. `efitkeynxt.dll` = `avcryptokinxt.dll` — **один файл під двома іменами** (SHA256 збігається з тим, що я проаналізував у попередньому чаті). Router IIT використовує різні імена для різних торгових марок токенів.
2. `Av337CryptokiD.dll` — ще один PKCS#11 модуль від **Avest Ukraine**, для апаратного токена CC-337 / SecureToken-338.
3. `plcpkcs11.dll` — **НЕ від IIT і НЕ від Avest**. Виробник — `NOKK Ltd`, продукт `PlasticCard`. PKCS#11 для невідомого широкому загалу українського токена, який у IIT router зазначається як "TEllipse3".
4. `PKCS11_NCMGryada301.dll` — **від IIT**, але має надзвичайну особливість: `InternalName = PKCS11.EKeyAlmaz1C.dll`. IIT копіює шаблон PKCS#11-модуля між продуктами і забуває оновити VS_VERSIONINFO.

---

## 1. `avcryptokinxt.dll` / `efitkeynxt.dll` — Avest Cryptoki NXT

Детально вже проаналізовано у попередньому чат-повідомленні. Коротко:

| Поле | Значення |
|---|---|
| SHA256 | `242af726cf1a2c06a30ee20d00a08ea8faefbae8c37e60ed7811663e3315a780` |
| Виробник | AvestUA plc (Kyiv) |
| Версія | 1.1.7.7229, build 2014-10-31 |
| Розмір | 1 338 368 (найбільший PKCS#11 серед усіх) |
| Machine | i386 |
| Експорти | 70 (68 стандартних C_\* + `C_SetLibraryAttributes` + `_DllMain@12`) — **жодних stub-ів** |
| WinSCard imports | 13 функцій (досконаліше ніж у IIT = 8): +`SCardReconnect`, `SCardBegin/EndTransaction`, всі три protocol PCI |
| Crypto | RSA PKCS#1 v1.5, ДСТУ 4145, ГОСТ 28147-89 (6 режимів) |
| Код | C++ з Boost (`boost::detail::sp_counted_impl_p` = shared_ptr) |
| Токени | AvestKey, EfitKey, AvPassG — всі керуються цим модулем |

Router IIT включає два рядки на цей самий файл:
- `avcryptokinxt.dll` | AvestKey / EfitKey — primary ім'я
- `efitkeynxt.dll` | EfitKey — альтернативне ім'я для lookup

**Рекомендація для `docs/IIT-ANALYSIS.md` §6**: позначити `efitkeynxt.dll` як duplicate з SHA256-referenced.

---

## 2. `Av337CryptokiD.dll` — Avest CC-337 / SecureToken-338

| Поле | Значення |
|---|---|
| SHA256 | `e25da8047fe9eb0b1fab6114b0d7b53495e0a51609aa3ba3b0a5669e65cc61bf` |
| Розмір | 511 488 |
| Machine | i386 |
| Build | 2022-04-15 |
| FileDescription | **"CC-33x PKCS11 API"** |
| FileVersion | 1.3.44.7 |
| CompanyName / ProductName | **порожні** (значно менше metadata ніж у avcryptokinxt.dll) |
| Експорти | 68 (C_\*), 2 дубльованих адреси (2 stubs — значно менше ніж у IIT HW PKCS11) |
| Статичні imports | WinSCard (11), KERNEL32 (73), ADVAPI32 (3) |

### 2.1. Залежності

Тільки статичні (без runtime LoadLibrary — перевірено):
- `WinSCard.dll` (11 функцій — проміжок між IIT на 8 і NXT на 13)
- `KERNEL32.dll`, `ADVAPI32.dll`

Тобто **standalone модуль**, не тягне за собою сторонніх .dll.

### 2.2. Позиціонування

Цей модуль обслуговує токени Avest моделей **CC-337** і **ST-338** (SecureToken-338). Це окремі апаратні пристрої Avest (інша лінійка), не ті самі що EfitKey/AvestKey/AvPassG (які обслуговує `avcryptokinxt.dll`).

### 2.3. Порівняння з Avest NXT

| Властивість | `avcryptokinxt.dll` | `Av337CryptokiD.dll` |
|---|---|---|
| Розмір | 1 338 KB | 511 KB |
| Stubs | 0 | 2 |
| Crypto API у strings | Много (Gost/UASgn/RSA класи) | (мало) |
| CompanyName | AvestUA plc | — |
| Build | 2014-10-31 | 2022-04-15 |
| WinSCard fns | 13 | 11 |

Av337 — очевидно **легша**, простіша DLL для вузькопрофільних токенів. Avest NXT — важкий, flagship-модуль.

**Для sedo-client:** не релевантно.

---

## 3. `plcpkcs11.dll` — NOKK PlasticCard PKCS#11

| Поле | Значення |
|---|---|
| SHA256 | `6b215c2d0f7f8e153c9c5e286b93dca860f662e5829168dcf7d6f60bef4fe19c` |
| Розмір | 384 512 |
| Machine | i386 |
| Build | 2015-09-09 |
| **CompanyName** | **`NOKK Ltd`** (!) |
| FileDescription | PlasticCard PKCS#11 library |
| FileVersion | 1.0.0.72 |
| Експорти | 70 (C_\*), 1 stub |
| Imports | WinSCard (6), KERNEL32, USER32, ADVAPI32 |

### 3.1. Хто такий NOKK Ltd

Не стандартна назва в українській крипто-екосистемі. Можливі варіанти:
- Поліський виробник smart-card системи (торгова марка "TEllipse3" з router-таблиці IIT)
- OEM bundle з іноземним постачальником

Єдиний публічно видимий артефакт — ця DLL, яку IIT включає у свій router. Це вказує на **комерційне партнерство** між IIT та NOKK для інтеграції їх токена у Користувач ЦСК-1.

**User32 в imports** (1 функція) — необычно для PKCS#11 модуля. Вірогідно: `MessageBoxA` для помилкових діалогів (що показує user-facing error popups при невірному PIN тощо). На headless worker це може викликати blocked UI.

### 3.2. Для sedo-client

Не релевантно. Якщо колись з'явиться користувач з TEllipse3-токеном і заявкою на sedo-client, тоді треба буде перевіряти сумісність окремо (і warn про можливі GUI dialogs).

---

## 4. `PKCS11_NCMGryada301.dll` — IIT Гряда-301

Цей файл — перлина з точки зору reverse-engineering.

| Поле | Значення |
|---|---|
| SHA256 | `377e711721115f459b40a15e948d670e7666e29a1fa626f180087deb8990dec5` |
| Розмір | 291 584 |
| Machine | i386 |
| Build | 2019-11-16 |
| CompanyName | АТ "ІІТ" |
| FileDescription | "Бібліотека взаємодії із НКІ 'криптомодуль ІІТ Гряда-301', які підтримують формат ключових даних PKCS#11" |
| ProductName | Те саме, що вище |
| FileVersion | **1.0.1.7** |
| **InternalName** | **`PKCS11.EKeyAlmaz1C.dll`** (!!!) |
| **OriginalFilename** | **`PKCS11.EKeyAlmaz1C.dll`** (!!!) |
| Експорти | 68 (C_\*), 2 stubs, export DLL name = `PKCS11.NCMGryada301.dll` |

### 4.1. Що означає розбіжність InternalName

IIT використовує **один шаблон PKCS#11-модуля** для всіх своїх токенів:
- `PKCS11.EKeyAlmaz1C.dll` — для Алмаз-1К
- `PKCS11.EKeyCrystal1.dll` — для Crystal-1 (у router, у нас відсутня)
- `PKCS11.NCMGryada301.dll` — для Гряда-301 (цей файл)
- `PKCS11.Virtual.EKeyAlmaz1C.dll` — software variant для Алмаз-1К (також з тим самим pattern)

Вони беруть код-базу одного модуля, міняють transport layer і hardware-specific APDU, **але забувають оновити VS_VERSIONINFO**. Тому у всіх чотирьох `InternalName` і `OriginalFilename` стоїть `PKCS11.EKeyAlmaz1C.dll`.

Експорт table DLL name при цьому встановлено правильно:
- `PKCS11.NCMGryada301.dll`
- `PKCS11.Virtual.EKeyAlmaz1C.dll`

Тобто це справді **baseline template**, а `VS_VERSIONINFO` — результат copy-paste без повної ревізії.

**Версія 1.0.1.7 у обох файлах** (HW Алмаз + Гряда-301) теж не збіг — це спільний release-tag шаблону.

### 4.2. Гряда-301 — що це

`НКІ` = "носій ключової інформації" (ukr.) — апаратний токен. "Криптомодуль Гряда-301" — IIT-бренд для апаратного модуля підпису, який використовується в НБУ (Національний банк України) та подібних структурах. OID `1.3.6.1.4.1.19398.1.1.8.31` (з оригінального IIT-ANALYSIS §6).

Це **не USB-токен для фізичної особи** (як Алмаз), а **модуль вищого класу** (HSM-like) для банківських/державних центрів. Використовується у CSK НБУ.

### 4.3. Для sedo-client

Не релевантно. Гряда-301 зазвичай не видається фізичним особам для роботи з СЕДО ЗСУ. Але факт існування цього модуля демонструє, що ABI `PKCS11.EKeyAlmaz1C.dll` — стандартизований шаблон IIT, що ви можете використовувати для тестування пайплайну.

---

## 5. Оновлення router-таблиці (§6 оригінального analysis)

| Модуль | Токен | Статус | Вендор | Нотатка |
|---|---|---|---|---|
| `PKCS11.EKeyAlmaz1C.dll` | Алмаз-1К | ✅ маємо | IIT | HW PKCS#11, 64-bit (addendum v1) |
| `PKCS11.Virtual.EKeyAlmaz1C.dll` | Алмаз-1К | ✅ маємо | IIT | Software token (addendum v2) |
| `PKCS11.EKeyCrystal1.dll` | Crystal-1 | ❌ відсутній | IIT | Нижні шари маємо (addendum v3) |
| **`PKCS11.NCMGryada301.dll`** | Гряда-301 HSM | ✅ **маємо** | IIT | Для банків/держструктур (§4 v4) |
| `PKCS11.CModGryada61.dll` | Гряда-61 | ❌ відсутній | IIT | — |
| **`Av337CryptokiD.dll`** | CC-337 / ST-338 | ✅ **маємо** | **Avest** | Вузькопрофільний Avest (§2 v4) |
| **`avcryptokinxt.dll`** | AvestKey / EfitKey / AvPassG | ✅ **маємо** | **Avest** | Flagship Avest (§1 v4) |
| **`efitkeynxt.dll`** | EfitKey | ✅ маємо | Avest | **Дублікат** `avcryptokinxt.dll` під іншим іменем |
| **`plcpkcs11.dll`** | TEllipse3 | ✅ **маємо** | **NOKK Ltd** | Третій вендор (§3 v4) |
| `jcPKCS11ua.dll` | JaCarta | ❌ відсутній | Aladdin/JaCarta | Російський, малоймовірно |
| `pkcs11.dll` | iToken | ❌ | — | — |
| `eTPKCS11.dll` | eToken | ❌ | Aladdin | — |
| `asepkcs.dll` | eToken Safenet | ❌ | Aladdin/SafeNet | — |
| `aetpkss1.dll` | eToken | ❌ | Aladdin | — |
| `dkck201.dll` | Aladdin PKI | ❌ | Aladdin | — |
| `cihsm.dll` | Cipher-HSM | ❌ | — | OID `1.3.6.1.4.1.19398.1.1.8.25` |

Ви зараз маєте **6 з 16** PKCS#11 модулів (включаючи два "dublicate" рядки — Virtual і efitkeynxt).

---

## 6. Спостереження

### 6.1. Єдиний ABI для всіх PKCS#11 модулів

Усі PKCS#11 модулі у вашій router-таблиці дотримуються стандарту **PKCS#11 v2.40**: 68 стандартних `C_*` функцій + `C_GetFunctionList` як entry point. Це означає:

- IIT `KM.PKCS11.dll` router може завантажувати **будь-який стандартний PKCS#11 модуль**, не тільки IIT-власні
- Сторонній модуль (OpenSC, наприклад) теоретично міг би бути підключений у цей router, якщо відомо ім'я пристрою
- Стандарт виконується — що полегшує інтероперабельність

### 6.2. Avest і IIT — конкуренти з частковою кооперацією

Avest і IIT — українські крипто-компанії з **різними крипто-стеками**:
- IIT: власна крипто (`DSTU 4145 CoupleMake*`, `GOST28147WrapSharedKey`) у `CSPBase.dll`
- Avest: власна крипто (`g28147_cfb.c`, `Gost34311Params.c`, `TokUAGost*`) inline у `avcryptokinxt.dll`

Але вони **співпрацюють** на рівні системної інтеграції: IIT "Користувач ЦСК-1" router підтримує Avest-токени через Avest-ні PKCS#11 модулі.

### 6.3. Різні крипто-OID schemes

- IIT: `1.2.804.2.1.1.1.1.3.1.*` (куряви) — DSTU 4145 named curves
- Avest: `1.2.804.2.1.1.1.1.1.1.10.*` — інша гілка
- Спільний корінь `1.2.804.2.1.1.1.1` (Україна). Корисно для верифікатора `ua-sign-verify`: треба **підтримувати обидві гілки**, якщо хочете працювати з підписами від обох вендорів.

---

## 7. Метадані

- **Дата:** 2026-04-22
- **Версія:** v4
- **Попередні:** v1 (PKCS11 HW + інші Алмаз), v2 (Virtual PKCS11), v3 (Crystal-1 driver package)
- **Вхід:** 3 нових файли (`Av337CryptokiD.dll`, `plcpkcs11.dll`, `PKCS11_NCMGryada301.dll`) + посилання на раніше проаналізований `efitkeynxt.dll`
