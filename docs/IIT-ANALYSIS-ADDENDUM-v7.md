# IIT-ANALYSIS — Addendum v7 (Web-компонент 2026-07: EUSignCP 1.3.1.222, CSPBase 1.1.0.174, KM.PKCS11 1.0.1.39) 2026-09-12

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

> **Вхід:** архів `Web_dll.7z` від власника (10 DLL + 9 `.cap`, усі 32-bit, білди
> 2026-05…07; sha256 архіву `78f91381c1d0acee1e07ac38f40b425b661e6587477395ae879266f4f65cd1b7`).
> Це web-компонент підпису (EUSignWeb), **не** драйвер Алмаз-1К.
> **Призначення:** зафіксувати snapshot **S3-2026-07-web_dll**, порівняти з
> S1 (v5, 2025) і S2 (v6, 2023–24), оновити перелік `.cap`. Перший addendum,
> згенерований і відтворюваний скриптом (`scripts/iit_inventory.py`); сирі дані —
> `docs/inventory/S3-2026-07-web_dll.json`, експорти — `docs/inventory/exports/`.

---

## 0. TL;DR — головне для sedo-client

1. 🔁 **Крипто-ядро оновилось**: CSPBase 1.1.0.173 → **1.1.0.174** (2026-06-29),
   EUSignCP 1.3.1.209 → **1.3.1.222** (2026-07-31, 619 → 630 експортів),
   KM.PKCS11 1.0.1.37 → **1.0.1.39**, KM.EKeyAlmaz1C 1.0.1.9 → **1.0.1.13**.
2. ⚠️ **`PKIFormats.dll` — та сама версія 1.2.0.171, інший бінарник** (build 2026-07-01,
   sha `e9011e94…` проти `25ac050a…` у S1). Версія з ресурсів **не** є ідентичністю
   файла; звіряти треба sha256 (для цього і є `docs/DLL-REGISTRY.md`).
3. 📦 **Змінився набір `.cap`**: `CSPBase.dll` 1.1.0.174 шукає `DSTU4145CacheP2.cap` /
   `DSTU4145CacheN2.cap` (замість `…CachePB` / `…CacheNB` з MINIMUM-FILES-LIST), а
   `EUSignCP.dll` — ще й нові `DSTU7624SBox.cap` (Калина) і `DSTU8845SBox.cap`
   (Струмок). Наш перелік файлів для деплою оновлено (§8).
4. ✅ **`KM.PKCS11.dll` статично містить `0x80420031`** (3 входження), `0x80420032` —
   ні. Головний sign-механізм sedo-client підтверджено ще раз, але статично.
5. ❌ У пакеті **немає** `PKCS11.EKeyAlmaz1C.dll`, `PKCS11.Virtual.EKeyAlmaz1C.dll`,
   `CSPExtension.dll`, `CSPIBase.dll`, `KM.dll`, `KM.FileSystem.dll`, `EUSignAgent.exe` —
   для деплою sedo-client цей batch **неповний**; змішувати його з S2 (2023) — той самий
   version drift, що описаний у v6 §3.2.

---

## 1. Вхідні дані

| Параметр | Значення |
|---|---|
| Архів | `Web_dll.7z`, 3 142 599 B, LZMA2, 19 файлів (10 730 350 B розпаковано) |
| SHA256 архіву | `78f91381c1d0acee1e07ac38f40b425b661e6587477395ae879266f4f65cd1b7` |
| Дати файлів в архіві | 2026-05-20 … 2026-07-31 |
| Виробник (VS_VERSIONINFO) | `АТ "ІІТ"` у 8 з 10 DLL; `NCHostCP.dll` і `SSLUtils.dll` без version-ресурсу |
| Бітність | усі 10 DLL — i386 (32-bit); 64-bit варіантів немає |
| Джерело на сайті IIT | найімовірніше `EUSignWebUpdate.exe` / `EUSignWebInstall.msi` (2026-08-24), не перевірено |

## 2. Метод

Без запуску бінарників, без Wine. `7z x` → `scripts/iit_inventory.py` (власний
stdlib PE-парсер: заголовок, експорти, імпорти + delay-load, `VS_FIXEDFILEINFO`
і UTF-16 `StringFileInfo`, ASCII/UTF-16 рядки, DWORD-константи) з cross-check
через `pefile 2024.8.26` (`--engine pefile`): усі поля збігаються. Команда:

```bash
python scripts/iit_inventory.py web_dll --label web_dll \
    --snapshot-label S3-2026-07-web_dll --source "Web_dll.7z sha256=78f9…" \
    --baseline docs/inventory/snapshot-a-v5.json \
    --baseline docs/inventory/snapshot-b-v6.json \
    --json docs/inventory/S3-2026-07-web_dll.json --exports-dir docs/inventory/exports
```

Обмеження методу: mechanism-и з прапорцями, поведінка токена і фактичний
LoadLibrary-порядок — тільки live на Windows (§9).

## 3. Склад пакета

```
CSPBase.dll          1 239 688  1.1.0.174   2026-06-29  крипто-примітиви DSTU 4145/7564/7624/8845 (133 експорти)
EUSignCP.dll         1 864 840  1.3.1.222   2026-07-31  головна бібліотека підпису (630 EU*-експортів)
EUSignRPC.dll          498 824  1.3.1.109   2026-07-31  JSON-RPC диспетчер (1 експорт: EUSignRPCGetInterface)
KM.EKeyAlmaz1C.dll     703 624  1.0.1.13    2026-07-31  прямий драйвер Алмаз-1К (winscard.dll)
KM.PKCS11.dll          300 544  1.0.1.39    2026-06-27  роутер сторонніх PKCS#11-модулів
NCHostCP.dll         1 531 528  —           2026-05-28  CA Gateway / JSON-server host (9 експортів)
NCMGryada301.dll       221 832  1.2.4.3     2026-07-19  МКМ Гряда-301 (96 експортів) — не для sedo-client
PDFSecurity.dll        822 920  1.3.1.12    2026-06-03  PDF-підпис (PDFGetInterface)
PKIFormats.dll       1 005 704  1.2.0.171   2026-07-01  ASN.1 / X.509 (3 експорти)
SSLUtils.dll         2 537 096  —           2026-05-12  TLS-хелпер (SSLGetContext, SSLGetKeyManager; crypt32)
DSTU4145Parameters.cap, DSTU7624SBox.cap, DSTU8845SBox.cap, ECDHParameters.cap,
ECDSAParameters.cap, GOST28147SBox.cap, GOST34311Parameters.cap, PRNGParameters.cap, RSAParameters.cap
```

PDB-шляхи (лишились у бінарниках): `d:\CryptoServiceProvider\Version11\…\CSPBase.pdb`,
`D:\PKIFormats\Version12UA\…\PKIFormats32.pdb`, `D:\Hardware\KeyMedias\EKeyAlmaz1C\…\KMEKeyAlmaz1C.pdb`,
`D:\Hardware\KeyMedias\PKCS11\…\KMPKCS11.pdb`,
`D:\CertificateAuthority\Version13\…\NetworkCommunications\Host\…\NCHostCP.pdb`.

## 4. Версії і SHA256 критичних файлів — S3 проти S1/S2

| Файл | S1 (v5, 2025) | S2 (v6, 2023–24) | **S3 (2026-07)** | SHA256 S3 |
|---|---|---|---|---|
| `CSPBase.dll` | 1.1.0.173 · 2025-06-18 | 1.1.0.172 · 2023-08-03 | **1.1.0.174 · 2026-06-29** | `05c6ceec…649e67` |
| `PKIFormats.dll` | 1.2.0.171 · 2025-08-15 | 1.2.0.163 · 2024-01-04 | **1.2.0.171 · 2026-07-01** ⚠️ інший sha | `e9011e94…2dcf66` |
| `EUSignCP.dll` | 1.3.1.209 · 2025-11-03 | = S1 | **1.3.1.222 · 2026-07-31** | `818dff83…a52814` |
| `EUSignRPC.dll` | — | — | **1.3.1.109 · 2026-07-31** | `3aa787b5…c75c38` |
| `KM.PKCS11.dll` | — | 1.0.1.37 · 2025-02-28 | **1.0.1.39 · 2026-06-27** | `90731561…f84fb3` |
| `KM.EKeyAlmaz1C.dll` | — | 1.0.1.9 (32-bit) | **1.0.1.13 · 2026-07-31** | `de7dc0c8…5324ee` |
| `NCHostCP.dll` | — | — | — · 2026-05-28 | `f1e539c1…8ad65f` |
| `CSPExtension.dll`, `CSPIBase.dll` | є | є | **немає** | |
| `PKCS11.EKeyAlmaz1C.dll`, `PKCS11.Virtual…`, `KM.dll`, `KM.FileSystem.dll` | — | є | **немає** | |

Повна матриця по всіх файлах — `docs/DLL-REGISTRY.md`.

```
# S3-2026-07-web_dll — sha256 критичних файлів
05c6ceec3477aaaf5b3926bb8af4e47a8416f2e8a20d5fe36dbce58ad0649e67  CSPBase.dll (1.1.0.174, 2026-06-29)
818dff837eb953041b866850a78a3eb7ac49d81e4d5cd797234c7aa175a52814  EUSignCP.dll (1.3.1.222, 2026-07-31)
3aa787b584927dfcc9b9fc6cc9baa6a43d74715761d2fb057737a591cec75c38  EUSignRPC.dll (1.3.1.109, 2026-07-31)
de7dc0c88c4d346955703939fc8eb147c4303f05a9978c9c8bed2b03605324ee  KM.EKeyAlmaz1C.dll (1.0.1.13, 2026-07-31)
90731561e124ee6c10eee6ca2cc8956a799d60b03c26ecf8b7349692e8f84fb3  KM.PKCS11.dll (1.0.1.39, 2026-06-27)
f1e539c1c17ebecec2cccb82e39fb88b8c73ad59f11f9f63afeaeafc598ad65f  NCHostCP.dll (2026-05-28)
e9011e94279d19c8f89ecbee287dfe28bee7ab760d52287078f96c4b702dcf66  PKIFormats.dll (1.2.0.171, 2026-07-01)
```

## 5. PKCS#11-шар: `KM.PKCS11.dll` 1.0.1.39

Власних PKCS#11-модулів (`C_GetFunctionList`) у пакеті немає. Роутер оновився
(1.0.1.37 → 1.0.1.39, −1 104 B) і в `.rdata` явно зашитий на **24 модулі**:

| Група | Модулі (рядки LoadLibrary) |
|---|---|
| IIT | `PKCS11.EKeyAlmaz1C.dll`, `PKCS11.Virtual.EKeyAlmaz1C.dll`, `PKCS11.EKeyCrystal1.dll`, **`PKCS11.Virtual.EKeyCrystal1.dll`** (новий), `PKCS11.CModGryada61.dll`, `PKCS11.NCMGryada301.dll` |
| Автор (Avest) / EFIT | `Av337CryptokiD.dll`, `avcryptokinxt.dll`, `efitkeynxt.dll` — те, що покриває наш `detect_token_vendor` |
| Інші | `plcpkcs11.dll` (NOKK), `jcpkcs11ua.dll` (JaCarta UA), `etpkcs11.dll` (SafeNet eToken), `gtop11dotnet.dll` (Gemalto IDPrime), `cihsm.dll`, `itoken-pkcs11.dll`, `bit4xpki.dll`, `aetpkss1.dll` (SafeSign), `asepkcs.dll` (Athena), `dkck201.dll` (Datakey), `pkcs11_x86.dll` |

RTTI-класи ті самі, що у v6 §2.2 (`EKeyAlmaz1CHardware`, `VirtualEKeyAlmaz1CHardware`,
`AvestKeyHardware`, `AladdinJaCartaASEKey`, …) плюс `VirtualEKeyCrystal1Hardware`.

**DWORD-константи mechanism ID у `KM.PKCS11.dll`** (єдиний модуль пакета, де вони є):

| ID | Входжень | Значення |
|---|---:|---|
| `0x80420031` | 3 | DSTU4145_SIGN_A — головний підпис sedo-client |
| `0x80420042` | 3 | DSTU4145_KEYPAIR_GEN |
| `0x80420044` | 3 | DSTU4145_ECDH_B |
| `0x80420016` | 2 | SYM_WRAP |
| `0x80420011`, `0x80420043` | 1 | SYM_ENC_A, DSTU4145_ECDH_A |
| `0x80420032`, `0x80420014`, `0x80420021`, … | 0 | роутер не використовує альтернативний sign `…32` і MAC `…14` |

Це узгоджується з `mechanism_ids.choose_sign_mechanism()` (спершу `0x80420031`).
Прапорці `hw/sign/verify` статично не видно — лише `pkcs11-tool --list-mechanisms`.

## 6. `EUSignCP.dll` 1.3.1.222 і `EUSignRPC.dll` 1.3.1.109

- **630 експортів** (S1: 619, +11). Точний список нових функцій встановити не можна:
  для 1.3.1.209 список експортів не зберігався. Відтепер зберігається
  (`docs/inventory/exports/EUSignCP.dll@1.3.1.222.txt`), наступний diff буде точним.
- Помітні сімейства (частини немає у `PROTOCOL-JSON-RPC.md`): `EUCOSE*` (COSE-підпис),
  `EUBASE45*`, `EUSServerClient*` (серверний підпис хешів, async), `EUSCClient*`
  (secure-connection шлюзи), `EUDevCtx*IDCard*` (ID-картка/е-паспорт, 42 функції),
  `EUASiC*` (15), `EUXAdES*` (9), `EUPDF*` (6), `EUCtx*` (123).
- **LoadLibrary-залежності EUSignCP** (з рядків, після придушення артефакту
  «зайвий перший символ»): `cspbase`, `cspextension`, `cspibase`, `pkiformats`, `km.dll`,
  `ldapclient`, `caconnectors`, `cagui`, `pdfsecurity`, `xmlsecurity`, `qrcode`, `rf`,
  `slmessages`. Тобто `PDFSecurity.dll` з пакета — саме та бібліотека, що її тягне
  EUSignCP (у v5 вона фігурувала як `ePDFSecurity.dll` — це був артефакт `strings`,
  як і `sCSPIBase.dll`). `slmessages.dll` і `km.dll` — обов'язкові, у v5 §7 не згадані.
- **OID**: 43 OID `1.2.804.2.1.1.1.*` в EUSignCP (усі 10 кривих ДСТУ 4145 `…3.1.1.2.0–9`),
  48 у PKIFormats, 15 у KM.*.
- **`EUSignRPC.dll`**: один експорт `EUSignRPCGetInterface`, 466 → 487 KB. У рядках
  кілька сотень імен методів (`ASiCSign`, `CtxEnvelopWithDynamicKey`,
  `ClientDynamicKeySessionCreate`, …), більшості нема в `PROTOCOL-JSON-RPC.md`.
  Акуратне витягування каталогу методів — окреме завдання (див. §9).
- **`NCHostCP.dll`** експортує `NCHostGetInterfaceJSONServer` / `…CAGateway` — це
  host JSON-сервера, за яким, імовірно, стоїть агент на 8081/8083; раніше вважався
  «CA Gateway, не потрібен».

## 7. `CSPBase.dll` 1.1.0.174 і `.cap`

133 експорти (як і раніше; `DSTU4145*`, `DSTU7564*`, `DSTU7624*`, `DSTU8845*`).
Рядки з іменами `.cap`:

| Модуль | Шукає |
|---|---|
| `CSPBase.dll` | **`DSTU4145CacheN2.cap`, `DSTU4145CacheP2.cap`** |
| `EUSignCP.dll` | `%s\DSTU4145Parameters.cap`, `%s\DSTU7624SBox.cap`, `%s\DSTU8845SBox.cap`, `%s\ECDHParameters.cap`, `%s\ECDSAParameters.cap`, `%s\GOST28147SBox.cap`, `%s\PRNGParameters.cap`, `%s\RSAParameters.cap` |

В архіві є всі 8 файлів зі списку EUSignCP плюс `GOST34311Parameters.cap`, але **немає
`DSTU4145CacheP2/N2.cap`** — великих кешів точок кривих (у S1/S2 вони звались `CachePB` /
`CacheNB`, 1.7 MB + 784 KB). Або web-компонент їх не постачає (обчислює кеш сам), або
власник не включив їх в архів. Для деплою треба перевірити на живому інсталяторі.

## 8. Наслідки для документів і коду

- `docs/MINIMUM-FILES-LIST.md`: перелік `.cap` — нові імена кешів `CacheP2`/`CacheN2`,
  додано `DSTU7624SBox.cap`, `DSTU8845SBox.cap`; у таблицю version drift додано колонку
  S3. **Оновлено цим addendum-ом.**
- `docs/PROTOCOL-JSON-RPC.md`: каталог методів застарів відносно EUSignRPC 1.3.1.109 —
  потрібне повторне витягування (не в цьому PR).
- `mechanism_ids.py`, `virtual_signer.py`, `pkcs11_signer.py`: **змін не потребують**
  (роутер підтверджує `0x80420031`, вендорна мапа `detect_token_vendor` покриває всі
  Avest/EFIT-модулі з роутера; нових IIT-mechanism ID не з'явилось).
- `docs/IIT-ANALYSIS-ADDENDUM-v5.md` §7 (LoadLibrary-карта EUSignCP): фактично
  `PDFSecurity.dll` / `XMLSecurity.dll` без префікса `e`; `slmessages.dll`, `km.dll`
  обов'язкові. Історичний текст не переписуємо — це виправлення тут.

## 9. Рекомендація і що перевірити live

1. **Не деплоїти S3 самостійно** — у ньому немає PKCS#11-модулів, `CSPExtension`,
   `CSPIBase`, `KM.dll`, `KM.FileSystem.dll`. Потрібен повний snapshot з одного
   інсталятора: `EUInstall.msi` (2026-08-27) + `EKAlmaz1CInstall.msi` (2026-09-09) з
   `https://iit.com.ua/download/productfiles/` → `scripts/iit_unpack.sh` →
   `iit_inventory.py --baseline docs/inventory/S3-2026-07-web_dll.json`. Якщо в них
   CSPBase 1.1.0.174 / PKIFormats sha `e9011e94…` / EUSignCP 1.3.1.222 — це один випуск,
   і його можна брати цілком (S4).
2. **Live на Windows** (`opensc-test-almaz.ps1`, `scripts/smoke_test.py`,
   `pkcs11-tool --module PKCS11.EKeyAlmaz1C.dll --list-mechanisms`): чи лишились
   `0x80420031/32` з `sign, verify, EC F_2M` після оновлення драйвера; чи потрібні
   `DSTU4145CacheP2/N2.cap` поруч із `CSPBase.dll` (симптом — `CKR_GENERAL_ERROR` /
   `Library not initialized`).
3. **PIN-ліміт**: жодних `--sign`-спроб із невідомими механізмами; лише `--list-mechanisms`.

## 10. Метадані

- **Дата:** 2026-09-12 · **Версія:** v7 · **Попередні:** v1–v6
- **Інструменти:** `scripts/iit_inventory.py` 1.0 (stdlib), cross-check `pefile 2024.8.26`,
  `7z` 16.02, `strings`/`objdump` (binutils)
- **Артефакти:** `docs/inventory/S3-2026-07-web_dll.json`, `docs/inventory/exports/*.txt`,
  `docs/DLL-REGISTRY.md`
- **Відтворення:** §2; бінарники — у приватному сховищі власника, у git їх немає.
