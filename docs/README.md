# sedo-client Documentation

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.29
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

## Документи

### Огляд і архітектура

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — загальний огляд архітектури,
  data flow, розподіл відповідальностей Linux ↔ Windows
- **[MINIMUM-FILES-LIST.md](MINIMUM-FILES-LIST.md)** — точний перелік файлів
  для деплою (HW: 4 DLL + 9 cap ≈ 5 MB; Virtual: ще 5 DLL + Key-6.dat)
- **[LINUX-WINE-DEPLOYMENT.md](LINUX-WINE-DEPLOYMENT.md)** — запуск без
  Windows: 32-bit Wine prefix, virtual token (Key-6.dat), playbook
  `sedo_daily_linux.yml`

### Реверс-інжиніринг

- **[IIT-ANALYSIS.md](IIT-ANALYSIS.md)** — повний звіт аналізу 36+ DLL ІІТ
  (EUSignAgent, EUSignRPC, EUSignCP, CSPBase, PKCS11 модулі)
- **[IIT-ANALYSIS-ADDENDUM.md](IIT-ANALYSIS-ADDENDUM.md)** — HW PKCS11
  module (v1.0.1.7), Crystal-1 package, PKIFormats.dll
- **[IIT-ANALYSIS-ADDENDUM-v2.md](IIT-ANALYSIS-ADDENDUM-v2.md)** — Virtual
  token (PKCS11.Virtual.EKeyAlmaz1C.dll), Key-6.dat, CSPIBase.dll
- **[IIT-ANALYSIS-ADDENDUM-v3.md](IIT-ANALYSIS-ADDENDUM-v3.md)** — Crystal-1
  kernel driver (EKeyCr1N.sys), why it is not for SEDO
- **[IIT-ANALYSIS-ADDENDUM-v4.md](IIT-ANALYSIS-ADDENDUM-v4.md)** — third-party
  PKCS#11 modules (Avest, NOKK, Gryada-301 HSM)
- **[IIT-ANALYSIS-ADDENDUM-v5.md](IIT-ANALYSIS-ADDENDUM-v5.md)** — 32-bit
  crypto chain (CSPBase, CSPIBase, PKIFormats, EUSignCP)
- **[IIT-ANALYSIS-ADDENDUM-v6.md](IIT-ANALYSIS-ADDENDUM-v6.md)** — KM
  architecture, version pinning, production-ready assessment
- **[IIT-ANALYSIS-ADDENDUM-v7.md](IIT-ANALYSIS-ADDENDUM-v7.md)** — web-компонент
  2026-07 (EUSignCP 1.3.1.222, CSPBase 1.1.0.174, KM.PKCS11 1.0.1.39), нові `.cap`,
  snapshot S3; перший addendum, згенерований `scripts/iit_inventory.py`
- **[inventory/](inventory/README.md)** — snapshot-и бінарників IIT у JSON
  (S1/S2/S3), списки експортів, як додати наступний;
  **[DLL-REGISTRY.md](DLL-REGISTRY.md)** — матриця версій/sha256 по snapshot-ах
- **[MECHANISM-IDS.md](MECHANISM-IDS.md)** — 12 PKCS#11 mechanism IDs з
  прапорцями, DSTU 4145 криві OIDs, таблиця співставлення з avcryptokinxt
- **[REVERSE-METHODOLOGY.md](REVERSE-METHODOLOGY.md)** — методологія
  аналізу, інструменти, reproduce steps, етичні міркування

### Протоколи

- **[PROTOCOL-JSON-RPC.md](PROTOCOL-JSON-RPC.md)** — повний опис IIT
  EUSignAgent JSON-RPC протоколу: endpoints, формат, послідовність
  авторизації, каталог ~500 методів, 110+ JSON полів сертифіката

## Швидкий індекс

**Хочу зрозуміти як це працює** → [ARCHITECTURE.md](ARCHITECTURE.md)

**Хочу дізнатись про реверс DLL** → [IIT-ANALYSIS.md](IIT-ANALYSIS.md) + ADDENDUM v1-v7

**Вийшла нова версія DLL від IIT** → [inventory/README.md](inventory/README.md) (скрипт інвентаризації + diff)

**Треба точний mechanism ID для PKCS#11** → [MECHANISM-IDS.md](MECHANISM-IDS.md)

**Цікавий JSON-RPC протокол агента** → [PROTOCOL-JSON-RPC.md](PROTOCOL-JSON-RPC.md)

**Хочу повторити наш аналіз** → [REVERSE-METHODOLOGY.md](REVERSE-METHODOLOGY.md)

**Що ставити на Windows worker** → [../SETUP-WINDOWS.md](../SETUP-WINDOWS.md)

**OpenSC команди і troubleshooting** → [../OPENSC-QUICKSTART.md](../OPENSC-QUICKSTART.md)

**Fiddler capture для СЕДО auth** → [../FIDDLER-CAPTURE-GUIDE.md](../FIDDLER-CAPTURE-GUIDE.md)
