# docs/inventory — snapshot-и бінарників IIT

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Contact:  github.com/click0
Version:  0.30
License:  BSD 3-Clause "New" or "Revised" License
Year:     2025-2026
```

Тут лежать **лише похідні метадані** про DLL/EXE ІІТ («Користувач ЦСК-1»,
EUSignWeb, драйвер Алмаз-1К). Самі бінарники в git не потрапляють (`.gitignore`);
тримай їх у приватному сховищі каталогом на кожен batch, з `MANIFEST.sha256`
всередині — sha256 у JSON нижче дозволяє звірити будь-який файл.

## Файли

| Файл | Що це | Як з'явився |
|---|---|---|
| `snapshot-a-v5.json` | **S1-2025-v5** — 32-bit крипто-ланцюжок 2025 (CSPBase 1.1.0.173, PKIFormats 1.2.0.171, EUSignCP 1.3.1.209…) | ручна транскрипція `docs/IIT-ANALYSIS-ADDENDUM-v5.md` §1 |
| `snapshot-b-v6.json` | **S2-2023-v6** — 32-bit KM-ланцюжок (PKCS11.EKeyAlmaz1C 1.0.1.7, PKCS11.Virtual 1.0.1.10, KM.*, CSPBase 1.1.0.172, PKIFormats 1.2.0.163…) | ручна транскрипція `docs/IIT-ANALYSIS-ADDENDUM-v6.md` §1.1–1.3, §8.1 |
| `S3-2026-07-web_dll.json` | **S3-2026-07-web_dll** — архів `Web_dll.7z` від власника (10 DLL + 9 `.cap`, білди 2026-05…07): CSPBase 1.1.0.174, PKIFormats 1.2.0.171 (перезбірка без зміни версії), EUSignCP 1.3.1.222, EUSignRPC 1.3.1.109, KM.PKCS11 1.0.1.39, KM.EKeyAlmaz1C 1.0.1.13 | `scripts/iit_inventory.py` (містить `diffs` проти S1 і S2) |
| `exports/<DLL>@<версія>.txt` | відсортовані списки експортів критичних модулів — щоб наступного разу можна було точно сказати, які функції додались/зникли | `--exports-dir` |
| `../DLL-REGISTRY.md` | матриця «файл × snapshot»: версія · build · sha256 | `--registry` |

Мітка snapshot: `S<n>-<рік-місяць білдів>-<джерело>`. Наступний — `S4-…`.

## Як додати новий snapshot

```bash
scripts/iit_unpack.sh <installer.msi|.exe|.7z> downloads/iit/<дата>/<пакет>
python scripts/iit_inventory.py downloads/iit/<дата>/<пакет> --label <пакет> \
    --snapshot-label S4-<рік-місяць>-<джерело> --source "<файл> sha256=<…>" \
    --baseline docs/inventory/S3-2026-07-web_dll.json \
    --json docs/inventory/S4-<…>.json --md /tmp/S4.md --exports-dir docs/inventory/exports
python scripts/iit_inventory.py --registry docs/inventory/snapshot-*.json docs/inventory/S*.json \
    --md docs/DLL-REGISTRY.md
```

Markdown-звіт (`/tmp/S4.md`) — заготовка для нового `IIT-ANALYSIS-ADDENDUM-vN.md`:
секції «Критичні файли», «PKCS#11 / крипто-модулі», «Diff vs …», блок `sha256sum`.

## Що вміє і чого не вміє скрипт

- Вміє: усе статичне — версії, хеші, експорти, імпорти, LoadLibrary-рядки,
  `.cap`-посилання, OID, DWORD-константи mechanism ID (механізми в бінарнику лежать
  числами, а не текстом: рядкова перевірка `0x8042…` завжди порожня, сенс має
  лічильник DWORD).
- Не вміє: запускати DLL. Список механізмів з прапорцями і поведінка токена —
  тільки live на Windows (`opensc-test-almaz.ps1`, `pkcs11-tool --list-mechanisms`).
- Не імпортує модулі репо (працює як самостійний файл); синхронність 12 mechanism ID
  з `mechanism_ids.IIT_MECHANISMS` перевіряє тест.
