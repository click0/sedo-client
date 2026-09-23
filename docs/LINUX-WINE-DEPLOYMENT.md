# Linux deployment via Wine (Virtual token)

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.30
License:  BSD 3-Clause
Year:     2025-2026
```

Run sedo-client on Linux **without a Windows worker** by using
`PKCS11.Virtual.EKeyAlmaz1C.dll` inside a 32-bit Wine prefix.
No USB token or Smart Card service required — only a `Key-6.dat` file.

---

## Prerequisites

- Debian/Ubuntu (or any distro with Wine 9+)
- Python 3.11+
- PyKCS11 (`pip install PyKCS11`)
- Wine 32-bit
- IIT DLLs (see below)
- A `Key-6.dat` private key file (exported from a real token)

## 1. Install Wine 32-bit

```bash
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install wine32

wine --version
# wine-9.x or newer
```

## 2. Create a 32-bit prefix

```bash
export WINEPREFIX=$HOME/.sedo-wine
WINEARCH=win32 wineboot --init
```

## 3. Deploy IIT DLLs

Copy these files into the prefix (all 32-bit, from the same IIT installation batch):

```bash
DLLDIR="$WINEPREFIX/drive_c/sedo-libs"
mkdir -p "$DLLDIR"

# Required DLLs (from MINIMUM-FILES-LIST.md, Scenario B)
cp PKCS11.Virtual.EKeyAlmaz1C.dll "$DLLDIR/"
cp CSPBase.dll                     "$DLLDIR/"
cp CSPExtension.dll                "$DLLDIR/"
cp CSPIBase.dll                    "$DLLDIR/"
cp PKIFormats.dll                  "$DLLDIR/"
cp EUSignCP.dll                    "$DLLDIR/"
cp KM.dll                          "$DLLDIR/"
cp KM.FileSystem.dll               "$DLLDIR/"   # з крапкою: KM.dll шукає саме це ім'я

# Curve parameters (.cap files)
cp *.cap "$DLLDIR/"

# Private key
cp Key-6.dat "$DLLDIR/"
```

### Version pinning

Use DLLs from a **single snapshot** of an IIT installation.
Do NOT mix v5-batch (2025) DLLs with v6-batch (2023) DLLs.
See `docs/MINIMUM-FILES-LIST.md` for details.

## 4. Wine registry keys

The Virtual module and EUSignCP.dll read configuration from the Windows
registry. Set up the minimum keys inside the Wine prefix:

```bash
wine regedit /S - <<'REGEDIT'
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User\Libraries\Sign]
"Path"="C:\\sedo-libs"

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User\Libraries\Sign Agent\Common]
"HTTPPort"=dword:00001f91
"HTTPSPort"=dword:00001f93

[HKEY_LOCAL_MACHINE\SOFTWARE\Institute of Informational Technologies\Certificate Authority-1.3\End User\Libraries\Sign Agent\TrustedSites]
"https://sedo.mod.gov.ua"=""
REGEDIT
```

## 5. Which Python runs the client — read this first

⚠️ **A native `python3` cannot use this backend.**
`PKCS11.Virtual.EKeyAlmaz1C.dll` is a 32-bit **Windows PE**. Under native
CPython, PyKCS11 calls `dlopen()`, which cannot load a PE image, and
`WINEPREFIX` has no effect on a native process — it only configures Wine.
Setting it and calling `python3` does nothing for the loader.

The only configuration that can work is **all three parts Windows**: a Windows
Python inside the Wine prefix, the Windows build of PyKCS11, and the IIT DLL.
Same conclusion as `IIT-ANALYSIS-ADDENDUM-v6.md` §6.3.

```bash
# Install Python for Windows into the prefix (once)
export WINEPREFIX=$HOME/.sedo-wine
wine python-3.12.x-win32.exe /quiet InstallAllUsers=1 PrependPath=1
wine C:\\Python312\\python.exe -m pip install PyKCS11 requests
```

**Status: not yet verified** on a live prefix with a real `Key-6.dat`. The
steps below are the architecture, not a tested recipe. Until someone runs it,
prefer `--backend opensc` on a Windows worker.

## 6. Test and run

```bash
export WINEPREFIX=$HOME/.sedo-wine

# Verify the virtual module loads — note: Windows Python, not python3
wine C:\\Python312\\python.exe -c "import PyKCS11; \
lib = PyKCS11.PyKCS11Lib(); \
lib.load(r'C:\\sedo-libs\\PKCS11.Virtual.EKeyAlmaz1C.dll'); \
print('OK:', lib.getInfo().libraryDescription.strip())"
```

Expected:
```
OK: E.key_Almaz-1C_Library
```

```bash
# Run the client. Paths are Windows-form because a Windows Python reads them;
# Wine maps the Linux root to Z:, so a repo at /opt/sedo-client is
# Z:\opt\sedo-client. PIN via SEDO_PIN, never on the command line.
SEDO_PIN="$PIN" wine C:\\Python312\\python.exe 'Z:\opt\sedo-client\sedo_client.py' \
    --backend virtual \
    --module 'C:\sedo-libs\PKCS11.Virtual.EKeyAlmaz1C.dll' \
    --key-file 'C:\sedo-libs\Key-6.dat' \
    --fetch \
    --output 'Z:\opt\sedo-client\downloads'
```

## 7. Ansible (Linux worker)

No WinRM required. The full playbook is
`ansible/playbooks/sedo_daily_linux.yml` (inventory group
`sedo_workers_linux`, PINs in `vault.yml` under `virtual_pins`).

The interpreter is **not** defaulted: per §5 a native `python3` cannot load the
module, so the playbook refuses to run until you name a Windows Python inside
the prefix. Set it in the inventory:

```yaml
    sedo_workers_linux:
      vars:
        sedo_client_python: 'wine C:\Python312\python.exe'
```

Without it the first task fails with an explanatory message instead of dying
inside PyKCS11 several tasks later. The core task then looks like this — note
the Windows-form paths and the PIN going through `SEDO_PIN`, never `--pin`:

```yaml
    - name: Run sedo-client with virtual backend
      ansible.builtin.command:
        cmd: >-
          {{ client_python }} "{{ client_script_win }}"
          --backend virtual
          --module "{{ virtual_module_win }}"
          --key-file "{{ key_file_win }}"
          --fetch
          --since "{{ date_today }}"
          --output "{{ output_dir_win }}"
      environment:
        WINEPREFIX: "{{ wine_prefix }}"
        SEDO_PIN: "{{ virtual_pins[inventory_hostname] }}"
      no_log: true
```

The playbook derives the `*_win` variables from the Unix ones: everything under
the prefix becomes `C:\…`, everything outside it `Z:\…`.

## Mutex warning

The HW and Virtual PKCS#11 modules share the same mutex names
(`Global\EKAlmaz1CMutex`, `Global\EKAlmaz1CMemory`).
Do NOT run both simultaneously in the same Wine prefix.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `DLL was not found` | CSPBase.dll or PKIFormats.dll missing | Copy all DLLs to the same directory |
| `No virtual token slot` | Missing registry keys or Key-6.dat | Check registry and file paths |
| `wine: Bad EXE format` | 64-bit Wine prefix | Recreate with `WINEARCH=win32` |
| `No private keys` | Key-6.dat format mismatch | Ensure Key-6.dat was exported from IIT, not raw PKCS#8 |
