# Linux deployment via Wine (Virtual token)

```
Project:  sedo-client
Author:   Vladyslav V. Prodan
Version:  0.26
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
cp KM_FileSystem.dll               "$DLLDIR/"

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

## 5. Test

```bash
export WINEPREFIX=$HOME/.sedo-wine

# Verify the virtual module loads
python3 -c "
import PyKCS11
lib = PyKCS11.PyKCS11Lib()
lib.load('$HOME/.sedo-wine/drive_c/sedo-libs/PKCS11.Virtual.EKeyAlmaz1C.dll')
print('OK:', lib.getInfo().libraryDescription.strip())
"
```

Expected:
```
OK: E.key_Almaz-1C_Library
```

## 6. Run sedo-client

```bash
python3 sedo_client.py \
    --backend virtual \
    --module "$HOME/.sedo-wine/drive_c/sedo-libs/PKCS11.Virtual.EKeyAlmaz1C.dll" \
    --key-file "$HOME/.sedo-wine/drive_c/sedo-libs/Key-6.dat" \
    --pin "$PIN" \
    --fetch \
    --output ./downloads
```

## 7. Ansible (Linux worker)

No WinRM required. Run directly on the controller or a Linux worker:

```yaml
- name: SEDO daily check (Linux/Wine virtual token)
  hosts: sedo_workers_linux
  gather_facts: false
  vars_files:
    - ../inventory/vault.yml
  vars:
    wine_prefix: "/opt/sedo-wine"
    sedo_libs: "{{ wine_prefix }}/drive_c/sedo-libs"
  tasks:
    - name: Run sedo-client with virtual backend
      ansible.builtin.command:
        cmd: >
          python3 /opt/sedo-client/sedo_client.py
          --backend virtual
          --module "{{ sedo_libs }}/PKCS11.Virtual.EKeyAlmaz1C.dll"
          --key-file "{{ sedo_libs }}/Key-6.dat"
          --pin "{{ virtual_pin }}"
          --fetch
          --since "{{ lookup('pipe', 'date +%Y-%m-%d') }}"
          --output "/opt/sedo-reports/{{ lookup('pipe', 'date +%Y-%m-%d') }}"
      environment:
        WINEPREFIX: "{{ wine_prefix }}"
      no_log: true
```

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
