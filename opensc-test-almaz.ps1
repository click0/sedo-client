# opensc-test-almaz.ps1
#
# Повна валідація Алмаз-1К + PKCS11.EKeyAlmaz1C.dll через OpenSC.
# Автоматично підбирає 32-bit OpenSC (IIT DLL — 32-bit!)
# Знаходить .cap файли у всіх IIT директоріях і додає до PATH.
#
# Project:  sedo-client
# Author:   Vladyslav V. Prodan
# Contact:  github.com/click0
# Phone:    +38(099)6053340
# Version:  0.25
# License:  BSD 3-Clause "New" or "Revised" License
# Year:     2025-2026
#
# Usage:
#   .\opensc-test-almaz.ps1                          # автопошук
#   .\opensc-test-almaz.ps1 -Dll "..."              # явний шлях DLL
#   .\opensc-test-almaz.ps1 -Pin 1234                # + login і перелік
#   .\opensc-test-almaz.ps1 -Pin 1234 -TestSign      # + тест підпису

param(
    [string]$Dll = "",
    [string]$OpenSCPath = "",   # автовибір 32-bit якщо не задано
    [string]$Pin,
    [switch]$TestSign
)

[Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding(1251)
$OutputEncoding = [System.Text.Encoding]::GetEncoding(1251)

$ErrorActionPreference = "Continue"

function Section($name) {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  $name" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param($Name, $Status, $Detail = "")
    $color = if ($Status) { "Green" } else { "Red" }
    $mark  = if ($Status) { "[OK]  " } else { "[FAIL]" }
    Write-Host -ForegroundColor $color "$mark $Name" -NoNewline
    if ($Detail) { Write-Host "  -- $Detail" } else { Write-Host "" }
}

# Читає PE header і повертає 32 або 64 (бітність)
function Get-PEBitness {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        $machine  = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
        switch ($machine) {
            0x014c  { return 32 }  # IMAGE_FILE_MACHINE_I386
            0x8664  { return 64 }  # IMAGE_FILE_MACHINE_AMD64
            default { return 0  }
        }
    } catch { return 0 }
}


# === 0. Пошук PKCS11 DLL =====================================
Section "0. Пошук PKCS11 DLL"

$pkcs11Dll = $null

if ($Dll -and (Test-Path $Dll)) {
    $pkcs11Dll = (Resolve-Path $Dll).Path
    Write-Host "[OK]  Переданий шлях: $pkcs11Dll" -ForegroundColor Green
}

if (-not $pkcs11Dll) {
    $knownLocations = @(
        "C:\Program Files (x86)\Institute of Informational Technologies\EKeys\Almaz1C",
        "C:\Program Files\Institute of Informational Technologies\EKeys\Almaz1C",
        "C:\Program Files (x86)\Institute of Informational Technologies\EKeys",
        "C:\Program Files\Institute of Informational Technologies\EKeys",
        "C:\Program Files (x86)\Institute of Informational Technologies",
        "C:\Program Files\Institute of Informational Technologies",
        "C:\Institute of Informational Technologies"
    )
    $namePatterns = @("PKCS11.EKeyAlmaz1C.dll", "PKCS11_EKeyAlmaz1C.dll")

    foreach ($root in $knownLocations) {
        if (-not (Test-Path $root)) { continue }
        foreach ($pat in $namePatterns) {
            $found = Get-ChildItem -Path $root -Recurse -Filter $pat `
                     -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($found) {
                $pkcs11Dll = $found.FullName
                Write-Host "[OK]  Знайдено: $pkcs11Dll" -ForegroundColor Green
                break
            }
        }
        if ($pkcs11Dll) { break }
    }
}

if (-not $pkcs11Dll) {
    Write-Host "[FAIL] PKCS11 DLL не знайдено" -ForegroundColor Red
    Write-Host "Знайдіть вручну:" -ForegroundColor Yellow
    Write-Host '  Get-ChildItem C:\ -Recurse -Filter "PKCS11*Almaz*.dll" -EA SilentlyContinue' -ForegroundColor Cyan
    exit 1
}

$dllDir = Split-Path $pkcs11Dll -Parent
$dllBitness = Get-PEBitness -Path $pkcs11Dll
Write-Host "      Директорія: $dllDir"
Write-Host "      Бітність DLL: ${dllBitness}-bit" -ForegroundColor Cyan


# === 0.5. Пошук залежних DLL + .cap файлів у всіх IIT директоріях ==
Section "0.5. Залежні DLL та .cap файли"

# CSPBase / CSPExtension поруч з PKCS11 DLL?
$cspBase = Test-Path (Join-Path $dllDir "CSPBase.dll")
$cspExt  = Test-Path (Join-Path $dllDir "CSPExtension.dll")
Write-Status "CSPBase.dll поруч" $cspBase
Write-Status "CSPExtension.dll поруч" $cspExt

# Глобальний пошук .cap по всіх IIT директоріях
Write-Host ""
Write-Host "Шукаю .cap файли в усіх IIT директоріях..."
$iitRoots = @(
    "C:\Program Files (x86)\Institute of Informational Technologies",
    "C:\Program Files\Institute of Informational Technologies",
    "C:\Institute of Informational Technologies",
    "C:\ProgramData\Institute of Informational Technologies"
)
$capDirs = [System.Collections.Generic.HashSet[string]]::new()
foreach ($r in $iitRoots) {
    if (Test-Path $r) {
        $caps = Get-ChildItem -Path $r -Recurse -Filter "*.cap" -EA SilentlyContinue
        foreach ($c in $caps) {
            [void]$capDirs.Add($c.DirectoryName)
        }
    }
}

if ($capDirs.Count -eq 0) {
    Write-Host "[FAIL] .cap файли не знайдено ніде в IIT директоріях" -ForegroundColor Red
    Write-Host "        PKCS11 DLL без них не буде працювати" -ForegroundColor Yellow
} else {
    Write-Host "[OK]  .cap файли знайдено у директоріях:" -ForegroundColor Green
    foreach ($d in $capDirs) {
        $capCount = (Get-ChildItem -Path $d -Filter "*.cap" -EA SilentlyContinue).Count
        Write-Host "        $d   ($capCount файлів)"
    }

    # Додаємо всі cap-директорії та директорію DLL у PATH для pkcs11-tool
    $pathAdditions = @($dllDir) + @($capDirs)
    $env:PATH = ($pathAdditions -join ";") + ";" + $env:PATH
    Write-Host ""
    Write-Host "Додав до PATH: $($pathAdditions.Count) директорій" -ForegroundColor Gray
}


# === 0.7. Пошук pkcs11-tool.exe потрібної бітності ==============
Section "0.7. Пошук pkcs11-tool.exe (потрібна бітність: ${dllBitness}-bit)"

# Стандартні шляхи OpenSC
$openSCCandidates = @()
if ($OpenSCPath) {
    $openSCCandidates += Join-Path $OpenSCPath "pkcs11-tool.exe"
} else {
    $openSCCandidates = @(
        "C:\Program Files (x86)\OpenSC Project\OpenSC\tools\pkcs11-tool.exe",  # 32-bit
        "C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe"         # 64-bit
    )
}

$pkcs11Tool = $null
$toolBitness = 0

foreach ($cand in $openSCCandidates) {
    if (-not (Test-Path $cand)) { continue }
    $b = Get-PEBitness -Path $cand
    Write-Host "  Знайдено: $cand (${b}-bit)"
    if ($b -eq $dllBitness) {
        $pkcs11Tool = $cand
        $toolBitness = $b
        Write-Host "[OK]  Підходить за бітністю: $cand" -ForegroundColor Green
        break
    }
}

if (-not $pkcs11Tool) {
    Write-Host ""
    Write-Host "[FAIL] Не знайдено pkcs11-tool.exe з бітністю ${dllBitness}-bit" -ForegroundColor Red
    Write-Host ""
    Write-Host "ПРИЧИНА ПОМИЛКИ 'LoadLibrary/GetProcAddress failed':" -ForegroundColor Yellow
    Write-Host "  64-bit процес не може завантажити 32-bit DLL (і навпаки)." -ForegroundColor Yellow
    Write-Host "  IIT DLL — ${dllBitness}-bit, значить потрібен ${dllBitness}-bit pkcs11-tool." -ForegroundColor Yellow
    Write-Host ""
    if ($dllBitness -eq 32) {
        Write-Host "РІШЕННЯ: встановіть 32-bit OpenSC у додаток до 64-bit:" -ForegroundColor Cyan
        Write-Host "  1. Скачайте OpenSC-*-win32.msi (НЕ win64) з" -ForegroundColor Cyan
        Write-Host "     https://github.com/OpenSC/OpenSC/releases" -ForegroundColor Cyan
        Write-Host "  2. Встановіть у ""C:\Program Files (x86)\OpenSC Project\""" -ForegroundColor Cyan
        Write-Host "  3. Запустіть цей скрипт знов" -ForegroundColor Cyan
    }
    exit 1
}

# Перевірка opensc-tool тієї самої бітності
$openscTool = Join-Path (Split-Path $pkcs11Tool -Parent) "opensc-tool.exe"


# === 1. PC/SC layer ==========================================
Section "1. PC/SC layer -- opensc-tool.exe"

if (Test-Path $openscTool) {
    Write-Host "Readers:"
    & $openscTool --list-readers
    Write-Host ""
    Write-Host "ATR:"
    & $openscTool --atr
} else {
    Write-Host "[SKIP] opensc-tool.exe не знайдено в $(Split-Path $pkcs11Tool -Parent)"
}


# === 2. PKCS#11 info без PIN =================================
Section "2. PKCS#11 info (без PIN)"

Write-Host ">>> Module info:"
& $pkcs11Tool --module $pkcs11Dll --show-info

Write-Host ""
Write-Host ">>> Слоти та токени:"
& $pkcs11Tool --module $pkcs11Dll --list-slots

Write-Host ""
Write-Host ">>> Token info:"
& $pkcs11Tool --module $pkcs11Dll --list-token-slots

Write-Host ""
Write-Host ">>> *** Механізми (шукаємо CKM_DSTU4145):"
& $pkcs11Tool --module $pkcs11Dll --list-mechanisms


# === 3. PKCS#11 з PIN ========================================
if ($Pin) {
    Section "3. PKCS#11 з PIN"

    Write-Host "! PIN використовується. Алмаз знищить ключ після 15 невдач!" -ForegroundColor Yellow
    Write-Host ""

    Write-Host ">>> Всі об'єкти:"
    & $pkcs11Tool --module $pkcs11Dll --login --pin $Pin --list-objects


    Section "4. Експорт сертифіката"

    $certOut = "almaz-cert.der"
    & $pkcs11Tool --module $pkcs11Dll --login --pin $Pin `
        --read-object --type cert --id 01 --output-file $certOut

    if (Test-Path $certOut) {
        $size = (Get-Item $certOut).Length
        Write-Host "[OK]  $certOut ($size bytes)" -ForegroundColor Green
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certOut)
            Write-Host "      Subject: $($cert.Subject)"
            Write-Host "      Issuer:  $($cert.Issuer)"
            Write-Host "      Valid:   $($cert.NotBefore) -- $($cert.NotAfter)"
        } catch {
            Write-Host "      (парсинг не вдався, але файл збережено)"
        }
    }


    if ($TestSign) {
        Section "6. Тест підпису"

        Write-Host "! Буде виконано ОДИН підпис" -ForegroundColor Yellow
        Write-Host "  Продовжити? (Y/N)" -ForegroundColor Yellow -NoNewline
        $confirm = Read-Host

        if ($confirm -eq "Y" -or $confirm -eq "y") {
            $testData = "test $(Get-Date -Format o)"
            $testData | Out-File "test-data.txt" -Encoding ASCII -NoNewline

            $mechanisms = @(
                @{Id = "0x80420031"; Name = "IIT DSTU4145 primary (EC F_2M)"},
                @{Id = "0x80420032"; Name = "IIT DSTU4145 alt"},
                @{Id = "0x00000352"; Name = "Standard CKM_DSTU4145"}
            )

            foreach ($m in $mechanisms) {
                Write-Host ""
                Write-Host ">>> mechanism $($m.Id) ($($m.Name)):"
                $sigFile = "sig-$($m.Id).bin"
                & $pkcs11Tool --module $pkcs11Dll --login --pin $Pin `
                    --sign --mechanism $m.Id `
                    --input-file test-data.txt --output-file $sigFile 2>&1

                if (Test-Path $sigFile) {
                    $size = (Get-Item $sigFile).Length
                    Write-Host "[OK]  $sigFile ($size bytes) -- ПРАЦЮЄ!" -ForegroundColor Green
                    break
                }
            }
        }
    }
}


Section "Підсумок"

Write-Host "DLL:         $pkcs11Dll"
Write-Host "Бітність:    ${dllBitness}-bit"
Write-Host "pkcs11-tool: $pkcs11Tool"
Write-Host ""
Write-Host "[DONE]" -ForegroundColor Green
