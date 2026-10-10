# Builds Toner: the program folder (PyInstaller), then Toner-Setup-<version>.exe (Inno Setup).
#   powershell -File packaging\build.ps1 [-Version 1.0.1]
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $Version) { $Version = (python -c "from core.version import VERSION; print(VERSION)").Trim() }   # core\version.py is the one place the version lives

python -m PyInstaller --noconfirm --clean --windowed --onedir --name Toner --icon "$root\assets\toner.ico" `
    --collect-all netmiko --collect-all ntc_templates --collect-all pysnmp `
    --collect-submodules keyring.backends --collect-submodules paramiko `
    --distpath build\dist --workpath build\work --specpath build app.py
if ($LASTEXITCODE) { throw "PyInstaller failed" }

$iscc = @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup)" }
& $iscc "/DAppVersion=$Version" packaging\toner.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }
Get-Item "build\installer\Toner-Setup-$Version.exe" | Select-Object Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } }
