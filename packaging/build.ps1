# Builds Toner: the program folder (PyInstaller), then Toner-Setup-<version>.exe (Inno Setup).
#   powershell -File packaging\build.ps1 [-Version 1.0.1]
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $Version) { $Version = (python -c "from core.version import VERSION; print(VERSION)").Trim() }   # core\version.py is the one place the version lives

python -m PyInstaller --noconfirm --clean --windowed --onedir --name Toner --icon "$root\assets\toner.ico" `
    --collect-all netmiko --collect-all ntc_templates --collect-all pysnmp --hidden-import cli --hidden-import PySide6.QtAxContainer --collect-all pypsrp --collect-all spnego --collect-all sspilib `
    --collect-submodules keyring.backends --collect-submodules paramiko --collect-all keeper_secrets_manager_core `
    --distpath build\dist --workpath build\work --specpath build app.py
if ($LASTEXITCODE) { throw "PyInstaller failed" }

$iscc = @("$env:ProgramFiles\Inno Setup 6\ISCC.exe", "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
          "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (winget install JRSoftware.InnoSetup)" }
& $iscc "/DAppVersion=$Version" packaging\toner.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }
# Code signing: set SIGN_PFX (path to a .pfx code-signing certificate) and SIGN_PASSWORD to sign the installer, so Windows
# shows a publisher instead of an "unknown publisher" SmartScreen warning. Without them the installer is built unsigned.
if ($env:SIGN_PFX) {
    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK) but SIGN_PFX is set" }
    & $signtool.FullName sign /f $env:SIGN_PFX /p $env:SIGN_PASSWORD /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "build\installer\Toner-Setup-$Version.exe"
    if ($LASTEXITCODE) { throw "Signing failed" }
    Write-Host "Installer signed."
}
Get-Item "build\installer\Toner-Setup-$Version.exe" | Select-Object Name, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 1) } }
