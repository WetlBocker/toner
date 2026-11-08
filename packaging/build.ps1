# Builds Toner: the program folder (PyInstaller), then Toner-Setup-<version>.exe (Inno Setup).
#   powershell -File packaging\build.ps1 [-Version 1.0.1]
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $Version) { $Version = (python -c "from core.version import VERSION; print(VERSION)").Trim() }   # core\version.py is the one place the version lives

$common = @("--noconfirm", "--clean", "--onedir", "--icon", "$root\assets\toner.ico", "--paths", "$root",
    "--collect-all", "netmiko", "--collect-all", "ntc_templates", "--collect-all", "pysnmp", "--hidden-import", "cli", "--hidden-import", "PySide6.QtAxContainer",
    "--collect-all", "pypsrp", "--collect-all", "spnego", "--collect-all", "sspilib",
    "--collect-submodules", "keyring.backends", "--collect-submodules", "paramiko", "--collect-all", "keeper_secrets_manager_core", "--collect-all", "sqlcipher3",
    "--collect-submodules", "anthropic", "--collect-submodules", "openai", "--collect-submodules", "google.genai",
    "--hidden-import", "PySide6.QtWebEngineWidgets", "--hidden-import", "PySide6.QtWebEngineCore", "--hidden-import", "PySide6.QtWebChannel",
    "--add-data", "$root\assets\echarts.min.js;assets", "--add-data", "$root\assets\chart.html;assets",
    "--add-data", "$root\core\data;core\data",
    "--distpath", "build\dist", "--workpath", "build\work", "--specpath", "build")
python -m PyInstaller @common --windowed --name Toner app.py
if ($LASTEXITCODE) { throw "PyInstaller failed" }
# TonerCli.exe: the same program as a console one, so its commands can ask for a password at the terminal (Toner.exe, a window
# program, has no stdin). Built from the same modules, it runs from Toner's own _internal folder, so only the exe is kept.
python -m PyInstaller @common --console --name TonerCli packaging\toner_cli.py
if ($LASTEXITCODE) { throw "PyInstaller failed (TonerCli)" }
Copy-Item build\dist\TonerCli\TonerCli.exe build\dist\Toner\ -Force
Remove-Item -Recurse -Force build\dist\TonerCli
# TonerHelper.exe: the helper service (packaging\toner_helper.py), without Qt, in a folder of its own beside Toner. Turning on
# sign-in without approval copies that folder to %ProgramFiles%\Toner Helper\ (TonerHelper.exe --install, elevated).
python -m PyInstaller --noconfirm --clean --onedir --console --name TonerHelper --exclude-module PySide6 --icon "$root\assets\toner.ico" `
    --paths "$root" --distpath build\dist --workpath build\work --specpath build packaging\toner_helper.py
if ($LASTEXITCODE) { throw "PyInstaller failed (TonerHelper)" }
Copy-Item build\dist\TonerHelper build\dist\Toner\TonerHelper -Recurse -Force
Remove-Item -Recurse -Force build\dist\TonerHelper

# Qt pieces PyInstaller ships that Toner never uses: the virtual keyboard (and its input-context plugin), QtTest, the PDF
# viewer (PDF reports are written with QPdfWriter, which is in QtGui) and Qt's own translation files (Toner is English only).
# QtQuick and QtQml stay: the charts' QtWebEngine needs them. (The charts add QtWebEngine itself, about 200 MB.)
$qt = "build\dist\Toner\_internal\PySide6"
$prune = @("Qt6VirtualKeyboard.dll", "Qt6Test.dll", "Qt6Pdf.dll", "Qt6PdfWidgets.dll", "Qt6PdfQuick.dll",
           "QtTest.pyd", "QtPdf.pyd", "QtPdfWidgets.pyd",
           "plugins\virtualkeyboard", "plugins\platforminputcontexts\qtvirtualkeyboardplugin.dll", "translations")
foreach ($rel in $prune) { $path = Join-Path $qt $rel; if (Test-Path $path) { Remove-Item -Recurse -Force $path } }
# The toner-agent binaries (agent/build.sh, or the CI artifact) ride along in agent\, so Toner can hand them to computers
# and update the agents it already has. Without them the package Toner makes is the PowerShell one.
if (Test-Path "$root\agent\dist") {
    New-Item -ItemType Directory -Force -Path "build\dist\Toner\agent" | Out-Null
    Copy-Item "$root\agent\dist\toner-agent-*" "build\dist\Toner\agent\" -Force
    Write-Host ("Agent binaries: " + ((Get-ChildItem "build\dist\Toner\agent").Name -join ", "))
} else { Write-Host "No agent\dist: the installer carries no toner-agent binary (run agent\build.sh first to include it)." }
$mb = [math]::Round((Get-ChildItem build\dist\Toner -Recurse -File | Measure-Object Length -Sum).Sum / 1MB)
Write-Host "Program folder: $mb MB"

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
