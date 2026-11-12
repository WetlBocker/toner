#!/usr/bin/env bash
# Builds Toner for Linux: the program folder (PyInstaller), then Toner-<version>-x86_64.AppImage (appimagetool).
#   bash packaging/build_linux.sh [version]
# Needs: python with requirements.lock installed, and appimagetool on PATH (or APPIMAGETOOL=/path/to/appimagetool).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
version="${1:-$(python -c 'from core.version import VERSION; print(VERSION)')}"   # core/version.py is the one place the version lives

python -m PyInstaller --noconfirm --clean --windowed --onedir --name Toner \
    --collect-all netmiko --collect-all ntc_templates --collect-all pysnmp --hidden-import cli --collect-all pypsrp --collect-all spnego \
    --collect-submodules keyring.backends --collect-submodules paramiko --collect-all keeper_secrets_manager_core --collect-all sqlcipher3 --collect-all fido2 \
    --collect-submodules anthropic --collect-submodules openai --collect-submodules google.genai \
    --hidden-import PySide6.QtWebEngineWidgets --hidden-import PySide6.QtWebEngineCore --hidden-import PySide6.QtWebChannel \
    --add-data "$root/assets/echarts.min.js:assets" --add-data "$root/assets/chart.html:assets" \
    --add-data "$root/core/data:core/data" \
    --distpath build/dist --workpath build/work --specpath build app.py
# toner-helper: the helper service (packaging/toner_helper.py), without Qt. It goes into the AppDir under
# usr/lib/toner-helper/; turning on sign-in without approval copies it to /opt/toner-helper/ (toner-helper --install, as root).
python -m PyInstaller --noconfirm --clean --onedir --console --name toner-helper --exclude-module PySide6 --paths "$root" \
    --distpath build/dist --workpath build/work --specpath build packaging/toner_helper.py

# Qt pieces PyInstaller ships that Toner never uses (see build.ps1 for the list and why). QtQuick and QtQml stay for the
# charts' QtWebEngine.
qt="build/dist/Toner/_internal/PySide6"
for rel in Qt/lib/libQt6VirtualKeyboard.so.6 Qt/lib/libQt6Test.so.6 Qt/lib/libQt6Pdf.so.6 Qt/lib/libQt6PdfWidgets.so.6 Qt/lib/libQt6PdfQuick.so.6 \
           QtTest.abi3.so QtPdf.abi3.so QtPdfWidgets.abi3.so \
           Qt/plugins/virtualkeyboard Qt/plugins/platforminputcontexts/libqtvirtualkeyboardplugin.so Qt/translations; do
    rm -rf "$qt/$rel"
done
if [ -d "$root/agent/dist" ]; then                       # the toner-agent binaries (agent/build.sh): see build.ps1
    mkdir -p build/dist/Toner/agent
    cp "$root"/agent/dist/toner-agent-* build/dist/Toner/agent/
    echo "Agent binaries: $(ls build/dist/Toner/agent | tr '\n' ' ')"
else
    echo "No agent/dist: the AppImage carries no toner-agent binary (run agent/build.sh first to include it)."
fi
du -sh build/dist/Toner | sed 's/^/Program folder: /'

appdir="build/AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/lib" "$appdir/usr/share/icons/hicolor/256x256/apps" "$appdir/usr/share/applications"
cp -a build/dist/Toner "$appdir/usr/lib/toner"
cp -a build/dist/toner-helper "$appdir/usr/lib/toner-helper"
cp assets/toner.png "$appdir/toner.png"
cp assets/toner.png "$appdir/usr/share/icons/hicolor/256x256/apps/toner.png"
cat > "$appdir/toner.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Toner
Comment=Check, document and troubleshoot a multi-vendor network from one window.
Exec=Toner
Icon=toner
Categories=Network;System;Monitor;
Terminal=false
EOF
cp "$appdir/toner.desktop" "$appdir/usr/share/applications/toner.desktop"
cat > "$appdir/AppRun" <<'EOF'
#!/bin/sh
# The AppImage's entry point: Toner's program folder inside it. $APPIMAGE (set by the AppImage runtime) is the file itself,
# which Toner's updater replaces with a newer one.
here="$(dirname "$(readlink -f "$0")")"
exec "$here/usr/lib/toner/Toner" "$@"
EOF
chmod +x "$appdir/AppRun"

mkdir -p build/installer
tool="${APPIMAGETOOL:-appimagetool}"
ARCH=x86_64 "$tool" --no-appstream "$appdir" "build/installer/Toner-$version-x86_64.AppImage"
sha256sum "build/installer/Toner-$version-x86_64.AppImage"
ls -la "build/installer/Toner-$version-x86_64.AppImage"
