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
    --collect-submodules keyring.backends --collect-submodules paramiko --collect-all keeper_secrets_manager_core --collect-all pyqtgraph \
    --distpath build/dist --workpath build/work --specpath build app.py

appdir="build/AppDir"
rm -rf "$appdir"
mkdir -p "$appdir/usr/lib" "$appdir/usr/share/icons/hicolor/256x256/apps" "$appdir/usr/share/applications"
cp -a build/dist/Toner "$appdir/usr/lib/toner"
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
