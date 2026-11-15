"""Takes the GPL-only pieces out of a built program folder, so what ships is under permissive, MPL or LGPL terms only.
    python packaging/strip_gpl.py build/dist/Toner

Qt publishes most of its modules under the LGPL, and these under the GPL alone: Charts, Data Visualization, Graphs, HTTP Server,
Lottie, Network Authorization, Quick 3D, Quick Timeline, Virtual Keyboard and the Wayland Compositor. Toner loads none of them:
PyInstaller's PySide6 hook collects every QML plugin once QtQml is in (the charts' QtWebEngine needs it), and the libraries those
plugins link to come along. On Linux, Python's readline module brings GNU readline (GPL) with it; nothing in Toner reads a line
that way, and the standard library does without it.
"""
import os
import re
import shutil
import sys

QT = "Charts|DataVisualization|Graphs|HttpServer|Lottie|NetworkAuth|Quick3D|QuickTimeline|VirtualKeyboard|Wayland(Egl)?Compositor"
FILES = re.compile(rf"^((lib)?Qt6({QT})\w*\.(dll|so)(\.\d+)*|(lib)?(qmldbg_quick3d|qtvirtualkeyboard)\w*\.(dll|so)"   # their plugins
                   rf"|libreadline\.so(\.\d+)*|readline\.cpython-[\w-]+\.so)$")
FOLDERS = ("/qml/QtCharts", "/qml/QtDataVisualization", "/qml/QtGraphs", "/qml/QtQuick3D", "/qml/QtQuick/Timeline",
           "/qml/QtQuick/VirtualKeyboard", "/qml/QtWayland/Compositor", "/plugins/virtualkeyboard")


def gpl_only(root):
    """The GPL-only files and folders under root (a folder is listed whole, not file by file)."""
    found = []
    for here, dirs, files in os.walk(root):
        for d in list(dirs):
            if os.path.join(here, d).replace(os.sep, "/").endswith(FOLDERS):
                found.append(os.path.join(here, d))
                dirs.remove(d)
        found += [os.path.join(here, f) for f in files if FILES.match(f)]
    return found


if __name__ == "__main__":
    root = sys.argv[1]
    if not os.path.isdir(root):
        sys.exit(f"{root} is not a folder")
    found = gpl_only(root)
    for path in found:
        shutil.rmtree(path) if os.path.isdir(path) and not os.path.islink(path) else os.remove(path)
    print(f"GPL-only pieces taken out of {root}: {len(found)}")
