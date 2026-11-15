# Run directly (python tests/test_strip_gpl.py) or all together (python tests/run_all.py).
# packaging/strip_gpl.py takes the GPL-only pieces out of a built program folder: the Qt modules Qt publishes under the GPL alone
# (PyInstaller collects them with the QML plugins; Toner loads none of them) and GNU readline. Checked on a made-up folder laid
# out as the Windows and the Linux builds are, and that both build scripts run it.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
import os, subprocess, sys, tempfile
ok = bad = 0
def check(name, cond, extra=""):
    global ok, bad
    if cond: ok += 1; print("  ok  ", name)
    else: bad += 1; print("  FAIL", name, extra)
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "packaging"))
import strip_gpl

GPL = [  # Windows
       "_internal/PySide6/Qt6Charts.dll", "_internal/PySide6/Qt6ChartsQml.dll", "_internal/PySide6/Qt6DataVisualization.dll",
       "_internal/PySide6/Qt6DataVisualizationQml.dll", "_internal/PySide6/Qt6Graphs.dll", "_internal/PySide6/Qt6GraphsWidgets.dll",
       "_internal/PySide6/Qt6Quick3D.dll", "_internal/PySide6/Qt6Quick3DRuntimeRender.dll", "_internal/PySide6/Qt6Quick3DSpatialAudio.dll",
       "_internal/PySide6/Qt6QuickTimeline.dll", "_internal/PySide6/Qt6QuickTimelineBlendTrees.dll", "_internal/PySide6/Qt6VirtualKeyboard.dll",
       "_internal/PySide6/Qt6VirtualKeyboardQml.dll", "_internal/PySide6/Qt6VirtualKeyboardSettings.dll", "_internal/PySide6/Qt6Lottie.dll",
       "_internal/PySide6/Qt6HttpServer.dll", "_internal/PySide6/Qt6NetworkAuth.dll",
       "_internal/PySide6/qml/QtCharts/qtchartsqml2plugin.dll", "_internal/PySide6/qml/QtCharts/qmldir",
       "_internal/PySide6/qml/QtDataVisualization/qmldir", "_internal/PySide6/qml/QtGraphs/qmldir",
       "_internal/PySide6/qml/QtQuick3D/Helpers/qmldir", "_internal/PySide6/qml/QtQuick3D/qmldir",
       "_internal/PySide6/qml/QtQuick/Timeline/qmldir", "_internal/PySide6/qml/QtQuick/VirtualKeyboard/Styles/qmldir",
       "_internal/PySide6/plugins/qmltooling/qmldbg_quick3dprofiler.dll",       # Quick 3D's own, and it links to Quick 3D
       "_internal/PySide6/plugins/platforminputcontexts/qtvirtualkeyboardplugin.dll", "_internal/PySide6/plugins/virtualkeyboard/qtvirtualkeyboard_hangul.dll",
       # Linux
       "_internal/PySide6/Qt/lib/libQt6Charts.so.6", "_internal/PySide6/Qt/lib/libQt6Quick3DUtils.so.6",
       "_internal/PySide6/Qt/lib/libQt6WaylandCompositor.so.6", "_internal/PySide6/Qt/lib/libQt6WaylandCompositorXdgShell.so.6",
       "_internal/PySide6/Qt/lib/libQt6WaylandEglCompositorHwIntegration.so.6", "_internal/libQt6Graphs.so.6",
       "_internal/PySide6/Qt/qml/QtWayland/Compositor/qmldir", "_internal/PySide6/Qt/qml/QtQuick3D/qmldir",
       "_internal/PySide6/Qt/plugins/qmltooling/libqmldbg_quick3dprofiler.so",
       "_internal/PySide6/Qt/plugins/platforminputcontexts/libqtvirtualkeyboardplugin.so",
       "_internal/libreadline.so.8", "_internal/python3.14/lib-dynload/readline.cpython-314-x86_64-linux-gnu.so"]
KEPT = ["Toner.exe", "_internal/PySide6/Qt6Core.dll", "_internal/PySide6/Qt6Quick.dll", "_internal/PySide6/Qt6QuickControls2.dll",
        "_internal/PySide6/Qt6QuickWidgets.dll", "_internal/PySide6/Qt6QuickShapes.dll", "_internal/PySide6/Qt6QuickEffects.dll",
        "_internal/PySide6/Qt6Qml.dll", "_internal/PySide6/Qt6WebEngineCore.dll", "_internal/PySide6/Qt6WebEngineQuick.dll",
        "_internal/PySide6/Qt6Network.dll", "_internal/PySide6/Qt63DQuickScene3D.dll", "_internal/PySide6/Qt6SpatialAudio.dll",
        "_internal/PySide6/Qt6ShaderTools.dll", "_internal/PySide6/Qt6Multimedia.dll", "_internal/PySide6/QtWebEngineProcess.exe",
        "_internal/PySide6/qml/QtQuick/Controls/qmldir", "_internal/PySide6/qml/QtQuick/Scene3D/qmldir",
        "_internal/PySide6/qml/QtWebEngine/qmldir", "_internal/PySide6/plugins/qmltooling/qmldbg_profiler.dll", "_internal/PySide6/plugins/platforminputcontexts/qtibusplatforminputcontextplugin.dll", "_internal/PySide6/qml/Qt3D/Core/qmldir", "_internal/PySide6/qml/QtQuick/qmldir",
        "_internal/PySide6/Qt/lib/libQt6Core.so.6", "_internal/PySide6/Qt/lib/libQt6WaylandClient.so.6",
        "_internal/PySide6/Qt/lib/libQt6WlShellIntegration.so.6", "_internal/PySide6/Qt/qml/QtWayland/Client/qmldir",
        "_internal/libtinfo.so.6", "_internal/libstdc++.so.6", "_internal/core/charts_timeline.txt", "_internal/assets/echarts.min.js"]

folder = tempfile.mkdtemp(prefix="toner_strip_")
for rel in GPL + KEPT:
    path = os.path.join(folder, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "w").close()
def there(rel): return os.path.exists(os.path.join(folder, *rel.split("/")))

print("== what is GPL only")
found = strip_gpl.gpl_only(folder)
under = lambda rel: any(os.path.join(folder, *rel.split("/")).startswith(p) for p in found)
check("every GPL-only Qt library, QML folder and readline is found", all(under(r) for r in GPL), [r for r in GPL if not under(r)])
check("nothing else is", not any(under(r) for r in KEPT), [r for r in KEPT if under(r)])
check("a QML folder is taken whole, not file by file", os.path.join(folder, "_internal", "PySide6", "qml", "QtQuick3D") in found)

print("== run on a program folder")
r = subprocess.run([sys.executable, os.path.join(root, "packaging", "strip_gpl.py"), folder], capture_output=True, text=True)
check("it finishes and says how much it took out", r.returncode == 0 and "GPL-only" in r.stdout, (r.returncode, r.stdout, r.stderr))
check("the GPL-only pieces are gone", not any(there(r_) for r_ in GPL), [r_ for r_ in GPL if there(r_)])
check("everything else is still there", all(there(r_) for r_ in KEPT), [r_ for r_ in KEPT if not there(r_)])
check("a second run finds nothing left", strip_gpl.gpl_only(folder) == [])
r = subprocess.run([sys.executable, os.path.join(root, "packaging", "strip_gpl.py"), os.path.join(folder, "not-there")], capture_output=True, text=True)
check("a folder that is not there fails the build rather than passing quietly", r.returncode != 0)

print("== the builds")
def read(name): return open(os.path.join(root, "packaging", name), encoding="utf-8").read()
ps1, sh = read("build.ps1"), read("build_linux.sh")
check("the Windows build strips the program folder before the installer is made",
      "packaging\\strip_gpl.py build\\dist\\Toner" in ps1 and ps1.index("strip_gpl.py") < ps1.index("toner.iss"))
check("the Linux build strips it, and the helper's folder (readline), before the AppImage is made",
      "packaging/strip_gpl.py build/dist/Toner\n" in sh and "packaging/strip_gpl.py build/dist/toner-helper\n" in sh
      and sh.rindex("strip_gpl.py") < sh.index('cp -a build/dist/Toner "$appdir'))

print(f"\n{ok} passed, {bad} failed"); sys.exit(1 if bad else 0)
