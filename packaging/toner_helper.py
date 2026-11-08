"""TonerHelper.exe (Windows) / toner-helper (Linux): Toner's helper service. packaging/build.ps1 and build_linux.sh build it
beside Toner, without Qt.
  --service    run it: as the service manager's TonerHelper service on Windows, in the foreground under systemd on Linux
  --install    as an administrator/root: put the service in place from this program's own folder (the built one only)
  --uninstall  as an administrator/root: stop and remove the service, its program folder and its store
  --version    print Toner's version"""
import os
import sys
from pathlib import Path

if os.name == "nt":
    from core.helper import windows as platform
else:
    from core.helper import linux as platform
from core.helper.protocol import COPY_FAILED, CopyFailed
from core.version import VERSION


def main(argv):
    if argv == ["--version"]:
        print(VERSION)
    elif argv == ["--service"]:
        platform.run_service()
    elif argv in (["--install"], ["--uninstall"]):
        if argv == ["--install"] and not getattr(sys, "frozen", False):
            print("toner-helper: --install runs from the built program only", file=sys.stderr)
            return 2
        try:
            platform.install(Path(sys.executable).resolve().parent) if argv == ["--install"] else platform.uninstall()
        except (OSError, ValueError) as e:
            print(f"toner-helper: {e}", file=sys.stderr)
            return COPY_FAILED if isinstance(e, CopyFailed) else 1
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
