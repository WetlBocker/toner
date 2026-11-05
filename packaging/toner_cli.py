"""TonerCli.exe: `Toner.exe cli ...` with a console of its own. Toner.exe is a window program, so it has no stdin to sign in
from; packaging\\build.ps1 builds this next to it, sharing its _internal folder."""
import sys

import app

sys.exit(app.run_cli(sys.argv[1:]))
