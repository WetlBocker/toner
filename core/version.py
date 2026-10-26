"""The one place the version lives. packaging\\build.ps1 reads it, so the installer, the About page and the update
check always agree. Raise it before building a release. The Windows agent has the same version (core/agents.py), so a
new release also updates the agents on the next report."""
APP_NAME = "Toner"
VERSION = "1.9.2"
REPO = "WetlBocker/toner"                       # GitHub owner/name that releases are published to
URL = f"https://github.com/{REPO}"
LICENSE = "GNU General Public License v3.0"
TAGLINE = "Check, document and troubleshoot a multi-vendor network from one window."
