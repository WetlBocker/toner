#!/usr/bin/env bash
# Builds toner-agent for every platform Toner serves, into agent/dist, stamped with Toner's version (core/version.py).
#   bash agent/build.sh            every platform
#   bash agent/build.sh linux-amd64   one
# The installer builds (packaging/build.ps1, build_linux.sh) copy agent/dist into the program folder's agent/ so Toner
# can hand the binary to computers and update the agents it already has.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
version="$(python3 -c "import re;print(re.search(r'VERSION = \"([^\"]+)\"', open('$root/core/version.py').read()).group(1))" 2>/dev/null || grep -oP 'VERSION = "\K[^"]+' "$root/core/version.py")"
cd "$here"
mkdir -p dist
platforms="${1:-windows-amd64 windows-arm64 linux-amd64 linux-arm64 darwin-arm64}"
go mod tidy >/dev/null 2>&1 || true          # fills go.sum on a fresh checkout
for p in $platforms; do
  os="${p%-*}"; arch="${p#*-}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  echo "building toner-agent $version for $os/$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X github.com/WetlBocker/toner/agent/internal/agent.Version=$version" \
    -o "dist/toner-agent-$p$ext" ./cmd/toner-agent
done
ls -la dist
