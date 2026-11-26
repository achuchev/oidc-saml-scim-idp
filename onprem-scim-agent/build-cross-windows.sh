#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "Cross-compiling standalone Windows x64 binary (scim-agent.exe)..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o scim-agent.exe .
ls -lh scim-agent.exe
echo "Done! Copy scim-agent.exe and config.json to your Windows machine (no dependencies needed on Windows)."
