#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT/build"
python3 -m compileall -q "$ROOT/src"
(
  cd "$ROOT/src"
  zip -X -q -j "$ROOT/build/lambda.zip" lambda_handler.py
)
echo "Created $ROOT/build/lambda.zip"
