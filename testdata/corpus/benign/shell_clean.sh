#!/bin/bash
set -euo pipefail
echo "hello"
base64 -d <<< "aGVsbG8="
