#!/bin/bash
set -euo pipefail

# Absolute path to the directory this script is in
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set environment to use local shared libraries
export LD_LIBRARY_PATH="$BASE_DIR/bin/dependencies/lib"

# Paths
SNORT_BIN="$BASE_DIR/bin/snort3/build/src/snort"

# Validate paths
if [[ ! -x "$SNORT_BIN" ]]; then
    echo "❌ Snort binary not found or not executable: $SNORT_BIN"
    exit 1
fi

# Run Snort
exec "$SNORT_BIN" "$@"