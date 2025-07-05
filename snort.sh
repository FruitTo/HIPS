#!/bin/bash
set -euo pipefail

# Absolute path to the directory this script is in
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

# Set environment to use local shared libraries
export LD_LIBRARY_PATH="$BASE_DIR/bin/dependencies/lib"

# Paths
SNORT_BIN="$BASE_DIR/bin/snort3/build/src/snort"
SNORT_CONF="$BASE_DIR/config/snort.lua"
SNORT_RULES="$BASE_DIR/rules/snort3-community.rules"
SNORT_RULE_MAP="$BASE_DIR/rules/sid-msg.map"

# Validate paths
if [[ ! -x "$SNORT_BIN" ]]; then
    echo "❌ Snort binary not found or not executable: $SNORT_BIN"
    exit 1
fi

if [[ ! -f "$SNORT_CONF" ]]; then
    echo "❌ Snort config file not found: $SNORT_CONF"
    exit 1
fi

if [[ ! -f "$SNORT_RULES" ]]; then
    echo "❌ Rule file not found: $SNORT_RULES"
    exit 1
fi

# Optional: export SID-MSG map (used in some alert outputs)
export SNORT_SID_MSG_MAP="$SNORT_RULE_MAP"

# Run Snort
exec "$SNORT_BIN" -c "$SNORT_CONF" "$@"
