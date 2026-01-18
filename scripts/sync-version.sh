#!/bin/bash
# sync-version.sh - Propagate VERSION to all files
#
# Usage: ./scripts/sync-version.sh [new-version]
#   If new-version is provided, updates VERSION file first
#   Then syncs to all other files

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION_FILE="$REPO_ROOT/VERSION"

# If version argument provided, update VERSION file first
if [ -n "$1" ]; then
    echo "$1" > "$VERSION_FILE"
    echo "Updated VERSION file to $1"
fi

# Read the canonical version
VERSION=$(cat "$VERSION_FILE" | tr -d '[:space:]')

if [ -z "$VERSION" ]; then
    echo "Error: VERSION file is empty"
    exit 1
fi

echo "Syncing version $VERSION to all files..."

# 1. speed_monitor.sh
sed -i '' "s/^APP_VERSION=\".*\"/APP_VERSION=\"$VERSION\"/" "$REPO_ROOT/speed_monitor.sh"
echo "  ✓ speed_monitor.sh"

# 2. dist/server/index.js
sed -i '' "s/^const APP_VERSION = '.*';/const APP_VERSION = '$VERSION';/" "$REPO_ROOT/dist/server/index.js"
echo "  ✓ dist/server/index.js"

# 3. WiFiHelper/SpeedMonitorMenuBar.swift
sed -i '' "s/static let appVersion = \".*\"/static let appVersion = \"$VERSION\"/" "$REPO_ROOT/WiFiHelper/SpeedMonitorMenuBar.swift"
echo "  ✓ WiFiHelper/SpeedMonitorMenuBar.swift"

# 4. CLAUDE.md header
sed -i '' "s/^# Speed Monitor v.* -/# Speed Monitor v$VERSION -/" "$REPO_ROOT/CLAUDE.md"
echo "  ✓ CLAUDE.md"

echo ""
echo "Version $VERSION synced to all files."
echo ""
echo "Verify with:"
echo "  grep -h 'APP_VERSION\|appVersion' speed_monitor.sh dist/server/index.js WiFiHelper/SpeedMonitorMenuBar.swift"
