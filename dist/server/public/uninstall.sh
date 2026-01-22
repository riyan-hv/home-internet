#!/bin/bash
# Speed Monitor - Uninstaller
# Usage: curl -fsSL https://home-internet.onrender.com/uninstall.sh | bash
# Or:    curl -fsSL https://raw.githubusercontent.com/riyan-hv/home-internet/main/dist/uninstall.sh | bash

SCRIPT_DIR="$HOME/.local/share/nkspeedtest"
CONFIG_DIR="$HOME/.config/nkspeedtest"
BIN_DIR="$HOME/.local/bin"
PLIST_NAME="com.speedmonitor.plist"
MENUBAR_PLIST_NAME="com.speedmonitor.menubar.plist"

echo "=== Speed Monitor Uninstaller ==="
echo ""
echo "This will remove Speed Monitor completely from your system."
echo ""

# Stop and remove launchd services
echo "Stopping services..."
launchctl unload "$HOME/Library/LaunchAgents/$PLIST_NAME" 2>/dev/null || true
launchctl unload "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$PLIST_NAME"
rm -f "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME"
echo "✓ Services stopped and removed"

# Kill the menu bar app
echo "Closing SpeedMonitor app..."
killall SpeedMonitor 2>/dev/null || true
echo "✓ App closed"

# Remove the app
echo "Removing application..."
rm -rf /Applications/SpeedMonitor.app
echo "✓ SpeedMonitor.app removed"

# Remove scripts and data
echo "Removing data and scripts..."
rm -f "$BIN_DIR/speed_monitor.sh"
rm -f "$BIN_DIR/wifi_info"
rm -rf "$SCRIPT_DIR"
rm -rf "$CONFIG_DIR"
echo "✓ Data and scripts removed"

echo ""
echo "=== Uninstall Complete ==="
echo ""
echo "Speed Monitor has been completely removed from your system."
echo ""
echo "To reinstall, run:"
echo "  curl -fsSL https://raw.githubusercontent.com/hyperkishore/home-internet/main/dist/install.sh | bash"
echo ""
