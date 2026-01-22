#!/bin/bash
# Speed Monitor v3.1.41 - One-line installer for employees
# Install:   bash <(curl -fsSL https://home-internet.onrender.com/install.sh)
# Uninstall: bash <(curl -fsSL https://home-internet.onrender.com/uninstall.sh)

set -e

SERVER_URL="https://home-internet.onrender.com"
DOWNLOAD_URL="$SERVER_URL"  # Files hosted on Render server
SCRIPT_DIR="$HOME/.local/share/nkspeedtest"
CONFIG_DIR="$HOME/.config/nkspeedtest"
BIN_DIR="$HOME/.local/bin"
PLIST_NAME="com.speedmonitor.plist"
MENUBAR_PLIST_NAME="com.speedmonitor.menubar.plist"
LISTENER_PLIST_NAME="com.speedmonitor.listener.plist"

echo "=== Speed Monitor v3.1.41 Installer ==="
echo ""

# =============================================================================
# STEP 1: FULL CLEANUP FIRST - Remove ALL old installations before anything else
# =============================================================================
echo "Step 1: Removing all old Speed Monitor installations..."

# Kill any running SpeedMonitor processes
echo "  Stopping running processes..."
pkill -x "SpeedMonitor" 2>/dev/null || true
pkill -f "speed_monitor.sh" 2>/dev/null || true
sleep 1

# Unload and REMOVE all launchd services
echo "  Removing launchd services..."
launchctl unload "$HOME/Library/LaunchAgents/$PLIST_NAME" 2>/dev/null || true
launchctl unload "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME" 2>/dev/null || true
launchctl unload "$HOME/Library/LaunchAgents/$LISTENER_PLIST_NAME" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$PLIST_NAME" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME" 2>/dev/null || true
rm -f "$HOME/Library/LaunchAgents/$LISTENER_PLIST_NAME" 2>/dev/null || true

# Remove scripts from ~/.local/bin (curl install location)
echo "  Removing scripts from ~/.local/bin..."
rm -f "$BIN_DIR/speed_monitor.sh" 2>/dev/null || true
rm -f "$BIN_DIR/command_listener.sh" 2>/dev/null || true
rm -f "$BIN_DIR/wifi_info" 2>/dev/null || true

# Remove scripts from /usr/local/speedmonitor/bin (PKG install location)
if [[ -d "/usr/local/speedmonitor/bin" ]]; then
    echo "  Removing scripts from /usr/local/speedmonitor/bin..."
    rm -f /usr/local/speedmonitor/bin/speed_monitor.sh 2>/dev/null || true
    rm -f /usr/local/speedmonitor/bin/wifi_info 2>/dev/null || true
fi

# Remove SpeedMonitor.app (may need elevated permissions)
echo "  Removing SpeedMonitor.app..."
rm -rf /Applications/SpeedMonitor.app 2>/dev/null || sudo rm -rf /Applications/SpeedMonitor.app 2>/dev/null || true

# Remove old data files (but preserve email and device_id)
echo "  Cleaning data directory (preserving identity)..."
rm -f "$SCRIPT_DIR/launchd_stdout.log" 2>/dev/null || true
rm -f "$SCRIPT_DIR/launchd_stderr.log" 2>/dev/null || true
rm -f "$SCRIPT_DIR/menubar_stdout.log" 2>/dev/null || true
rm -f "$SCRIPT_DIR/menubar_stderr.log" 2>/dev/null || true
rm -f "$SCRIPT_DIR/wifi_info.swift" 2>/dev/null || true

echo "✓ Old installations removed"
echo ""

# =============================================================================
# STEP 2: Create directories
# =============================================================================
mkdir -p "$SCRIPT_DIR" "$BIN_DIR" "$CONFIG_DIR"

# =============================================================================
# STEP 3: Collect user email (or use existing)
# =============================================================================
USER_EMAIL=""

# Check if email already exists from previous installation
if [[ -f "$CONFIG_DIR/user_email" ]]; then
    EXISTING_EMAIL=$(cat "$CONFIG_DIR/user_email" 2>/dev/null | xargs)
    if [[ -n "$EXISTING_EMAIL" ]] && [[ "$EXISTING_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo "Found existing email: $EXISTING_EMAIL"
        echo "Press Enter to keep this email, or type a new one:"

        if [[ -t 0 ]]; then
            read -p "Email [$EXISTING_EMAIL]: " NEW_EMAIL
        else
            read -p "Email [$EXISTING_EMAIL]: " NEW_EMAIL < /dev/tty 2>/dev/null || NEW_EMAIL=""
        fi

        NEW_EMAIL=$(echo "$NEW_EMAIL" | xargs)
        if [[ -z "$NEW_EMAIL" ]]; then
            USER_EMAIL="$EXISTING_EMAIL"
            echo "✓ Using existing email: $USER_EMAIL"
        else
            USER_EMAIL="$NEW_EMAIL"
        fi
    fi
fi

# If no valid email yet, prompt for one
if [[ -z "$USER_EMAIL" ]]; then
    echo "Please enter your Hyperverge email address:"
    echo "(This is required to identify your device in the dashboard)"
    echo ""

    MAX_ATTEMPTS=3
    ATTEMPT=0

    while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
        ATTEMPT=$((ATTEMPT + 1))

        if [[ -t 0 ]]; then
            read -p "Email: " USER_EMAIL
        else
            read -p "Email: " USER_EMAIL < /dev/tty 2>/dev/null || {
                echo "Error: Cannot read input. Please run the installer differently:"
                echo "  curl -fsSL https://home-internet.onrender.com/install.sh -o /tmp/install.sh && bash /tmp/install.sh"
                exit 1
            }
        fi

        USER_EMAIL=$(echo "$USER_EMAIL" | xargs)

        if [[ -z "$USER_EMAIL" ]]; then
            echo "❌ Email cannot be empty. Please try again. (Attempt $ATTEMPT/$MAX_ATTEMPTS)"
            continue
        fi

        if [[ ! "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo "❌ Invalid email format. Please enter a valid email. (Attempt $ATTEMPT/$MAX_ATTEMPTS)"
            continue
        fi

        break
    done
fi

# Final validation
if [[ -z "$USER_EMAIL" ]] || [[ ! "$USER_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo ""
    echo "❌ Error: A valid email address is required to proceed."
    echo "Please run the installer again and provide your email."
    exit 1
fi

echo "✓ Email: $USER_EMAIL"
echo "$USER_EMAIL" > "$CONFIG_DIR/user_email"
echo ""

# =============================================================================
# STEP 4: Install dependencies
# =============================================================================
echo "Step 2: Checking dependencies..."

# Check for Homebrew
if ! command -v brew &> /dev/null; then
    echo "  Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" < /dev/null

    # Add Homebrew to PATH for this session
    if [[ -f "/opt/homebrew/bin/brew" ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f "/usr/local/bin/brew" ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi

# Install speedtest-cli
if ! command -v speedtest-cli &> /dev/null; then
    echo "  Installing speedtest-cli..."
    brew install speedtest-cli < /dev/null
fi

echo "✓ Dependencies ready"
echo ""

# =============================================================================
# STEP 5: Download and install fresh components
# =============================================================================
echo "Step 3: Installing Speed Monitor v3.1.41..."

# Download speed_monitor.sh
echo "  Downloading speed_monitor.sh..."
curl -fsSL "$DOWNLOAD_URL/speed_monitor.sh" -o "$BIN_DIR/speed_monitor.sh"
chmod +x "$BIN_DIR/speed_monitor.sh"

# Verify download
if [[ ! -f "$BIN_DIR/speed_monitor.sh" ]]; then
    echo "❌ Failed to download speed_monitor.sh"
    exit 1
fi

# Download command_listener.sh (active command polling daemon)
echo "  Downloading command_listener.sh..."
curl -fsSL "$DOWNLOAD_URL/command_listener.sh" -o "$BIN_DIR/command_listener.sh"
chmod +x "$BIN_DIR/command_listener.sh"

# Also install to PKG location if directory exists (for backwards compatibility)
if [[ -d "/usr/local/speedmonitor/bin" ]]; then
    echo "  Installing to PKG location..."
    cp "$BIN_DIR/speed_monitor.sh" /usr/local/speedmonitor/bin/speed_monitor.sh 2>/dev/null || true
    chmod +x /usr/local/speedmonitor/bin/speed_monitor.sh 2>/dev/null || true
fi

# Download and install SpeedMonitor.app
echo "  Downloading SpeedMonitor.app..."
curl -fsSL "$DOWNLOAD_URL/SpeedMonitor.app.zip" -o /tmp/SpeedMonitor.app.zip

if [[ -f /tmp/SpeedMonitor.app.zip ]]; then
    unzip -o /tmp/SpeedMonitor.app.zip -d /tmp/ > /dev/null 2>&1
    if [[ -d /tmp/SpeedMonitor.app ]]; then
        # Remove existing app first (handles permission issues)
        if [[ -d /Applications/SpeedMonitor.app ]]; then
            rm -rf /Applications/SpeedMonitor.app 2>/dev/null || sudo rm -rf /Applications/SpeedMonitor.app 2>/dev/null || true
        fi

        # Copy new app
        cp -R /tmp/SpeedMonitor.app /Applications/ 2>/dev/null || sudo cp -R /tmp/SpeedMonitor.app /Applications/

        # Remove quarantine flag (Gatekeeper)
        xattr -cr /Applications/SpeedMonitor.app 2>/dev/null || sudo xattr -cr /Applications/SpeedMonitor.app 2>/dev/null || true

        # Ad-hoc code sign
        codesign --force --deep --sign - /Applications/SpeedMonitor.app 2>/dev/null || true

        echo "  ✓ SpeedMonitor.app installed"
    else
        echo "  ⚠ Failed to unzip SpeedMonitor.app"
    fi
    rm -f /tmp/SpeedMonitor.app.zip
    rm -rf /tmp/SpeedMonitor.app
else
    echo "  ⚠ Failed to download SpeedMonitor.app"
fi

# Optional: wifi_info Swift helper (backup)
if command -v swiftc &> /dev/null; then
    echo "  Setting up WiFi helper..."
    if [[ -f "/opt/homebrew/bin/wifi_info" ]]; then
        ln -sf "/opt/homebrew/bin/wifi_info" "$BIN_DIR/wifi_info"
    else
        curl -fsSL "$DOWNLOAD_URL/wifi_info.swift" -o "$SCRIPT_DIR/wifi_info.swift" 2>/dev/null || true
        swiftc -O -o "$BIN_DIR/wifi_info" "$SCRIPT_DIR/wifi_info.swift" -framework CoreWLAN -framework Foundation 2>/dev/null || true
    fi
fi

echo "✓ Components installed"
echo ""

# =============================================================================
# STEP 6: Create and load launchd services
# =============================================================================
echo "Step 4: Setting up background services..."

# Create launchd plist for speed monitor
cat > "$HOME/Library/LaunchAgents/$PLIST_NAME" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.speedmonitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DIR/speed_monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$SCRIPT_DIR/launchd_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$SCRIPT_DIR/launchd_stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>SPEED_MONITOR_SERVER</key>
        <string>$SERVER_URL</string>
    </dict>
</dict>
</plist>
EOF

launchctl load "$HOME/Library/LaunchAgents/$PLIST_NAME"
echo "  ✓ Speed monitor service started"

# Create launchd plist for menu bar app
if [[ -d "/Applications/SpeedMonitor.app" ]]; then
    cat > "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.speedmonitor.menubar</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/SpeedMonitor.app/Contents/MacOS/SpeedMonitor</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$SCRIPT_DIR/menubar_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$SCRIPT_DIR/menubar_stderr.log</string>
</dict>
</plist>
EOF

    launchctl load "$HOME/Library/LaunchAgents/$MENUBAR_PLIST_NAME"

    # Launch the app
    if open /Applications/SpeedMonitor.app 2>/dev/null; then
        echo "  ✓ Menu bar app launched"
    else
        nohup /Applications/SpeedMonitor.app/Contents/MacOS/SpeedMonitor &>/dev/null &
        sleep 1
        if pgrep -x "SpeedMonitor" > /dev/null; then
            echo "  ✓ Menu bar app launched"
        else
            echo "  ⚠ Please open SpeedMonitor.app manually from Applications"
        fi
    fi
fi

# Create launchd plist for command listener (polls every 30 seconds for remote commands)
cat > "$HOME/Library/LaunchAgents/$LISTENER_PLIST_NAME" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.speedmonitor.listener</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DIR/command_listener.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$SCRIPT_DIR/listener_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$SCRIPT_DIR/listener_stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>SPEED_MONITOR_SERVER</key>
        <string>$SERVER_URL</string>
    </dict>
</dict>
</plist>
EOF

launchctl load "$HOME/Library/LaunchAgents/$LISTENER_PLIST_NAME"
echo "  ✓ Command listener started (polls every 30s)"

echo "✓ Services configured"
echo ""

# =============================================================================
# STEP 7: Run initial speed test
# =============================================================================
echo "Step 5: Running initial speed test (~30 seconds)..."
SPEED_MONITOR_SERVER="$SERVER_URL" "$BIN_DIR/speed_monitor.sh" 2>/dev/null &
SPEEDTEST_PID=$!

for i in {1..40}; do
    if ! kill -0 $SPEEDTEST_PID 2>/dev/null; then
        break
    fi
    printf "."
    sleep 1
done
echo " Done!"

# =============================================================================
# COMPLETE
# =============================================================================
echo ""
echo "=========================================="
echo "   Speed Monitor v3.1.41 Installed!"
echo "=========================================="
echo ""
echo "What's running:"
echo "  • Speed tests every 10 minutes"
echo "  • Command listener (polls every 30 seconds)"
echo "  • Results uploaded to: $SERVER_URL"
echo "  • Menu bar shows live stats"
echo ""
echo "Dashboard: $SERVER_URL"
echo ""
echo "Commands:"
echo "  Run test now:  $BIN_DIR/speed_monitor.sh"
echo "  View logs:     tail -f $SCRIPT_DIR/launchd_stdout.log"
echo "  Stop service:  launchctl unload ~/Library/LaunchAgents/$PLIST_NAME"
echo ""
