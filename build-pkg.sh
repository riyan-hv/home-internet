#!/bin/bash
#
# Speed Monitor .pkg Builder
# Creates a macOS installer package that handles all setup automatically
#
# Usage: ./build-pkg.sh
# Output: SpeedMonitor-3.1.0.pkg
#

set -e

# Read version from VERSION file (single source of truth)
if [[ -f "VERSION" ]]; then
    VERSION=$(cat VERSION | tr -d '[:space:]')
else
    VERSION="3.1.0"
fi
PKG_NAME="SpeedMonitor-${VERSION}.pkg"
BUILD_DIR="$(pwd)/pkg-build"
PAYLOAD_DIR="${BUILD_DIR}/payload"
SCRIPTS_DIR="${BUILD_DIR}/scripts"
RESOURCES_DIR="${BUILD_DIR}/resources"

echo "=== Speed Monitor .pkg Builder v${VERSION} ==="
echo ""

# Load configuration if exists
if [ -f "pkg-config.env" ]; then
    echo "Loading configuration from pkg-config.env..."
    source pkg-config.env
    echo "  Server URL: ${SERVER_URL}"
    echo "  Company: ${COMPANY_NAME}"
else
    echo "No configuration found. Using defaults."
    echo "Run ./configure-pkg.sh to customize settings."
    SERVER_URL="https://home-internet.onrender.com"
    COMPANY_NAME="Your Company"
    EMAIL_DOMAIN="yourcompany.com"
fi
echo ""

# Clean previous build
if [ -d "$BUILD_DIR" ]; then
    echo "Cleaning previous build..."
    rm -rf "$BUILD_DIR"
fi

# Create directory structure
echo "Creating package structure..."
mkdir -p "${PAYLOAD_DIR}/usr/local/speedmonitor/bin"
mkdir -p "${PAYLOAD_DIR}/usr/local/speedmonitor/lib"
mkdir -p "${PAYLOAD_DIR}/Library/LaunchDaemons"
mkdir -p "${SCRIPTS_DIR}"
mkdir -p "${RESOURCES_DIR}"

# Copy main script
echo "Copying speed monitor script..."
cp speed_monitor.sh "${PAYLOAD_DIR}/usr/local/speedmonitor/bin/"
chmod +x "${PAYLOAD_DIR}/usr/local/speedmonitor/bin/speed_monitor.sh"

# Copy Swift helper source
echo "Copying Swift helper..."
cp dist/src/wifi_info.swift "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/"

# Copy watchdog script
echo "Copying watchdog script..."
cp watchdog.sh "${PAYLOAD_DIR}/usr/local/speedmonitor/bin/"
chmod +x "${PAYLOAD_DIR}/usr/local/speedmonitor/bin/watchdog.sh"

# Copy LaunchAgent templates
echo "Copying LaunchAgent templates..."
cp com.speedmonitor.plist "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/"
cp com.speedmonitor.watchdog.plist "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/"

# Copy SpeedMonitor.app if it exists
if [ -d "WiFiHelper/build/SpeedMonitor.app" ]; then
    echo "Copying SpeedMonitor.app..."
    cp -r WiFiHelper/build/SpeedMonitor.app "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/"
elif [ -f "WiFiHelper/SpeedMonitorMenuBar.swift" ]; then
    echo "Copying SpeedMonitor.app source..."
    cp WiFiHelper/SpeedMonitorMenuBar.swift "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/"
fi

# Create configuration file
echo "Creating configuration..."
cat > "${PAYLOAD_DIR}/usr/local/speedmonitor/lib/config.sh" << EOF
#!/bin/bash
# Speed Monitor Configuration
# Edit this file to customize deployment

# Server URL (REQUIRED - update this!)
SERVER_URL="${SERVER_URL}"

# Company name for branding
COMPANY_NAME="${COMPANY_NAME}"

# Email domain for validation (optional)
EMAIL_DOMAIN="${EMAIL_DOMAIN}"

# Installation directories
INSTALL_DIR="/usr/local/speedmonitor"
USER_DATA_DIR=".local/share/nkspeedtest"
USER_CONFIG_DIR=".config/nkspeedtest"
USER_BIN_DIR=".local/bin"
EOF

# Create preinstall script
echo "Creating preinstall script..."
cat > "${SCRIPTS_DIR}/preinstall" << 'PREINSTALL_EOF'
#!/bin/bash
#
# Preinstall script - runs before package installation
# Checks requirements and installs dependencies
#

set -e

LOG_FILE="/var/log/speedmonitor-install.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "=== Speed Monitor Preinstall Starting ==="

# Check macOS version
OS_VERSION=$(sw_vers -productVersion)
OS_MAJOR=$(echo "$OS_VERSION" | cut -d'.' -f1)

log "macOS version: $OS_VERSION"

if [ "$OS_MAJOR" -lt 11 ]; then
    log "ERROR: macOS 11 (Big Sur) or later required"
    exit 1
fi

# Check if Homebrew is installed
log "Checking for Homebrew..."
if ! command -v brew &> /dev/null; then
    log "Homebrew not found - will install in postinstall"
else
    log "Homebrew found at: $(which brew)"
fi

# Check for Xcode Command Line Tools (required for Swift compilation)
log "Checking for Xcode Command Line Tools..."
if ! xcode-select -p &> /dev/null; then
    log "Installing Xcode Command Line Tools (this may take a few minutes)..."
    # Trigger installation
    xcode-select --install 2>/dev/null || true

    # Wait for installation (with timeout)
    TIMEOUT=300
    ELAPSED=0
    while ! xcode-select -p &> /dev/null; do
        if [ $ELAPSED -ge $TIMEOUT ]; then
            log "WARNING: Xcode CLT installation timeout - continuing anyway"
            break
        fi
        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done
fi

if xcode-select -p &> /dev/null; then
    log "Xcode Command Line Tools found at: $(xcode-select -p)"
else
    log "WARNING: Xcode CLT not available - Swift helper may not compile"
fi

# Check disk space (need ~500MB for Homebrew + speedtest-cli)
AVAILABLE_KB=$(df -k /usr/local 2>/dev/null | tail -1 | awk '{print $4}')
AVAILABLE_MB=$((AVAILABLE_KB / 1024))

log "Available disk space: ${AVAILABLE_MB}MB"

if [ "$AVAILABLE_MB" -lt 500 ]; then
    log "WARNING: Low disk space (${AVAILABLE_MB}MB available, 500MB recommended)"
fi

log "=== Preinstall Complete ==="
exit 0
PREINSTALL_EOF

chmod +x "${SCRIPTS_DIR}/preinstall"

# Create postinstall script
echo "Creating postinstall script..."
cat > "${SCRIPTS_DIR}/postinstall" << 'POSTINSTALL_EOF'
#!/bin/bash
#
# Postinstall script - runs after package installation
# Sets up Homebrew, installs dependencies, configures per-user settings
#

# Don't exit on errors - try to install as much as possible
set +e

LOG_FILE="/var/log/speedmonitor-install.log"
INSTALL_DIR="/usr/local/speedmonitor"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "=== Speed Monitor Postinstall Starting ==="

# Load configuration
if [ -f "${INSTALL_DIR}/lib/config.sh" ]; then
    source "${INSTALL_DIR}/lib/config.sh"
    log "Configuration loaded from config.sh"
fi

# Install Homebrew if not present (system-wide)
CURRENT_USER=$(stat -f "%Su" /dev/console)
HOMEBREW_PREFIX=""

# Detect architecture and set Homebrew prefix
if [[ $(uname -m) == "arm64" ]]; then
    HOMEBREW_PREFIX="/opt/homebrew"
else
    HOMEBREW_PREFIX="/usr/local"
fi

log "Detected Homebrew prefix: $HOMEBREW_PREFIX"

# Check if Homebrew is already installed
if [ -f "${HOMEBREW_PREFIX}/bin/brew" ]; then
    log "Homebrew already installed at ${HOMEBREW_PREFIX}"
    export PATH="${HOMEBREW_PREFIX}/bin:$PATH"
else
    log "Installing Homebrew for user: $CURRENT_USER..."

    # Create Homebrew directory with correct ownership
    if [ ! -d "$HOMEBREW_PREFIX" ]; then
        log "Creating $HOMEBREW_PREFIX directory..."
        mkdir -p "$HOMEBREW_PREFIX"
        chown -R "$CURRENT_USER:staff" "$HOMEBREW_PREFIX"
    else
        log "Fixing ownership of $HOMEBREW_PREFIX..."
        chown -R "$CURRENT_USER:staff" "$HOMEBREW_PREFIX"
    fi

    # Download and run Homebrew installer in non-interactive mode
    HOMEBREW_INSTALL_LOG="/var/log/homebrew-install-$$.log"
    log "Installing Homebrew (this may take 5-10 minutes)..."

    # Run installer as user with non-interactive flag
    if sudo -u "$CURRENT_USER" /bin/bash -c "NONINTERACTIVE=1 CI=1 /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"" > "$HOMEBREW_INSTALL_LOG" 2>&1; then
        log "Homebrew installation command completed"
    else
        log "WARNING: Homebrew installation returned non-zero exit code"
        log "Check log: $HOMEBREW_INSTALL_LOG"
    fi

    # Verify installation
    if [ -f "${HOMEBREW_PREFIX}/bin/brew" ]; then
        log "SUCCESS: Homebrew installed at ${HOMEBREW_PREFIX}"
        export PATH="${HOMEBREW_PREFIX}/bin:$PATH"

        # Fix any permission issues
        log "Setting correct permissions..."
        chown -R "$CURRENT_USER:staff" "${HOMEBREW_PREFIX}"
        chmod -R u+w "${HOMEBREW_PREFIX}"

        # Verify brew command works
        BREW_VERSION=$(sudo -u "$CURRENT_USER" "${HOMEBREW_PREFIX}/bin/brew" --version 2>&1 | head -1)
        log "Homebrew version: $BREW_VERSION"
    else
        log "ERROR: Homebrew installation failed - ${HOMEBREW_PREFIX}/bin/brew not found"
        log "Installation log saved to: $HOMEBREW_INSTALL_LOG"
        log "Will continue without Homebrew - speedtest-cli must be installed manually"
    fi
fi

# Install speedtest-cli
log "Installing speedtest-cli..."

if [ -f "${HOMEBREW_PREFIX}/bin/brew" ]; then
    # Check if already installed
    if sudo -u "$CURRENT_USER" "${HOMEBREW_PREFIX}/bin/brew" list speedtest-cli &> /dev/null; then
        log "speedtest-cli already installed"
    else
        log "Installing speedtest-cli via Homebrew..."
        # Install speedtest-cli
        if sudo -u "$CURRENT_USER" "${HOMEBREW_PREFIX}/bin/brew" install speedtest-cli 2>&1 | tee -a "$LOG_FILE"; then
            log "speedtest-cli installed successfully"
        else
            log "WARNING: Failed to install speedtest-cli"
            log "User can install manually later: brew install speedtest-cli"
        fi
    fi

    # Verify installation
    if [ -f "${HOMEBREW_PREFIX}/bin/speedtest-cli" ]; then
        SPEEDTEST_VERSION=$(sudo -u "$CURRENT_USER" "${HOMEBREW_PREFIX}/bin/speedtest-cli" --version 2>&1 | head -1)
        log "speedtest-cli verified: $SPEEDTEST_VERSION at ${HOMEBREW_PREFIX}/bin/speedtest-cli"

        # Create symlink in user PATH
        sudo -u "$CURRENT_USER" ln -sf "${HOMEBREW_PREFIX}/bin/speedtest-cli" "$HOME/.local/bin/speedtest-cli" 2>/dev/null || true
    else
        log "WARNING: speedtest-cli binary not found at ${HOMEBREW_PREFIX}/bin/speedtest-cli"
    fi
else
    log "WARNING: Homebrew not available - skipping speedtest-cli installation"
    log "Please install manually: brew install speedtest-cli"
fi

# Compile Swift helper (wifi_info)
log "Compiling Swift helper..."
if command -v swiftc &> /dev/null; then
    if swiftc -O -o "${INSTALL_DIR}/bin/wifi_info" \
              "${INSTALL_DIR}/lib/wifi_info.swift" \
              -framework CoreWLAN -framework Foundation 2>&1 | tee -a "$LOG_FILE"; then
        chmod +x "${INSTALL_DIR}/bin/wifi_info"
        log "Swift helper compiled successfully"
    else
        log "WARNING: Swift helper compilation failed - will use fallback methods"
    fi
else
    log "WARNING: swiftc not available - Swift helper not compiled"
fi

# Build SpeedMonitor.app if source exists
if [ -f "${INSTALL_DIR}/lib/SpeedMonitorMenuBar.swift" ]; then
    log "Building SpeedMonitor.app..."

    # Create app bundle structure
    mkdir -p "${INSTALL_DIR}/lib/SpeedMonitor.app/Contents/MacOS"
    mkdir -p "${INSTALL_DIR}/lib/SpeedMonitor.app/Contents/Resources"

    # Compile Swift app (with -parse-as-library to fix @main attribute error)
    if swiftc -parse-as-library \
              -o "${INSTALL_DIR}/lib/SpeedMonitor.app/Contents/MacOS/SpeedMonitor" \
              "${INSTALL_DIR}/lib/SpeedMonitorMenuBar.swift" \
              -framework SwiftUI -framework CoreWLAN -framework CoreLocation -framework AppKit 2>&1 | tee -a "$LOG_FILE"; then

        # Create Info.plist
        cat > "${INSTALL_DIR}/lib/SpeedMonitor.app/Contents/Info.plist" << 'PLIST_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>SpeedMonitor</string>
    <key>CFBundleIdentifier</key>
    <string>com.speedmonitor.menubar</string>
    <key>CFBundleName</key>
    <string>SpeedMonitor</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>SpeedMonitor needs location access to display your WiFi network name (SSID).</string>
</dict>
</plist>
PLIST_EOF

        log "SpeedMonitor.app built successfully"
    else
        log "WARNING: SpeedMonitor.app build failed"
    fi
fi

# Set up for all users
log "Setting up Speed Monitor for all users..."

for user_home in /Users/*; do
    if [ ! -d "$user_home" ]; then
        continue
    fi

    username=$(basename "$user_home")

    # Skip system users
    if [ "$username" = "Shared" ] || [ "$username" = "Guest" ]; then
        continue
    fi

    log "Configuring for user: $username"

    # Create directories
    sudo -u "$username" mkdir -p "$user_home/${USER_DATA_DIR}"
    sudo -u "$username" mkdir -p "$user_home/${USER_CONFIG_DIR}"
    sudo -u "$username" mkdir -p "$user_home/${USER_BIN_DIR}"
    sudo -u "$username" mkdir -p "$user_home/Library/LaunchAgents"

    # Link scripts to user bin
    sudo -u "$username" ln -sf "${INSTALL_DIR}/bin/speed_monitor.sh" "$user_home/${USER_BIN_DIR}/speed_monitor.sh"
    sudo -u "$username" ln -sf "${INSTALL_DIR}/bin/wifi_info" "$user_home/${USER_BIN_DIR}/wifi_info" 2>/dev/null || true

    # Generate device ID if not exists
    if [ ! -f "$user_home/${USER_CONFIG_DIR}/device_id" ]; then
        # Use hardware UUID for stable device ID
        hw_uuid=$(ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ { print $3 }' | tr -d '"')
        device_id=$(echo "$hw_uuid-$username" | shasum -a 256 | cut -c1-16)
        echo "$device_id" | sudo -u "$username" tee "$user_home/${USER_CONFIG_DIR}/device_id" > /dev/null
        log "Generated device ID for $username: $device_id"
    fi

    # Prompt for email (interactive mode only)
    if [ -t 0 ] && [ ! -f "$user_home/${USER_CONFIG_DIR}/user_email" ]; then
        echo ""
        echo "Enter email for $username (or press Enter to skip):"
        read -r user_email
        if [ -n "$user_email" ]; then
            echo "$user_email" | sudo -u "$username" tee "$user_home/${USER_CONFIG_DIR}/user_email" > /dev/null
            log "Email saved for $username: $user_email"
        fi
    fi

    # Create LaunchAgent plist from template
    cat > "$user_home/Library/LaunchAgents/com.speedmonitor.plist" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.speedmonitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>$user_home/${USER_BIN_DIR}/speed_monitor.sh</string>
    </array>
    <key>StartInterval</key>
    <integer>600</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$user_home/${USER_DATA_DIR}/launchd_stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$user_home/${USER_DATA_DIR}/launchd_stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>SPEED_MONITOR_SERVER</key>
        <string>${SERVER_URL}</string>
    </dict>
</dict>
</plist>
PLIST_EOF

    chown "$username" "$user_home/Library/LaunchAgents/com.speedmonitor.plist"
    log "Created LaunchAgent for $username"

    # Load LaunchAgent (only if user is logged in)
    if pgrep -u "$username" &> /dev/null; then
        sudo -u "$username" launchctl load "$user_home/Library/LaunchAgents/com.speedmonitor.plist" 2>/dev/null || true
        log "Loaded LaunchAgent for $username"
    else
        log "User $username not logged in - LaunchAgent will load on next login"
    fi

    # Copy SpeedMonitor.app to user's Applications
    if [ -d "${INSTALL_DIR}/lib/SpeedMonitor.app" ]; then
        sudo -u "$username" cp -r "${INSTALL_DIR}/lib/SpeedMonitor.app" "$user_home/Applications/" 2>/dev/null || \
        cp -r "${INSTALL_DIR}/lib/SpeedMonitor.app" "/Applications/"
        log "Installed SpeedMonitor.app for $username"
    fi
done

# Run initial speed test for console user
CURRENT_USER=$(stat -f "%Su" /dev/console)
if [ -f "/Users/${CURRENT_USER}/${USER_BIN_DIR}/speed_monitor.sh" ]; then
    log "Running initial speed test for $CURRENT_USER..."
    sudo -u "$CURRENT_USER" "/Users/${CURRENT_USER}/${USER_BIN_DIR}/speed_monitor.sh" &
fi

log "=== Postinstall Complete ==="
log "Speed Monitor installed successfully!"
log "Dashboard: ${SERVER_URL}"
log "Logs: $LOG_FILE"

exit 0
POSTINSTALL_EOF

chmod +x "${SCRIPTS_DIR}/postinstall"

# Create welcome message
cat > "${RESOURCES_DIR}/welcome.txt" << 'EOF'
Speed Monitor Installation

This installer will set up automated internet speed monitoring on your Mac.

What will be installed:
• Speed Monitor scripts (collects WiFi and speed test data)
• Homebrew package manager (if not already installed)
• speedtest-cli (for speed testing)
• LaunchAgent (runs tests every 10 minutes)
• SpeedMonitor menu bar app (displays real-time stats)

After installation:
1. Grant Location Services permission when prompted
   (required to see WiFi network name)
2. Check menu bar for SpeedMonitor icon
3. Speed tests will run automatically every 10 minutes

For support, contact your IT administrator.
EOF

# Create conclusion message
cat > "${RESOURCES_DIR}/conclusion.txt" << 'EOF'
Installation Complete!

Speed Monitor is now running on your Mac.

Next steps:
1. Look for the SpeedMonitor icon in your menu bar (top right)
2. Click it to see your WiFi and speed stats
3. Click "Settings" to grant Location Services permission
4. Speed tests will run automatically every 10 minutes

View your speed history:
Open your web browser and go to the dashboard URL
(your IT admin will provide this)

Troubleshooting:
• If no menu bar icon appears, open /Applications/SpeedMonitor.app
• View logs: ~/.local/share/nkspeedtest/speed_monitor.log
• System logs: /var/log/speedmonitor-install.log

For support, contact your IT administrator.
EOF

# Build the package
echo "Building package..."
pkgbuild --root "${PAYLOAD_DIR}" \
         --scripts "${SCRIPTS_DIR}" \
         --identifier "com.speedmonitor.pkg" \
         --version "${VERSION}" \
         --install-location "/" \
         "${BUILD_DIR}/component.pkg"

# Create distribution (for customization)
echo "Creating distribution..."
productbuild --synthesize \
             --package "${BUILD_DIR}/component.pkg" \
             "${BUILD_DIR}/distribution.xml"

# Customize distribution XML
cat > "${BUILD_DIR}/distribution.xml" << DIST_EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Speed Monitor</title>
    <welcome file="welcome.txt"/>
    <conclusion file="conclusion.txt"/>
    <pkg-ref id="com.speedmonitor.pkg"/>
    <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
    <choices-outline>
        <line choice="default">
            <line choice="com.speedmonitor.pkg"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="com.speedmonitor.pkg" visible="false">
        <pkg-ref id="com.speedmonitor.pkg"/>
    </choice>
    <pkg-ref id="com.speedmonitor.pkg" version="${VERSION}" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
DIST_EOF

# Build final product
echo "Creating final package..."
productbuild --distribution "${BUILD_DIR}/distribution.xml" \
             --resources "${RESOURCES_DIR}" \
             --package-path "${BUILD_DIR}" \
             "${PKG_NAME}"

# Show results
echo ""
echo "=== Package Build Complete ==="
echo ""
echo "Package: ${PKG_NAME}"
echo "Size: $(du -h "${PKG_NAME}" | cut -f1)"
echo ""
echo "Before distributing:"
echo "1. Edit pkg-build/payload/usr/local/speedmonitor/lib/config.sh"
echo "   Update SERVER_URL to your Render deployment"
echo "2. Rebuild: ./build-pkg.sh"
echo "3. Test: sudo installer -pkg ${PKG_NAME} -target /"
echo ""
echo "For MDM deployment:"
echo "• Upload to Jamf/Intune"
echo "• No configuration required by end users"
echo "• Will install Homebrew automatically"
echo ""
