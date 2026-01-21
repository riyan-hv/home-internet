#!/bin/bash
#
# Interactive configuration for Speed Monitor package
# Run this before building the .pkg to customize settings
#
# Usage: ./configure-pkg.sh
#

set -e

echo "=== Speed Monitor Package Configuration ==="
echo ""

# Get Railway URL
echo "Enter your Railway server URL (or press Enter for default):"
echo "Example: https://your-app.up.railway.app"
read -r SERVER_URL

if [ -z "$SERVER_URL" ]; then
    SERVER_URL="https://home-internet.onrender.com"
    echo "Using default: $SERVER_URL"
fi

# Get company name
echo ""
echo "Enter your company name (for branding):"
read -r COMPANY_NAME

if [ -z "$COMPANY_NAME" ]; then
    COMPANY_NAME="Your Company"
fi

# Get email domain
echo ""
echo "Enter your email domain (optional, for validation):"
echo "Example: yourcompany.com"
read -r EMAIL_DOMAIN

if [ -z "$EMAIL_DOMAIN" ]; then
    EMAIL_DOMAIN="yourcompany.com"
fi

# Create configuration file
cat > pkg-config.env << EOF
# Speed Monitor Package Configuration
# Generated: $(date)

SERVER_URL="${SERVER_URL}"
COMPANY_NAME="${COMPANY_NAME}"
EMAIL_DOMAIN="${EMAIL_DOMAIN}"
EOF

echo ""
echo "Configuration saved to: pkg-config.env"
echo ""
echo "Settings:"
echo "  Server URL:    $SERVER_URL"
echo "  Company:       $COMPANY_NAME"
echo "  Email Domain:  $EMAIL_DOMAIN"
echo ""
echo "Next steps:"
echo "1. Review settings in pkg-config.env"
echo "2. Run: ./build-pkg.sh"
echo "3. Test: sudo installer -pkg SpeedMonitor-3.1.0.pkg -target /"
echo ""
