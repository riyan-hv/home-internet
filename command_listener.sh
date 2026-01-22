#!/bin/bash
# Speed Monitor - Command Listener
# Lightweight daemon that polls for remote commands every 30 seconds
# Runs independently of the main speed test cycle
# Version: 3.1.41

set -euo pipefail

# Configuration
POLL_INTERVAL=30  # seconds between polls
CONFIG_DIR="$HOME/.config/nkspeedtest"
LOG_DIR="$HOME/.local/share/nkspeedtest"
LOG_FILE="$LOG_DIR/command_listener.log"
SPEED_MONITOR_SCRIPT="$HOME/.local/bin/speed_monitor.sh"
SERVER_URL="${SPEED_MONITOR_SERVER:-https://home-internet.onrender.com}"

# Ensure directories exist
mkdir -p "$CONFIG_DIR" "$LOG_DIR"

# Get device ID (must match the main script)
get_device_id() {
    local device_id_file="$CONFIG_DIR/device_id"
    if [[ -f "$device_id_file" ]]; then
        cat "$device_id_file"
    else
        # Generate from hardware UUID for stability
        local hw_uuid=$(ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ { print $3 }' | tr -d '"')
        echo "$hw_uuid" | shasum -a 256 | cut -c1-16
    fi
}

# Logging
log() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $1" >> "$LOG_FILE"
    # Keep log file under 1MB
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || echo 0) -gt 1048576 ]]; then
        tail -1000 "$LOG_FILE" > "$LOG_FILE.tmp" && mv "$LOG_FILE.tmp" "$LOG_FILE"
    fi
}

# Report command result back to server
report_result() {
    local cmd_id="$1"
    local status="$2"
    local result="$3"

    curl -s --max-time 10 -X POST "$SERVER_URL/api/commands/$cmd_id/result" \
        -H "Content-Type: application/json" \
        -d "{\"status\":\"$status\",\"result\":\"$result\"}" \
        >/dev/null 2>&1 || true
}

# Execute a command
execute_command() {
    local cmd_id="$1"
    local command="$2"
    local payload="$3"

    log "Executing command: $command (id: $cmd_id)"

    case "$command" in
        force_update)
            log "Running force update..."
            if [[ -x "$SPEED_MONITOR_SCRIPT" ]]; then
                "$SPEED_MONITOR_SCRIPT" --update >> "$LOG_FILE" 2>&1
                report_result "$cmd_id" "executed" "Update completed"
                log "Force update completed"
            else
                report_result "$cmd_id" "failed" "speed_monitor.sh not found"
                log "ERROR: speed_monitor.sh not found at $SPEED_MONITOR_SCRIPT"
            fi
            ;;

        force_speedtest)
            log "Running force speedtest..."
            if [[ -x "$SPEED_MONITOR_SCRIPT" ]]; then
                # Run speedtest in background so listener continues
                ("$SPEED_MONITOR_SCRIPT" >> "$LOG_DIR/launchd_stdout.log" 2>&1) &
                report_result "$cmd_id" "executed" "Speedtest triggered"
                log "Force speedtest triggered"
            else
                report_result "$cmd_id" "failed" "speed_monitor.sh not found"
                log "ERROR: speed_monitor.sh not found at $SPEED_MONITOR_SCRIPT"
            fi
            ;;

        restart_service)
            log "Restarting speed monitor service..."
            # Unload and reload the main launchd job
            launchctl unload "$HOME/Library/LaunchAgents/com.speedmonitor.plist" 2>/dev/null || true
            sleep 1
            launchctl load "$HOME/Library/LaunchAgents/com.speedmonitor.plist" 2>/dev/null || true
            report_result "$cmd_id" "executed" "Service restarted"
            log "Service restart completed"
            ;;

        collect_diagnostics)
            log "Collecting diagnostics..."
            local diag_file="$LOG_DIR/diagnostics_$(date +%Y%m%d_%H%M%S).txt"
            {
                echo "=== Speed Monitor Diagnostics ==="
                echo "Timestamp: $(date)"
                echo "Device ID: $(get_device_id)"
                echo ""
                echo "=== System Info ==="
                sw_vers
                echo ""
                echo "=== Network Interfaces ==="
                ifconfig | grep -A2 "^en"
                echo ""
                echo "=== WiFi Info ==="
                system_profiler SPAirPortDataType 2>/dev/null | head -50
                echo ""
                echo "=== LaunchD Jobs ==="
                launchctl list | grep speedmonitor
                echo ""
                echo "=== Recent Logs ==="
                tail -50 "$LOG_DIR/launchd_stdout.log" 2>/dev/null || echo "No logs found"
                echo ""
                echo "=== Process List ==="
                ps aux | grep -i speed
            } > "$diag_file" 2>&1

            report_result "$cmd_id" "executed" "Diagnostics collected: $diag_file"
            log "Diagnostics saved to $diag_file"
            ;;

        *)
            log "Unknown command: $command"
            report_result "$cmd_id" "failed" "Unknown command: $command"
            ;;
    esac
}

# Poll for commands
poll_commands() {
    local device_id=$(get_device_id)

    # Fetch pending commands for this device
    local response=$(curl -s --max-time 15 "$SERVER_URL/api/commands/$device_id" 2>/dev/null)

    if [[ -z "$response" ]]; then
        return
    fi

    # Check if response contains commands (simple JSON check)
    if ! echo "$response" | grep -q '"command"'; then
        return
    fi

    # Parse commands using simple bash (avoid jq dependency)
    # Response format: {"commands":[{"id":1,"command":"force_speedtest","payload":null},...]}

    # Extract the commands array content
    local commands_json=$(echo "$response" | sed 's/.*"commands":\[\(.*\)\].*/\1/')

    if [[ -z "$commands_json" || "$commands_json" == "$response" ]]; then
        return
    fi

    # Split by },{ to get individual commands (using tr to replace delimiter)
    echo "$commands_json" | tr '}' '\n' | while read -r cmd_fragment; do
        if [[ -z "$cmd_fragment" ]]; then
            continue
        fi

        # Extract id using sed (macOS compatible)
        local cmd_id=$(echo "$cmd_fragment" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')

        # Extract command using sed
        local command=$(echo "$cmd_fragment" | sed -n 's/.*"command":"\([^"]*\)".*/\1/p')

        if [[ -n "$cmd_id" && -n "$command" ]]; then
            log "Received command: $command (id: $cmd_id)"
            execute_command "$cmd_id" "$command" "null"
        fi
    done
}

# Main loop
main() {
    log "Command listener started (polling every ${POLL_INTERVAL}s)"
    log "Device ID: $(get_device_id)"
    log "Server: $SERVER_URL"

    while true; do
        poll_commands
        sleep "$POLL_INTERVAL"
    done
}

# Handle signals for graceful shutdown
trap 'log "Listener stopped"; exit 0' SIGTERM SIGINT

# Start main loop
main
