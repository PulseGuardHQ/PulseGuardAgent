#!/bin/bash
# PulseGuard Agent Installation Script for Linux
# ------------------------------------------------

# Check parameters
if [ $# -lt 2 ]; then
    echo "Usage: $0 <device_uuid> <api_token> [check_interval]"
    echo "Example: $0 914759c0-bcec-43be-a2b6-3d6f7bf67749 apitoken123456 30"
    echo ""
    echo "Parameters:"
    echo "  device_uuid    : The UUID of your device"
    echo "  api_token      : Your API token for authentication"
    echo "  check_interval : (Optional) How often to send metrics in seconds (default: 60)"
    exit 1
fi

DEVICE_UUID=$1
API_TOKEN=$2
CHECK_INTERVAL=${3:-60}  # Use third parameter if provided, otherwise default to 60
API_BASE_URL="https://app.pulseguard.nl/api"
AGENT_VERSION="1.0.0" # Initial version

echo -e "\e[34mPulseGuard Agent Installation\e[0m"
echo -e "\e[34m=========================\e[0m"
echo ""
echo -e "\e[32mDevice UUID: $DEVICE_UUID\e[0m"
echo -e "\e[32mAPI URL: $API_BASE_URL\e[0m"
echo -e "\e[32mAgent Version: $AGENT_VERSION\e[0m"
echo -e "\e[32mCheck Interval: ${CHECK_INTERVAL} seconds\e[0m"
echo ""

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\e[31mThis script must be run as root or with sudo.\e[0m"
    exit 1
fi

# Check for curl
if ! command -v curl &> /dev/null; then
    echo -e "\e[33mInstalling curl, which is required for the agent...\e[0m"
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y curl
    elif command -v yum &> /dev/null; then
        yum install -y curl
    else
        echo -e "\e[31mCould not install curl. Please install it manually and run the script again.\e[0m"
        exit 1
    fi
fi

# Installation directory
INSTALL_DIR="/opt/pulseguard"
echo -e "\e[33mCreating installation directories...\e[0m"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
touch $INSTALL_DIR/logs/agent.log
chmod -R 755 $INSTALL_DIR
chmod 644 $INSTALL_DIR/logs/agent.log

# Create config file
echo -e "\e[33mCreating configuration file...\e[0m"
cat > $INSTALL_DIR/config.json << EOL
{
    "api_token": "$API_TOKEN",
    "api_base_url": "$API_BASE_URL",
    "check_interval": $CHECK_INTERVAL,
    "metrics_enabled": true,
    "services_monitoring": true
}
EOL

# Verify config file was created
if [ ! -f "$INSTALL_DIR/config.json" ]; then
    echo -e "\e[31mFailed to create config file. Check permissions and disk space.\e[0m"
    exit 1
fi

chmod 644 $INSTALL_DIR/config.json
echo -e "\e[32mConfiguration file created successfully.\e[0m"

# Test network connectivity to the API server
echo -e "\e[33mTesting network connectivity...\e[0m"
API_HOST=$(echo "$API_BASE_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
if ping -c 1 $API_HOST &> /dev/null; then
    echo -e "\e[32mNetwork connectivity test successful.\e[0m"
else
    echo -e "\e[31mWarning: Unable to ping $API_HOST. This might affect agent connectivity.\e[0m"
fi

# Create the agent script
echo -e "\e[33mCreating agent script...\e[0m"
cat > $INSTALL_DIR/pulseguard-agent << 'EOL'
#!/bin/bash
# PulseGuard Agent for Linux
# ----------------------------
# Version information
AGENT_VERSION="1.0.0"
# Set log file
LOG_FILE="/opt/pulseguard/logs/agent.log"
CONFIG_FILE="/opt/pulseguard/config.json"
UPDATE_DIR="/opt/pulseguard/update"

# Make sure log file exists
mkdir -p "$(dirname "$LOG_FILE")"
touch $LOG_FILE
chmod 644 $LOG_FILE

function log() {
    local timestamp=$(date)
    echo "$timestamp: $1" | tee -a $LOG_FILE
}

function log_debug() {
    local timestamp=$(date)
    echo "$timestamp: [DEBUG] $1" >> $LOG_FILE
}

function get_config_value() {
    local key=$1
    if [ ! -f "$CONFIG_FILE" ]; then
        log "ERROR: Config file not found at $CONFIG_FILE"
        echo "File listing of /opt/pulseguard:" >> $LOG_FILE
        ls -la /opt/pulseguard >> $LOG_FILE 2>&1
        return 1
    fi
    
    # Print config file contents to log for debugging
    log_debug "Config file contents:"
    cat "$CONFIG_FILE" >> $LOG_FILE 2>&1
    
    # Better approach to extract values from JSON
    if [ "$key" = "api_base_url" ]; then
        # Special handling for URL to avoid regex issues
        local pattern='"api_base_url"[[:space:]]*:[[:space:]]*"([^"]*)"'
        if [[ $(cat "$CONFIG_FILE") =~ $pattern ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        else
            # Fallback to default URL
            log_debug "Could not extract api_base_url, using default"
            echo "https://app.pulseguard.nl/api"
            return 0
        fi
    else
        # For other config values
        local pattern="\"$key\"[[:space:]]*:[[:space:]]*\"([^\"]*)\""
        if [[ $(cat "$CONFIG_FILE") =~ $pattern ]]; then
            echo "${BASH_REMATCH[1]}"
            return 0
        fi
    fi
    
    # If we get here, we couldn't extract the value
    log_debug "Could not extract $key from config file"
    return 1
}

function get_cpu_usage() {
    # More accurate CPU calculation based on averages
    # First try mpstat which gives more accurate values
    if command -v mpstat &> /dev/null; then
        mpstat 1 1 | grep -A 5 "CPU" | tail -n 1 | awk '{print 100 - $12}'
    else
        # Fallback to a more reliable calculation using /proc/stat
        # This calculates the average across all CPUs
        local cpu_idle=$(awk '{if (NR==1) {print $5}}' /proc/stat)
        local cpu_total=$(awk '{if (NR==1) {total=0; for(i=2;i<=NF;i++) total+=$i; print total}}' /proc/stat)
        sleep 0.5  # Short sleep for CPU measurement
        local cpu_idle_after=$(awk '{if (NR==1) {print $5}}' /proc/stat)
        local cpu_total_after=$(awk '{if (NR==1) {total=0; for(i=2;i<=NF;i++) total+=$i; print total}}' /proc/stat)
        
        local idle_diff=$((cpu_idle_after - cpu_idle))
        local total_diff=$((cpu_total_after - cpu_total))
        
        if [ $total_diff -eq 0 ]; then
            echo "0"  # Avoid division by zero
        else
            echo "$(( 100 - (idle_diff * 100 / total_diff) ))"
        fi
    fi
}

function get_memory_usage() {
    free | grep Mem | awk '{print $3/$2 * 100}'
}

function get_disk_usage() {
    df -h / | grep / | awk '{print $5}' | tr -d '%'
}

function get_uptime_seconds() {
    cat /proc/uptime | awk '{print $1}' | cut -d. -f1
}

function check_dns() {
    local domain=$1
    log_debug "Testing DNS resolution for $domain"
    
    if host $domain &>/dev/null; then
        log_debug "DNS resolution successful for $domain"
        return 0
    else
        log_debug "DNS resolution failed for $domain"
        return 1
    fi
}

function test_api_connection() {
    local API_TOKEN=$(get_config_value "api_token")
        local API_BASE_URL=$(get_config_value "api_base_url")        # Validate API_BASE_URL format    if [[ ! $API_BASE_URL =~ ^https?:// ]]; then        log "ERROR: API URL format is invalid: $API_BASE_URL"        return 1    fi
    
    local API_HOST=$(echo "$API_BASE_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
    log_debug "Extracted API host: $API_HOST"
    
    # Try to resolve the hostname
    if ! check_dns $API_HOST; then
        log "WARNING: Cannot resolve hostname $API_HOST. Check your network/DNS configuration."
    fi
    
    local CONFIG_URL="$API_BASE_URL/devices/config"
    
    log "Testing API connection to $CONFIG_URL..."
    
    # Send a simple test request with debug info
    log_debug "Sending curl request to $CONFIG_URL"
    
    local CURL_OUTPUT=$(mktemp)
    local HTTP_CODE=$(curl -v -s -o $CURL_OUTPUT -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $API_TOKEN" \
        "$CONFIG_URL" 2>&1)
    
    if [ "$HTTP_CODE" == "200" ]; then
        log "API connection successful (HTTP 200)"
        rm -f $CURL_OUTPUT
        return 0
    else 
        log "API connection failed (HTTP $HTTP_CODE)"
        
        # Additional diagnostics without exposing sensitive data
        log_debug "Running network diagnostics..."
        
        if command -v ping &> /dev/null; then
            log_debug "Ping test to $API_HOST:"
            ping -c 3 $API_HOST >> $LOG_FILE 2>&1
        fi
        
        if command -v traceroute &> /dev/null; then
            log_debug "Traceroute to $API_HOST:"
            traceroute $API_HOST >> $LOG_FILE 2>&1
        fi
        
        rm -f $CURL_OUTPUT
        return 1
    fi
}

function check_for_updates() {
    local API_TOKEN=$(get_config_value "api_token")
    local API_BASE_URL=$(get_config_value "api_base_url")
    
    if [ -z "$API_TOKEN" ] || [ -z "$API_BASE_URL" ]; then
        log "ERROR: Missing API token or base URL in configuration"
        return 1
    fi
    
    local UPDATE_URL="$API_BASE_URL/devices/check-for-updates"
    
    log "Checking for agent updates..."
    
    # Create the payload without the token (it will be sent in header)
    local PAYLOAD="{\"current_version\":\"$AGENT_VERSION\",\"os_type\":\"linux\"}"
    
    # Send the request
    local CURL_OUTPUT=$(mktemp)
    local HTTP_CODE=$(curl -s -o $CURL_OUTPUT -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $API_TOKEN" \
        -d "$PAYLOAD" \
        "$UPDATE_URL" 2>&1)
    
    if [ "$HTTP_CODE" == "200" ]; then
        # Parse the response
        local UPDATE_AVAILABLE=$(grep -o '"update_available":[^,}]*' $CURL_OUTPUT | cut -d: -f2 | tr -d ' "')
        
        if [ "$UPDATE_AVAILABLE" == "true" ]; then
            local LATEST_VERSION=$(grep -o '"latest_version":"[^"]*"' $CURL_OUTPUT | cut -d: -f2 | tr -d '"')
            local UPDATE_URL=$(grep -o '"update_url":"[^"]*"' $CURL_OUTPUT | cut -d: -f2 | tr -d '"')
            
            log "Update available! Current: $AGENT_VERSION, Latest: $LATEST_VERSION"
            
            # Log update notes (simplified parsing)
            log "Update notes:"
            grep -o '"update_notes":{[^}]*}' $CURL_OUTPUT | sed 's/"update_notes"://' >> $LOG_FILE
            
            # Initiate self-update if URL is provided
            if [ -n "$UPDATE_URL" ]; then
                log "Starting self-update process..."
                self_update "$UPDATE_URL"
            fi
        else
            log "Agent is up to date (version $AGENT_VERSION)"
        fi
    else 
        log "Error checking for updates: HTTP $HTTP_CODE"
        log_debug "Response: $(cat $CURL_OUTPUT)"
    fi
    
    rm -f $CURL_OUTPUT
}

function self_update() {
    local UPDATE_URL="$1"
    
    # Create update directory if it doesn't exist
    mkdir -p "$UPDATE_DIR"
    
    # Download the new version
    local TEMP_FILE="$UPDATE_DIR/new-agent.sh"
    
    log "Downloading update from $UPDATE_URL..."
    if curl -s -o "$TEMP_FILE" "$UPDATE_URL"; then
        # Verify the downloaded file
        if [ ! -s "$TEMP_FILE" ]; then
            log "ERROR: Failed to download update: File is empty or missing"
            return 1
        fi
        
        # Make the new file executable
        chmod +x "$TEMP_FILE"
        
        # Create an update script
        local UPDATE_SCRIPT="$UPDATE_DIR/update.sh"
        cat > "$UPDATE_SCRIPT" << EOF
#!/bin/bash
# PulseGuard Update Script

LOG_FILE="/opt/pulseguard/logs/update.log"
SOURCE_FILE="$TEMP_FILE"
TARGET_FILE="/opt/pulseguard/pulseguard-agent"

function write_log() {
    local timestamp=$(date)
    echo "$timestamp: [UPDATE] $1" >> "$LOG_FILE"
}

# Wait for original process to exit
sleep 5

write_log "Starting update process..."

# Copy the new agent file
if cp "$SOURCE_FILE" "$TARGET_FILE"; then
    write_log "Agent file updated successfully"
    
    # Restart the service
    write_log "Restarting agent service..."
    systemctl restart pulseguard-agent
    
    write_log "Update completed successfully!"
else
    write_log "Error during update: Failed to copy file"
fi
EOF
        
        # Make the update script executable
        chmod +x "$UPDATE_SCRIPT"
        
        # Run the update script in the background
        log "Preparing to update agent in background..."
        nohup "$UPDATE_SCRIPT" > /dev/null 2>&1 &
        
        # Exit this script to allow the update script to replace the file
        log "Update scheduled. Agent will restart momentarily."
        sleep 2
        exit 0
    else
        log "ERROR: Failed to download update"
    fi
}

function collect_metrics() {
    local CPU_USAGE=$(get_cpu_usage)
    local MEMORY_USAGE=$(get_memory_usage)
    local DISK_USAGE=$(get_disk_usage)
    local UPTIME=$(get_uptime_seconds)
    local HOSTNAME=$(hostname)
    local IP_ADDR=$(hostname -I | awk '{print $1}')
    local MAC_ADDR=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null || echo "00:00:00:00:00:00")
    
    # Get OS info
    local OS_TYPE=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2 | tr -d '"')
    local OS_VERSION=$(cat /etc/os-release | grep "^VERSION_ID=" | cut -d= -f2 | tr -d '"')
    
    # Create metrics payload
    local METRICS="{\"cpu_usage\":$CPU_USAGE,\"memory_usage\":$MEMORY_USAGE,\"disk_usage\":$DISK_USAGE,\"uptime\":$UPTIME}"
    
    # Create system specs payload
    local SYSTEM_SPECS="{\"cpu_cores\":$(nproc),\"total_memory\":$(free -m | grep Mem | awk '{print $2}')}"
    
    # Create the full data payload
    local DATA="{\"hostname\":\"$HOSTNAME\",\"ip_address\":\"$IP_ADDR\",\"mac_address\":\"$MAC_ADDR\",\"os_type\":\"$OS_TYPE\",\"os_version\":\"$OS_VERSION\",\"system_specs\":$SYSTEM_SPECS,\"metrics\":$METRICS}"
    
    # Get API token from config
    local API_TOKEN=$(get_config_value "api_token")
    local API_BASE_URL=$(get_config_value "api_base_url")
    local CHECKIN_URL="$API_BASE_URL/devices/check-in"
    
    log_debug "Sending metrics payload: $DATA"
    log_debug "Sending to URL: $CHECKIN_URL"
    
    # Send the data to the API
    local RESULT=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $API_TOKEN" \
        -d "$DATA" \
        -w "\nHTTP_STATUS:%{http_code}" \
        "$CHECKIN_URL")
    
    local HTTP_STATUS=$(echo "$RESULT" | grep HTTP_STATUS | cut -d':' -f2)
    local RESPONSE=$(echo "$RESULT" | grep -v HTTP_STATUS)
    
    if [ "$HTTP_STATUS" == "200" ]; then
        log "Sent metrics: HTTP 200 - Success"
        log_debug "Response: $RESPONSE"
        
        # Parse the response to get the new check interval
        local NEW_CHECK_INTERVAL=$(echo "$RESPONSE" | jq -r '.config.check_interval // empty')
        if [ ! -z "$NEW_CHECK_INTERVAL" ] && [ "$NEW_CHECK_INTERVAL" != "null" ]; then
            if [ "$NEW_CHECK_INTERVAL" != "$CHECK_INTERVAL" ]; then
                log "Updating check interval from $CHECK_INTERVAL to $NEW_CHECK_INTERVAL seconds"
                CHECK_INTERVAL=$NEW_CHECK_INTERVAL
                # Update the config file
                sed -i "s/\"check_interval\": [0-9]*/\"check_interval\": $CHECK_INTERVAL/" "$CONFIG_FILE"
            fi
        fi
    else
        log "Failed to send metrics: HTTP $HTTP_STATUS"
        log_debug "Error Response: $RESPONSE"
        log_debug "Request URL: $CHECKIN_URL"
        log_debug "Request Payload: $DATA"
        log_debug "API Token: ${API_TOKEN:0:8}...${API_TOKEN: -8}"
        
        # If we get a 500 error, try with a simplified payload
        if [ "$HTTP_STATUS" == "500" ]; then
            log "Detected server error (HTTP 500), trying with minimal payload..."
            local MINIMAL_DATA="{\"hostname\":\"$HOSTNAME\",\"metrics\":$METRICS}"
            
            local RETRY_RESULT=$(curl -s -X POST \
                -H "Content-Type: application/json" \
                -H "X-API-Token: $API_TOKEN" \
                -d "$MINIMAL_DATA" \
                -w "\nHTTP_STATUS:%{http_code}" \
                "$CHECKIN_URL")
                
            local RETRY_STATUS=$(echo "$RETRY_RESULT" | grep HTTP_STATUS | cut -d':' -f2)
            local RETRY_RESPONSE=$(echo "$RETRY_RESULT" | grep -v HTTP_STATUS)
            
            if [ "$RETRY_STATUS" == "200" ]; then
                log "Minimal payload succeeded (HTTP 200)"
                log_debug "Response: $RETRY_RESPONSE"
                
                # Also check for check interval update in retry response
                local NEW_CHECK_INTERVAL=$(echo "$RETRY_RESPONSE" | jq -r '.config.check_interval // empty')
                if [ ! -z "$NEW_CHECK_INTERVAL" ] && [ "$NEW_CHECK_INTERVAL" != "null" ]; then
                    if [ "$NEW_CHECK_INTERVAL" != "$CHECK_INTERVAL" ]; then
                        log "Updating check interval from $CHECK_INTERVAL to $NEW_CHECK_INTERVAL seconds"
                        CHECK_INTERVAL=$NEW_CHECK_INTERVAL
                        # Update the config file
                        sed -i "s/\"check_interval\": [0-9]*/\"check_interval\": $CHECK_INTERVAL/" "$CONFIG_FILE"
                    fi
                fi
            else
                log "Minimal payload also failed: HTTP $RETRY_STATUS"
                log_debug "Response: $RETRY_RESPONSE"
            fi
        fi
    fi
}

# Main loop
log "PulseGuard Agent starting... Version: $AGENT_VERSION"

# Make sure we have the required tools
if ! command -v curl &> /dev/null; then
    log "ERROR: curl is not installed. Agent cannot function without it."
    exit 1
fi

# Create log directory if it doesn't exist
if [ ! -d "$(dirname "$LOG_FILE")" ]; then
    mkdir -p "$(dirname "$LOG_FILE")"
    chmod 755 "$(dirname "$LOG_FILE")"
fi

# Check that config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    log "ERROR: Config file not found at $CONFIG_FILE"
    
    # Try to recover by creating default config
    log "Attempting to create default config file..."
    mkdir -p "$(dirname "$CONFIG_FILE")"
    cat > "$CONFIG_FILE" << EOF
{
    "api_token": "$API_TOKEN",
    "api_base_url": "https://app.pulseguard.nl/api",
    "check_interval": 60,
    "metrics_enabled": true,
    "services_monitoring": true
}
EOF
    chmod 644 "$CONFIG_FILE"
    
    if [ ! -f "$CONFIG_FILE" ]; then
        log "Failed to create config file. Agent cannot continue."
        exit 1
    else
        log "Created default config file."
    fi
fi

API_TOKEN=$(get_config_value "api_token")
API_BASE_URL=$(get_config_value "api_base_url")
CHECK_INTERVAL=$(get_config_value "check_interval")

log "Agent Configuration:"
log "  API URL: $API_BASE_URL"
log "  API Token: ${API_TOKEN:0:8}...${API_TOKEN:(-8)}" # Show only first/last 8 chars for security
log "  Check Interval: $CHECK_INTERVAL seconds"

# Test API connection before starting
if ! test_api_connection; then
    log "WARNING: Initial API connection test failed. Will continue trying, but check your API token and URL."
    
    # Try to reach the server via IP directly
    log "Attempting to reach server via direct IP..."
    if ping -c 3 94.228.203.142 &>/dev/null; then
        log "Can reach server IP. This may be a DNS issue."
    else
        log "Cannot reach server IP. This may be a network connectivity issue."
    fi
fi

if [ -z "$CHECK_INTERVAL" ]; then
    CHECK_INTERVAL=60
    log "Check interval not found in config, using default: $CHECK_INTERVAL seconds"
fi

log "Agent started. Sending metrics every $CHECK_INTERVAL seconds."

# Initialize variables for update checking
LAST_UPDATE_CHECK=0
UPDATE_CHECK_INTERVAL=3600 # Check for updates every hour (in seconds)

while true; do
    # Collect metrics
    collect_metrics
    
    # Check for updates periodically
    CURRENT_TIME=$(date +%s)
    if [ $((CURRENT_TIME - LAST_UPDATE_CHECK)) -ge $UPDATE_CHECK_INTERVAL ]; then
        check_for_updates
        LAST_UPDATE_CHECK=$CURRENT_TIME
    fi
    
    sleep $CHECK_INTERVAL
done
EOL

chmod +x $INSTALL_DIR/pulseguard-agent

# Save device information to env file
echo -e "\e[33mSaving device information...\e[0m"
mkdir -p $INSTALL_DIR
cat > $INSTALL_DIR/env << EOL
DEVICE_UUID=$DEVICE_UUID
API_TOKEN=$API_TOKEN
EOL
chmod 600 $INSTALL_DIR/env

# Create systemd service
echo -e "\e[33mCreating systemd service...\e[0m"
cat > /etc/systemd/system/pulseguard-agent.service << EOL
[Unit]
Description=PulseGuard Agent Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/pulseguard/pulseguard-agent
WorkingDirectory=/opt/pulseguard
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pulseguard-agent
User=root
Environment="API_TOKEN=$API_TOKEN"
Environment="DEVICE_UUID=$DEVICE_UUID"

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start service
echo -e "\e[33mEnabling and starting service...\e[0m"
systemctl daemon-reload
systemctl enable pulseguard-agent
systemctl restart pulseguard-agent

# Check if service is running
if systemctl is-active --quiet pulseguard-agent; then
    echo -e "\e[32mPulseGuard Agent service installed and running successfully!\e[0m"
    echo -e "\e[32mInstallation complete. The agent will now begin reporting system metrics.\e[0m"
    echo -e "\e[33mTo check logs: sudo journalctl -u pulseguard-agent -f\e[0m"
    echo -e "\e[33mDetailed logs: sudo cat /opt/pulseguard/logs/agent.log\e[0m"
else
    echo -e "\e[33mService installation completed, but the service is not running.\e[0m"
    echo -e "\e[33mCheck the logs with: sudo journalctl -u pulseguard-agent\e[0m"
    echo -e "\e[33mAlso check the agent logs: sudo cat /opt/pulseguard/logs/agent.log\e[0m"
fi

echo ""
echo -e "\e[36mFor support, visit https://pulseguard.io/support\e[0m" 