#!/bin/bash
# PulseGuard Agent Installation Script for Linux
# ------------------------------------------------

# Fix for Windows line endings (CRLF)
if grep -q $'\r' "$0"; then
    echo "Detected Windows line endings (CRLF). Converting to Unix format (LF)..."
    TMP_FILE=$(mktemp)
    sed 's/\r$//' "$0" > "$TMP_FILE"
    chmod +x "$TMP_FILE"
    exec "$TMP_FILE" "$@"
fi

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

echo -e "\\e[34mPulseGuard Agent Installation\\e[0m"
echo -e "\\e[34m=========================\\e[0m"
echo ""
echo -e "\\e[32mDevice UUID: $DEVICE_UUID\\e[0m"
echo -e "\\e[32mAPI URL: $API_BASE_URL\\e[0m"
echo -e "\\e[32mAgent Version: $AGENT_VERSION\\e[0m"
echo -e "\\e[32mCheck Interval: ${CHECK_INTERVAL} seconds\\e[0m"
echo ""

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\\e[31mThis script must be run as root or with sudo.\\e[0m"
    exit 1
fi

# Check for curl
if ! command -v curl &> /dev/null; then
    echo -e "\\e[33mInstalling curl, which is required for the agent...\\e[0m"
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y curl
    elif command -v yum &> /dev/null; then
        yum install -y curl
    else
        echo -e "\\e[31mCould not install curl. Please install it manually and run the script again.\\e[0m"
        exit 1
    fi
fi

# Installation directory
INSTALL_DIR="/opt/pulseguard"
echo -e "\\e[33mCreating installation directories...\\e[0m"
mkdir -p $INSTALL_DIR
mkdir -p $INSTALL_DIR/logs
touch $INSTALL_DIR/logs/agent.log
chmod -R 755 $INSTALL_DIR
chmod 644 $INSTALL_DIR/logs/agent.log

# Create config file
echo -e "\\e[33mCreating configuration file...\\e[0m"
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
    echo -e "\\e[31mFailed to create config file. Check permissions and disk space.\\e[0m"
    exit 1
fi

chmod 644 $INSTALL_DIR/config.json
echo -e "\\e[32mConfiguration file created successfully.\\e[0m"

# Test network connectivity to the API server
echo -e "\\e[33mTesting network connectivity...\\e[0m"
API_HOST=$(echo "$API_BASE_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
if ping -c 1 $API_HOST &> /dev/null; then
    echo -e "\\e[32mNetwork connectivity test successful.\\e[0m"
else
    echo -e "\\e[31mWarning: Unable to ping $API_HOST. This might affect agent connectivity.\\e[0m"
fi

# Create the agent script
echo -e "\\e[33mCreating agent script...\\e[0m"
cat > $INSTALL_DIR/pulseguard-agent << 'EOL'
#!/bin/bash
# PulseGuard Agent for Linux
# ----------------------------
# Version information
AGENT_VERSION="1.0.0"
EXPRESS_PORT=3001
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
    
    if ! command -v jq &> /dev/null; then
        log_debug "jq is not available for parsing config. Using grep/sed fallback."
        # Improved fallback using grep/sed if jq is not available
        local value=$(grep -oP "\"$key\"[[:space:]]*:[[:space:]]*\"\\K[^\"]*" "$CONFIG_FILE")
        if [ -n "$value" ]; then
            echo "$value"
            return 0
        elif [ "$key" = "api_base_url" ]; then # Default for api_base_url
            log_debug "Could not extract api_base_url with grep, using default"
            echo "https://app.pulseguard.nl/api"
            return 0
        elif [ "$key" = "check_interval" ]; then # Default for check_interval
            log_debug "Could not extract check_interval with grep, using default 60"
            echo "60"
            return 0
        fi
    else
        # Use jq if available
        local value=$(jq -r ".$key // empty" "$CONFIG_FILE")
        if [ -n "$value" ] && [ "$value" != "null" ]; then
            echo "$value"
            return 0
        elif [ "$key" = "api_base_url" ]; then # Default for api_base_url
            log_debug "Could not extract api_base_url with jq, using default"
            echo "https://app.pulseguard.nl/api"
            return 0
        elif [ "$key" = "check_interval" ]; then # Default for check_interval
            log_debug "Could not extract check_interval with jq, using default 60"
            echo "60"
            return 0
        fi
    fi
    
    log_debug "Could not extract $key from config file"
    return 1
}

function execute_power_command() {
    local action="$1"
    log "Executing power command: $action"
    
    local restart_cmd="shutdown -r now"
    local shutdown_cmd="shutdown -h now"
    local sleep_cmd="systemctl suspend"
    local hibernate_cmd="systemctl hibernate"
    
    # Attempt to find a suitable lock command
    local lock_cmd=""
    if command -v loginctl &>/dev/null; then
        lock_cmd="loginctl lock-session"
    elif command -v gnome-screensaver-command &>/dev/null; then
        lock_cmd="gnome-screensaver-command -l"
    elif command -v dm-tool &>/dev/null; then
        lock_cmd="dm-tool lock"
    elif command -v mate-screensaver-command &>/dev/null; then
        lock_cmd="mate-screensaver-command -l"
    elif command -v cinnamon-screensaver-command &>/dev/null; then
        lock_cmd="cinnamon-screensaver-command -l"
    elif command -v xdg-screensaver &>/dev/null; then
        lock_cmd="xdg-screensaver lock"
    elif command -v xset &>/dev/null && [ -n "$DISPLAY" ]; then
        lock_cmd="xset s activate"
    else
        log "No suitable lock command found. Lock functionality may not work."
    fi

    case "$action" in
        "restart")
            log "Executing system restart command: $restart_cmd"
            eval "$restart_cmd"
            ;;
        "shutdown")
            log "Executing system shutdown command: $shutdown_cmd"
            eval "$shutdown_cmd"
            ;;
        "sleep")
            if command -v systemctl &>/dev/null && [[ "$(systemctl is-system-running)" =~ (running|degraded) ]]; then
                log "Executing system sleep command: $sleep_cmd"
                eval "$sleep_cmd"
            else
                log "systemctl suspend not available or system not in a suspendable state."
                return 1
            fi
            ;;
        "hibernate")
            if command -v systemctl &>/dev/null && [[ "$(systemctl is-system-running)" =~ (running|degraded) ]]; then
                log "Executing system hibernate command: $hibernate_cmd"
                eval "$hibernate_cmd"
            else
                log "systemctl hibernate not available or system not in a hibernatable state."
                return 1
            fi
            ;;
        "lock")
            if [ -n "$lock_cmd" ]; then
                log "Executing screen lock command: $lock_cmd"
                eval "$lock_cmd"
            else
                log "ERROR: Screen lock command not found."
                return 1
            fi
            ;;
        *)
            log "ERROR: Unknown power command: $action"
            return 1
            ;;
    esac
    return 0
}

function get_cpu_usage() {
    if command -v mpstat &> /dev/null; then
        mpstat 1 1 | grep -A 5 "CPU" | tail -n 1 | awk '{print 100 - $12}'
    else
        local stat_file="/proc/stat"
        local line1_before=$(grep "^cpu " "$stat_file")
        sleep 0.5
        local line1_after=$(grep "^cpu " "$stat_file")

        local user_before=$(echo "$line1_before" | awk '{print $2}')
        local nice_before=$(echo "$line1_before" | awk '{print $3}')
        local system_before=$(echo "$line1_before" | awk '{print $4}')
        local idle_before=$(echo "$line1_before" | awk '{print $5}')
        local iowait_before=$(echo "$line1_before" | awk '{print $6}')
        local irq_before=$(echo "$line1_before" | awk '{print $7}')
        local softirq_before=$(echo "$line1_before" | awk '{print $8}')

        local user_after=$(echo "$line1_after" | awk '{print $2}')
        local nice_after=$(echo "$line1_after" | awk '{print $3}')
        local system_after=$(echo "$line1_after" | awk '{print $4}')
        local idle_after=$(echo "$line1_after" | awk '{print $5}')
        local iowait_after=$(echo "$line1_after" | awk '{print $6}')
        local irq_after=$(echo "$line1_after" | awk '{print $7}')
        local softirq_after=$(echo "$line1_after" | awk '{print $8}')

        local total_before=$((user_before + nice_before + system_before + idle_before + iowait_before + irq_before + softirq_before))
        local total_after=$((user_after + nice_after + system_after + idle_after + iowait_after + irq_after + softirq_after))

        local total_delta=$((total_after - total_before))
        local idle_delta=$((idle_after - idle_before))
        
        if [ $total_delta -eq 0 ]; then
            echo "0"
        else
            local usage=$(( ( (total_delta - idle_delta) * 100) / total_delta ))
            echo "$usage"
        fi
    fi
}

function get_memory_usage() {
    free | grep Mem | awk '{printf "%.2f", $3/$2 * 100}'
}

function get_disk_usage() {
    df -P / | grep / | awk '{print $5}' | tr -d '%'
}

function get_uptime_seconds() {
    cat /proc/uptime | awk '{print $1}' | cut -d. -f1
}

function check_dns() {
    local domain=$1
    log_debug "Testing DNS resolution for $domain"
    if host "$domain" &>/dev/null; then
        log_debug "DNS resolution successful for $domain"
        return 0
    else
        log_debug "DNS resolution failed for $domain"
        return 1
    fi
}

function test_api_connection() {
    local api_token_val=$(get_config_value "api_token")
    local api_base_url_val=$(get_config_value "api_base_url")

    if [ -z "$api_token_val" ] || [ -z "$api_base_url_val" ]; then
        log "ERROR: API token or base URL missing in config for API test."
        return 1
    fi
    
    if [[ ! $api_base_url_val =~ ^https?:// ]]; then
        log "ERROR: API URL format is invalid: $api_base_url_val"
        return 1
    fi
    
    local api_host=$(echo "$api_base_url_val" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
    log_debug "Extracted API host: $api_host"
    
    if ! check_dns "$api_host"; then
        log "WARNING: Cannot resolve hostname $api_host. Check your network/DNS configuration."
    fi
    
    local config_url="$api_base_url_val/devices/config"
    
    log "Testing API connection to $config_url..."
    log_debug "Sending curl request to $config_url"
    
    local curl_output_file=$(mktemp)
    # Use -L to follow redirects, ensure API token is correctly passed.
    local http_code=$(curl -L -s -o "$curl_output_file" -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $api_token_val" \
        "$config_url" 2>&1)
    
    if [ "$http_code" == "200" ]; then
        log "API connection successful (HTTP 200)"
        rm -f "$curl_output_file"
        return 0
    else 
        log "API connection failed (HTTP $http_code)"
        log_debug "Response from $config_url: $(cat "$curl_output_file")"
        
        if command -v ping &> /dev/null; then
            log_debug "Ping test to $api_host:"
            ping -c 3 "$api_host" >> $LOG_FILE 2>&1 # Quoted api_host
        fi
        
        if command -v traceroute &> /dev/null; then
            log_debug "Traceroute to $api_host:"
            traceroute "$api_host" >> $LOG_FILE 2>&1 # Quoted api_host
        fi
        
        rm -f "$curl_output_file"
        return 1
    fi
}

function check_for_updates() {
    local api_token_val=$(get_config_value "api_token")
    local api_base_url_val=$(get_config_value "api_base_url")
    
    if [ -z "$api_token_val" ] || [ -z "$api_base_url_val" ]; then
        log "ERROR: Missing API token or base URL in configuration for update check."
        return 1
    fi
    
    local update_check_url="$api_base_url_val/devices/check-for-updates"
    
    log "Checking for agent updates..."
    
    local payload="{\"current_version\":\"$AGENT_VERSION\",\"os_type\":\"linux\"}"
    
    local curl_output_file=$(mktemp)
    local http_code=$(curl -L -s -o "$curl_output_file" -w "%{http_code}" \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $api_token_val" \
        -d "$payload" \
        "$update_check_url" 2>&1)
    
    if [ "$http_code" == "200" ]; then
        if ! command -v jq &> /dev/null; then
            log "WARNING: jq not found. Update parsing might be unreliable."
            # Basic grep parsing as fallback
            local update_available_grep=$(grep -o "\"update_available\":true" "$curl_output_file")
            if [[ -n "$update_available_grep" ]]; then UPDATE_AVAILABLE="true"; else UPDATE_AVAILABLE="false"; fi
        else
            local update_available=$(jq -r '.update_available // false' "$curl_output_file")
        fi

        if [ "$update_available" == "true" ]; then
            if ! command -v jq &> /dev/null; then
                local latest_version=$(grep -oP "\"latest_version\":\"\\K[^\"]*" "$curl_output_file")
                local update_url_resp=$(grep -oP "\"update_url\":\"\\K[^\"}]*" "$curl_output_file")
            else
                local latest_version=$(jq -r '.latest_version // empty' "$curl_output_file")
                local update_url_resp=$(jq -r '.update_url // empty' "$curl_output_file")
            fi
            log "Update available! Current: $AGENT_VERSION, Latest: $latest_version"
            
            if command -v jq &> /dev/null; then
                jq -r '.update_notes // {}' "$curl_output_file" >> $LOG_FILE
            else
                grep -o "\"update_notes\":{[^}]*}" "$curl_output_file" | sed 's/"update_notes"://' >> $LOG_FILE
            fi

            if [ -n "$update_url_resp" ]; then
                log "Starting self-update process..."
                self_update "$update_url_resp"
            fi
        else
            log "Agent is up to date (version $AGENT_VERSION)"
        fi
    else 
        log "Error checking for updates: HTTP $http_code"
        log_debug "Response: $(cat "$curl_output_file")"
    fi
    
    rm -f "$curl_output_file"
}

function self_update() {
    local update_download_url="$1"
    
    mkdir -p "$UPDATE_DIR"
    local temp_file="$UPDATE_DIR/new-agent.sh"
    
    log "Downloading update from $update_download_url..."
    if curl -s -L -o "$temp_file" "$update_download_url"; then
        if [ ! -s "$temp_file" ]; then
            log "ERROR: Failed to download update: File is empty or missing from $update_download_url"
            rm -f "$temp_file"
            return 1
        fi
        
        chmod +x "$temp_file"
        
        local update_script_path="$UPDATE_DIR/perform_update.sh" # Changed name for clarity
        cat > "$update_script_path" << EOF
#!/bin/bash
# PulseGuard Update Script

SELF_LOG_FILE="/opt/pulseguard/logs/update.log"
SOURCE_AGENT_FILE="$temp_file"
TARGET_AGENT_FILE="/opt/pulseguard/pulseguard-agent"

function write_to_log() {
    local current_timestamp=$(date)
    echo "$current_timestamp: [UPDATE] $1" >> "$SELF_LOG_FILE"
}

mkdir -p "$(dirname "$SELF_LOG_FILE")"
touch "$SELF_LOG_FILE"
chmod 644 "$SELF_LOG_FILE"

write_to_log "Update script started. Waiting for main agent to exit..."
sleep 5 # Wait for original process to exit

write_to_log "Attempting to replace agent file: $SOURCE_AGENT_FILE -> $TARGET_AGENT_FILE"
if cp "$SOURCE_AGENT_FILE" "$TARGET_AGENT_FILE"; then
    write_to_log "Agent file updated successfully."
    rm -f "$SOURCE_AGENT_FILE" # Clean up downloaded file
    
    write_to_log "Restarting agent service..."
    if command -v systemctl &> /dev/null && systemctl is-active --quiet pulseguard-agent.service; then
        if systemctl restart pulseguard-agent.service; then
            write_to_log "Agent service restarted via systemctl."
        else
            write_to_log "Failed to restart agent via systemctl. Exit code: $?"
        fi
    elif command -v service &> /dev/null; then
        if service pulseguard-agent restart; then
            write_to_log "Agent service restarted via service command."
        else
            write_to_log "Failed to restart agent via service command. Exit code: $?"
        fi
else
        write_to_log "Could not automatically restart service. Please restart pulseguard-agent manually."
    fi
    write_to_log "Update completed successfully! Exiting update script."
    exit 0
else
    write_to_log "ERROR: Failed to copy $SOURCE_AGENT_FILE to $TARGET_AGENT_FILE. Update failed."
    exit 1
fi
EOF
        
        chmod +x "$update_script_path"
        
        log "Executing update script $update_script_path in background..."
        nohup "$update_script_path" > /dev/null 2>&1 &
        
        log "Update scheduled. Agent will exit to allow update script to run."
        sleep 2 # Give nohup a moment to detach
        exit 0 # Exit current agent to allow replacement
    else
        log "ERROR: Failed to download update from $update_download_url (curl command failed)"
    fi
}

function collect_metrics() {
    local cpu_usage_val=$(get_cpu_usage)
    local memory_usage_val=$(get_memory_usage)
    local disk_usage_val=$(get_disk_usage)
    local uptime_val=$(get_uptime_seconds)
    local hostname_val=$(hostname)
    local ip_addr_val=$(hostname -I | awk '{print $1}' || echo "127.0.0.1")
    local mac_addr_val=$(cat /sys/class/net/$(ip route show default | awk '/default/ {print $5}')/address 2>/dev/null || echo "00:00:00:00:00:00")
    
    local os_type_val="unknown"
    local os_version_val="unknown"
    if [ -f /etc/os-release ]; then
        os_type_val=$(grep "^ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
        os_version_val=$(grep "^VERSION_ID=" /etc/os-release | cut -d= -f2 | tr -d '"')
    fi
    
    # Get API configuration first
    local api_token_val=$(get_config_value "api_token")
    local api_base_url_val=$(get_config_value "api_base_url")
    
    if [ -z "$api_token_val" ] || [ -z "$api_base_url_val" ]; then
        log "ERROR: API token or base URL missing in config. Cannot send metrics."
        return 1
    fi
    
    log_debug "API Token (masked): ${api_token_val:0:5}..."
    
    # Create payload in the format expected by the API (metrics at top level, not nested)
    local data_payload="{\"token\":\"$api_token_val\",\"hostname\":\"$hostname_val\",\"cpu_usage\":$cpu_usage_val,\"memory_usage\":$memory_usage_val,\"disk_usage\":$disk_usage_val,\"uptime_seconds\":$uptime_val,\"ip_address\":\"$ip_addr_val\",\"os_version\":\"$os_version_val\",\"os_type\":\"linux\"}"
    
    local checkin_url_val="$api_base_url_val/devices/check-in"
    
    log_debug "Sending metrics payload: $data_payload"
    log_debug "Sending to URL: $checkin_url_val"
    
    local curl_output_file=$(mktemp)
    local http_code=$(curl -L -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-API-Token: $api_token_val" \
        -d "$data_payload" \
        -w "\nHTTP_STATUS:%{http_code}" \
        "$checkin_url_val" -o "$curl_output_file")
    
    local response_body=$(cat "$curl_output_file")
    rm -f "$curl_output_file"
    
    if [ "$http_code" == "200" ]; then
        log "Sent metrics: HTTP 200 - Success"
        log_debug "Response: $response_body"
        
        # Debug: Log power command detection
        if echo "$response_body" | grep -q "power_command"; then
            log_debug "Power command detected in response"
        else
            log_debug "No power command in response"
        fi
        
        if command -v jq &> /dev/null; then
            local new_check_interval_val=$(echo "$response_body" | jq -r '.config.check_interval // empty')
            local power_command_val=$(echo "$response_body" | jq -r '.power_command.action // .power_command // empty')
        else # Fallback if jq is not available
            log_debug "jq not found, using grep for response parsing."
            local new_check_interval_val=$(echo "$response_body" | grep -oP "\"check_interval\"[[:space:]]*:[[:space:]]*[0-9]+" | grep -oP "[0-9]+" | head -n1)
            local power_command_val=$(echo "$response_body" | grep -oP "\"action\"[[:space:]]*:[[:space:]]*\"\\K[^\"]*" | head -n1)
            if [ -z "$power_command_val" ]; then
                # Fallback for direct power_command string
                power_command_val=$(echo "$response_body" | grep -oP "\"power_command\"[[:space:]]*:[[:space:]]*\"\\K[^\"]*" | head -n1)
            fi
        fi

        if [ -n "$new_check_interval_val" ] && [ "$new_check_interval_val" != "null" ] && [[ "$new_check_interval_val" =~ ^[0-9]+$ ]]; then
            if [ "$new_check_interval_val" -ne "$CHECK_INTERVAL" ]; then # Use global CHECK_INTERVAL for comparison
                log "Updating check interval from $CHECK_INTERVAL to $new_check_interval_val seconds"
                CHECK_INTERVAL=$new_check_interval_val # Update global CHECK_INTERVAL
                # Update the config file safely with jq if available, otherwise sed
                if command -v jq &> /dev/null; then
                    jq --argjson interval "$new_check_interval_val" '.check_interval = $interval' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                else 
                    sed -i "s/\"check_interval\":[[:space:]]*[0-9]*/\"check_interval\": $new_check_interval_val/" "$CONFIG_FILE"
            fi
            fi
        fi
        
        if [ -n "$power_command_val" ] && [ "$power_command_val" != "null" ] && [ "$power_command_val" != "empty" ]; then
            log "Received power command: $power_command_val"
            execute_power_command "$power_command_val"
        fi
    else
        log "Failed to send metrics: HTTP $http_code"
        log_debug "Error Response: $response_body"
        log_debug "Request URL: $checkin_url_val"
        log_debug "Request Payload: $data_payload"
        log_debug "API Token (masked): ${api_token_val:0:5}..."
        
        if [ "$http_code" == "500" ]; then
            log "Detected server error (HTTP 500), trying with minimal payload..."
            local minimal_data_payload="{\"token\":\"$api_token_val\",\"hostname\":\"$hostname_val\",\"cpu_usage\":$cpu_usage_val,\"memory_usage\":$memory_usage_val,\"disk_usage\":$disk_usage_val,\"uptime_seconds\":$uptime_val,\"os_type\":\"linux\"}"
            
            local retry_curl_output_file=$(mktemp)
            local retry_http_code=$(curl -L -s -X POST \
                -H "Content-Type: application/json" \
                -H "X-API-Token: $api_token_val" \
                -d "$minimal_data_payload" \
                -w "\nHTTP_STATUS:%{http_code}" \
                "$checkin_url_val" -o "$retry_curl_output_file")
            
            local retry_response_body=$(cat "$retry_curl_output_file")
            rm -f "$retry_curl_output_file"

            if [ "$retry_http_code" == "200" ]; then
                log "Minimal payload succeeded (HTTP 200)"
                log_debug "Response: $retry_response_body"
                
                if command -v jq &> /dev/null; then
                    local new_check_interval_retry_val=$(echo "$retry_response_body" | jq -r '.config.check_interval // empty')
                    local power_command_retry_val=$(echo "$retry_response_body" | jq -r '.power_command.action // .power_command // empty')
                else
                    local new_check_interval_retry_val=$(echo "$retry_response_body" | grep -oP "\"check_interval\"[[:space:]]*:[[:space:]]*[0-9]+" | grep -oP "[0-9]+" | head -n1)
                    local power_command_retry_val=$(echo "$retry_response_body" | grep -oP "\"action\"[[:space:]]*:[[:space:]]*\"\\K[^\"]*" | head -n1)
                    if [ -z "$power_command_retry_val" ]; then
                        # Fallback for direct power_command string
                        power_command_retry_val=$(echo "$retry_response_body" | grep -oP "\"power_command\"[[:space:]]*:[[:space:]]*\"\\K[^\"]*" | head -n1)
                    fi
                fi

                if [ -n "$new_check_interval_retry_val" ] && [ "$new_check_interval_retry_val" != "null" ] && [[ "$new_check_interval_retry_val" =~ ^[0-9]+$ ]]; then
                    if [ "$new_check_interval_retry_val" -ne "$CHECK_INTERVAL" ]; then
                        log "Updating check interval from $CHECK_INTERVAL to $new_check_interval_retry_val seconds (after retry)"
                        CHECK_INTERVAL=$new_check_interval_retry_val
                        if command -v jq &> /dev/null; then
                            jq --argjson interval "$new_check_interval_retry_val" '.check_interval = $interval' "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
                        else
                            sed -i "s/\"check_interval\":[[:space:]]*[0-9]*/\"check_interval\": $new_check_interval_retry_val/" "$CONFIG_FILE"
                    fi
                    fi
                fi
                
                if [ -n "$power_command_retry_val" ] && [ "$power_command_retry_val" != "null" ] && [ "$power_command_retry_val" != "empty" ]; then
                    log "Received power command (after retry): $power_command_retry_val"
                    execute_power_command "$power_command_retry_val"
                fi
            else
                log "Minimal payload also failed: HTTP $retry_http_code"
                log_debug "Response: $retry_response_body"
            fi
        fi
    fi
}

# Express Server Functions for SSH Commands
function start_express_server() {
    # Install Node.js if not available
    if ! command -v node &> /dev/null; then
        log "Installing Node.js for remote command server..."
        if command -v apt-get &> /dev/null; then
            curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
            apt-get install -y nodejs
        elif command -v yum &> /dev/null; then
            curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
            yum install -y nodejs npm
        else
            log "Could not install Node.js automatically. Remote commands will not be available."
            return 1
        fi
    fi
    
    # Create Express server script
    cat > /opt/pulseguard/express-server.js << 'NODEJS_EOF'
const express = require('express');
const cors = require('cors');
const { exec, spawn } = require('child_process');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// SSH Command execution function
async function executeSshCommand(command, params = {}) {
    try {
        switch (command) {
            case 'execute_shell':
                return await executeShellCommand(params.command, params.timeout || 30000);
            case 'get_processes':
                return await getProcessList(params.filter);
            case 'kill_process':
                return await killProcess(params.pid, params.force);
            case 'get_services':
                return await getServicesList(params.status);
            case 'control_service':
                return await controlService(params.name, params.action);
            case 'list_directory':
                return await listDirectory(params.path, params.recursive);
            case 'create_directory':
                return await createDirectory(params.path);
            case 'delete_file':
                return await deleteFile(params.path, params.force);
            case 'copy_file':
                return await copyFile(params.source, params.destination);
            case 'move_file':
                return await moveFile(params.source, params.destination);
            case 'read_file':
                return await readFile(params.path, params.lines);
            case 'write_file':
                return await writeFile(params.path, params.content, params.append);
            case 'get_file_info':
                return await getFileInfo(params.path);
            case 'network_ping':
                return await networkPing(params.host, params.count);
            case 'network_traceroute':
                return await networkTraceroute(params.host);
            case 'network_netstat':
                return await networkNetstat(params.filter);
            case 'get_disk_usage':
                return await getDiskUsage(params.path);
            case 'get_network_interfaces':
                return await getNetworkInterfaces();
            case 'get_system_logs':
                return await getSystemLogs(params.lines);
            case 'get_installed_software':
                return await getInstalledSoftware();
            case 'get_environment_variables':
                return await getEnvironmentVariables();
            case 'set_environment_variable':
                return await setEnvironmentVariable(params.name, params.value);
            case 'cleanup_temp':
                return await cleanupTempFiles();
            case 'system_scan':
                return await performSystemScan(params.type);
            case 'check_disk':
                return await checkDisk(params.device, params.fix);
            default:
                throw new Error(`Unknown SSH command: ${command}`);
        }
    } catch (error) {
        console.error(`SSH command error: ${error.message}`);
        throw error;
    }
}

// Helper function to execute shell commands
function executeShellCommand(command, timeout = 30000) {
    return new Promise((resolve, reject) => {
        const child = exec(command, { 
            timeout: timeout,
            maxBuffer: 1024 * 1024 * 10 // 10MB buffer
        }, (error, stdout, stderr) => {
            if (error) {
                if (error.killed) {
                    reject(new Error(`Command timed out after ${timeout}ms`));
                } else {
                    reject(new Error(`Command failed: ${error.message}`));
                }
                return;
            }
            
            resolve({
                success: true,
                stdout: stdout.trim(),
                stderr: stderr.trim(),
                exitCode: 0
            });
        });
        
        setTimeout(() => {
            child.kill();
            reject(new Error(`Command timed out after ${timeout}ms`));
        }, timeout);
    });
}

// Process Management
async function getProcessList(filter = null) {
    try {
        let command = 'ps aux --no-headers';
        if (filter) {
            command += ` | grep "${filter}"`;
        }
        command += ' | head -50'; // Limit results
        
        const result = await executeShellCommand(command);
        const lines = result.stdout.split('\n').filter(line => line.trim());
        
        const processes = lines.map(line => {
            const parts = line.trim().split(/\s+/);
            return {
                user: parts[0],
                pid: parts[1],
                cpu: parts[2],
                mem: parts[3],
                command: parts.slice(10).join(' ')
            };
        });
        
        return { success: true, processes };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function killProcess(pid, force = false) {
    try {
        const signal = force ? '-9' : '-15';
        await executeShellCommand(`kill ${signal} ${pid}`);
        return { success: true, message: `Process ${pid} terminated` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Service Management
async function getServicesList(status = null) {
    try {
        let command = 'systemctl list-units --type=service --no-pager --no-legend';
        if (status) {
            command += ` --state=${status}`;
        }
        
        const result = await executeShellCommand(command);
        const lines = result.stdout.split('\n').filter(line => line.trim());
        
        const services = lines.map(line => {
            const parts = line.trim().split(/\s+/);
            return {
                name: parts[0],
                loaded: parts[1],
                active: parts[2],
                running: parts[3],
                description: parts.slice(4).join(' ')
            };
        });
        
        return { success: true, services };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function controlService(serviceName, action) {
    try {
        let command;
        switch (action) {
            case 'start':
                command = `systemctl start ${serviceName}`;
                break;
            case 'stop':
                command = `systemctl stop ${serviceName}`;
                break;
            case 'restart':
                command = `systemctl restart ${serviceName}`;
                break;
            case 'enable':
                command = `systemctl enable ${serviceName}`;
                break;
            case 'disable':
                command = `systemctl disable ${serviceName}`;
                break;
            case 'status':
                command = `systemctl status ${serviceName}`;
                break;
            default:
                throw new Error(`Invalid service action: ${action}`);
        }
        
        const result = await executeShellCommand(command);
        return { 
            success: true, 
            message: `Service ${serviceName} ${action}ed successfully`,
            output: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// File Management
async function listDirectory(dirPath = '.', recursive = false) {
    try {
        let command = recursive ? `find "${dirPath}" -type f -o -type d` : `ls -la "${dirPath}"`;
        
        const result = await executeShellCommand(command);
        const lines = result.stdout.split('\n').filter(line => line.trim());
        
        if (recursive) {
            return { success: true, items: lines.map(path => ({ path })) };
        } else {
            const items = lines.slice(1).map(line => {
                const parts = line.trim().split(/\s+/);
                return {
                    permissions: parts[0],
                    size: parts[4],
                    name: parts.slice(8).join(' '),
                    type: parts[0].startsWith('d') ? 'directory' : 'file'
                };
            });
            return { success: true, items };
        }
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function createDirectory(dirPath) {
    try {
        await executeShellCommand(`mkdir -p "${dirPath}"`);
        return { success: true, message: `Directory created: ${dirPath}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function deleteFile(filePath, force = false) {
    try {
        const command = force ? `rm -rf "${filePath}"` : `rm "${filePath}"`;
        await executeShellCommand(command);
        return { success: true, message: `File/Directory deleted: ${filePath}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function copyFile(source, destination) {
    try {
        await executeShellCommand(`cp -r "${source}" "${destination}"`);
        return { success: true, message: `File copied from ${source} to ${destination}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function moveFile(source, destination) {
    try {
        await executeShellCommand(`mv "${source}" "${destination}"`);
        return { success: true, message: `File moved from ${source} to ${destination}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function readFile(filePath, lines = null) {
    try {
        let command = lines ? `head -n ${lines} "${filePath}"` : `cat "${filePath}"`;
        const result = await executeShellCommand(command);
        return {
            success: true,
            content: result.stdout,
            encoding: 'utf-8'
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function writeFile(filePath, content, append = false) {
    try {
        const operator = append ? '>>' : '>';
        await executeShellCommand(`echo "${content}" ${operator} "${filePath}"`);
        return { success: true, message: `File written: ${filePath}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getFileInfo(filePath) {
    try {
        const result = await executeShellCommand(`stat "${filePath}"`);
        return {
            success: true,
            fileInfo: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Network Functions
async function networkPing(host, count = 4) {
    try {
        const result = await executeShellCommand(`ping -c ${count} ${host}`);
        return {
            success: true,
            output: result.stdout,
            host: host,
            count: count
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function networkTraceroute(host) {
    try {
        const result = await executeShellCommand(`traceroute ${host}`);
        return {
            success: true,
            output: result.stdout,
            host: host
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function networkNetstat(filter = null) {
    try {
        let command = 'netstat -tuln';
        if (filter) {
            command += ` | grep ${filter}`;
        }
        
        const result = await executeShellCommand(command);
        return {
            success: true,
            output: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getNetworkInterfaces() {
    try {
        const result = await executeShellCommand('ip addr show');
        return {
            success: true,
            interfaces: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// System Information
async function getDiskUsage(path = '/') {
    try {
        const result = await executeShellCommand(`df -h ${path}`);
        return {
            success: true,
            output: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getSystemLogs(lines = 100) {
    try {
        const result = await executeShellCommand(`journalctl -n ${lines} --no-pager`);
        return {
            success: true,
            logs: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getInstalledSoftware() {
    try {
        let command;
        if (await executeShellCommand('which dpkg').then(() => true).catch(() => false)) {
            command = 'dpkg -l | grep ^ii';
        } else if (await executeShellCommand('which rpm').then(() => true).catch(() => false)) {
            command = 'rpm -qa';
        } else {
            throw new Error('No supported package manager found');
        }
        
        const result = await executeShellCommand(command);
        return {
            success: true,
            software: result.stdout
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getEnvironmentVariables() {
    try {
        const result = await executeShellCommand('env');
        const lines = result.stdout.split('\n').filter(line => line.includes('='));
        const variables = lines.map(line => {
            const [name, ...valueParts] = line.split('=');
            return { name, value: valueParts.join('=') };
        });
        
        return {
            success: true,
            variables: variables
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function setEnvironmentVariable(name, value) {
    try {
        await executeShellCommand(`export ${name}="${value}"`);
        return { success: true, message: `Environment variable ${name} set to ${value}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Maintenance Functions
async function cleanupTempFiles() {
    try {
        const commands = [
            'rm -rf /tmp/*',
            'rm -rf /var/tmp/*',
            'apt-get autoremove -y',
            'apt-get autoclean'
        ];
        
        const results = [];
        for (const cmd of commands) {
            try {
                const result = await executeShellCommand(cmd);
                results.push(result.stdout);
            } catch (error) {
                results.push(`Error: ${error.message}`);
            }
        }
        
        return {
            success: true,
            message: 'Temporary files cleanup completed',
            details: results
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function checkDisk(device = '/', fix = false) {
    try {
        const command = fix ? `fsck -y ${device}` : `fsck -n ${device}`;
        const result = await executeShellCommand(command);
        return {
            success: true,
            output: result.stdout,
            device: device
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function performSystemScan(type = 'basic') {
    try {
        let command;
        switch (type) {
            case 'security':
                command = 'rkhunter --check --sk';
                break;
            case 'memory':
                command = 'free -h && cat /proc/meminfo | head -20';
                break;
            case 'cpu':
                command = 'lscpu && cat /proc/cpuinfo | head -20';
                break;
            default:
                command = 'uname -a && uptime && df -h && free -h';
        }
        
        const result = await executeShellCommand(command);
        return {
            success: true,
            output: result.stdout,
            type: type
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// API Routes
app.get('/api/status', (req, res) => {
    res.json({
        status: 'running',
        version: '1.0.0',
        platform: 'linux',
        os_type: 'linux',
        uptime: process.uptime(),
        hostname: os.hostname(),
        network: {
            interfaces: Object.keys(os.networkInterfaces())
        },
        timestamp: new Date().toISOString()
    });
});

app.post('/api/ssh-command', async (req, res) => {
    try {
        const { command, params = {}, timeout = 30000 } = req.body;
        
        if (!command) {
            return res.status(400).json({
                success: false,
                error: 'Command is required'
            });
        }
        
        console.log(`Received SSH command: ${command} with params:`, params);
        
        const result = await executeSshCommand(command, params);
        
        res.json({
            success: true,
            result: result,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error(`SSH command error: ${error.message}`);
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

app.post('/api/terminal', async (req, res) => {
    try {
        const { command, workingDirectory } = req.body;
        
        if (!command) {
            return res.status(400).json({
                success: false,
                error: 'Command is required'
            });
        }
        
        let fullCommand = command;
        if (workingDirectory) {
            fullCommand = `cd "${workingDirectory}" && ${command}`;
        }
        
        const result = await executeShellCommand(fullCommand, 30000);
        
        res.json({
            success: true,
            output: result.stdout,
            error: result.stderr,
            exitCode: result.exitCode,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`PulseGuard Express server started on port ${PORT} (accessible from any IP)`);
});
NODEJS_EOF

    # Install required npm packages
    cd /opt/pulseguard
    cat > package.json << 'PACKAGE_EOF'
{
  "name": "pulseguard-linux-agent",
  "version": "1.0.0",
  "description": "PulseGuard Linux Agent Express Server",
  "main": "express-server.js",
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5"
  },
  "scripts": {
    "start": "node express-server.js"
  }
}
PACKAGE_EOF

    if command -v npm &> /dev/null; then
        npm install --production
        log "Express server dependencies installed"
        
        # Configure firewall to allow Express server port
        log "Configuring firewall for Express server port $EXPRESS_PORT..."
        if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
            ufw allow $EXPRESS_PORT/tcp
            log "Firewall (ufw) configured to allow port $EXPRESS_PORT"
        elif command -v firewall-cmd &> /dev/null; then
            firewall-cmd --permanent --add-port=$EXPRESS_PORT/tcp
            firewall-cmd --reload
            log "Firewall (firewalld) configured to allow port $EXPRESS_PORT"
        elif command -v iptables &> /dev/null; then
            iptables -A INPUT -p tcp --dport $EXPRESS_PORT -j ACCEPT
            if command -v iptables-save &> /dev/null; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || iptables-save > /etc/iptables.rules 2>/dev/null
                log "Firewall (iptables) configured to allow port $EXPRESS_PORT"
            else
                log "Warning: iptables rule added but might not persist after reboot"
            fi
        else
            log "No supported firewall detected, skipping firewall configuration"
        fi
        
        # Start Express server in background
        nohup node express-server.js > /opt/pulseguard/logs/express.log 2>&1 &
        EXPRESS_PID=$!
        echo $EXPRESS_PID > /opt/pulseguard/express.pid
        log "Express server started with PID: $EXPRESS_PID"
    else
        log "npm not available, remote commands will not work"
    fi
}

# --- Main Agent Logic ---
log "PulseGuard Agent starting... Version: $AGENT_VERSION"

# Ensure curl is installed (should be by install script, but double check)
if ! command -v curl &> /dev/null; then
    log "CRITICAL: curl is not installed. Agent cannot function. Please install curl and restart."
    exit 1
fi

# Ensure jq is installed (attempt to install if missing)
if ! command -v jq &> /dev/null; then
    log "INFO: jq is not installed. Attempting to install it as it improves config and response parsing."
    if command -v apt-get &> /dev/null; then
        apt-get update && apt-get install -y jq
    elif command -v yum &> /dev/null; then
        yum install -y jq
    else
        log "WARNING: Could not install jq automatically. Agent will use grep/sed for parsing, which might be less reliable."
    fi
    if ! command -v jq &> /dev/null; then
         log "ERROR: Failed to install jq. Parsing will rely on grep/sed."
    else
         log "INFO: jq installed successfully."
    fi
fi

# Ensure log directory exists
if [ ! -d "$(dirname "$LOG_FILE")" ]; then
    log "INFO: Log directory $(dirname "$LOG_FILE") not found. Creating it."
    mkdir -p "$(dirname "$LOG_FILE")"
    chmod 755 "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"
fi

# Load initial configuration for CHECK_INTERVAL
# Other config values like API_TOKEN and API_BASE_URL are read within functions that need them
INITIAL_CHECK_INTERVAL=$(get_config_value "check_interval")
if [[ "$INITIAL_CHECK_INTERVAL" =~ ^[0-9]+$ ]] && [ "$INITIAL_CHECK_INTERVAL" -gt 0 ]; then
    CHECK_INTERVAL=$INITIAL_CHECK_INTERVAL
    log "Initialized CHECK_INTERVAL from config: $CHECK_INTERVAL seconds."
else
    log "WARNING: Invalid or missing check_interval in config ($INITIAL_CHECK_INTERVAL). Using default: 60 seconds."
    CHECK_INTERVAL=60 # Default if not found or invalid in config
fi

# Log initial effective configuration (API token will be masked)
EFFECTIVE_API_TOKEN=$(get_config_value "api_token")
EFFECTIVE_API_BASE_URL=$(get_config_value "api_base_url")
log "Effective Agent Configuration Loaded:"
log "  API URL: $EFFECTIVE_API_BASE_URL"
log "  API Token: ${EFFECTIVE_API_TOKEN:0:5}..."
log "  Check Interval: $CHECK_INTERVAL seconds"

# Initial API connection test
if ! test_api_connection; then
    log "WARNING: Initial API connection test failed. The agent will continue to try, but please verify your API token, URL, and network connectivity."
    API_HOST_FOR_PING=$(echo "$EFFECTIVE_API_BASE_URL" | sed -E 's|^https?://||' | sed -E 's|/.*$||')
    IP_FOR_PING="94.228.203.142" # PulseGuard IP for direct test
    log "Attempting to ping $API_HOST_FOR_PING and $IP_FOR_PING..."
    if ping -c 1 "$API_HOST_FOR_PING" &>/dev/null; then
        log "Successfully pinged $API_HOST_FOR_PING. DNS resolution seems OK."
    else
        log "Failed to ping $API_HOST_FOR_PING. Possible DNS or network issue."
        if ping -c 1 "$IP_FOR_PING" &>/dev/null; then
            log "Successfully pinged $IP_FOR_PING. Direct IP connectivity is OK. This points to a DNS issue for $API_HOST_FOR_PING."
        else
            log "Failed to ping $IP_FOR_PING. Possible network connectivity issue preventing access to PulseGuard servers."
        fi
    fi
fi

log "Agent main loop started. Sending metrics every $CHECK_INTERVAL seconds."

# Start Express server for remote commands
start_express_server

LAST_METRICS_SEND_ATTEMPT=0
LAST_UPDATE_CHECK_TS=0 # Timestamp of last update check
UPDATE_CHECK_FREQUENCY_SECONDS=3600 # How often to check for updates (e.g., 1 hour)

# Function to cleanup on exit
cleanup() {
    log "Agent shutdown initiated, cleaning up..."
    
    # Stop Express server if running
    if [ -f /opt/pulseguard/express.pid ]; then
        EXPRESS_PID=$(cat /opt/pulseguard/express.pid)
        if kill -0 $EXPRESS_PID 2>/dev/null; then
            log "Stopping Express server (PID: $EXPRESS_PID)"
            kill $EXPRESS_PID
        fi
        rm -f /opt/pulseguard/express.pid
    fi
    
    log "Cleanup completed"
    exit 0
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT SIGQUIT

while true; do
    current_ts=$(date +%s)

    # Collect and send metrics
    # Ensure we don't send too frequently if interval is very short or on rapid restarts
    if [ $((current_ts - LAST_METRICS_SEND_ATTEMPT)) -ge $CHECK_INTERVAL ]; then
    collect_metrics
        LAST_METRICS_SEND_ATTEMPT=$current_ts
    fi
    
    # Check for updates periodically
    if [ $((current_ts - LAST_UPDATE_CHECK_TS)) -ge $UPDATE_CHECK_FREQUENCY_SECONDS ]; then
        log "Periodic update check due."
        check_for_updates
        LAST_UPDATE_CHECK_TS=$current_ts
    fi
    
    # Sleep for a short duration before re-evaluating, to prevent tight loop if CHECK_INTERVAL is 0 or very small
    # The main sleep will be based on CHECK_INTERVAL. This is just a safety for the loop itself.
    # Determine effective sleep duration. It should be CHECK_INTERVAL, but we consider the time already spent in the loop.
    time_spent_in_loop=$(( $(date +%s) - current_ts ))
    sleep_duration=$((CHECK_INTERVAL - time_spent_in_loop))
    if [ $sleep_duration -lt 1 ]; then
        sleep_duration=1 # Minimum sleep of 1s to avoid busy-looping if processing took too long
    fi
    
    log_debug "Loop finished. Sleeping for $sleep_duration seconds (effective interval: $CHECK_INTERVAL)."
    sleep $sleep_duration
done
EOL

chmod +x "$INSTALL_DIR/pulseguard-agent"

# Save device information to env file
echo -e "\\e[33mSaving device information...\\e[0m"
mkdir -p "$INSTALL_DIR"
cat > "$INSTALL_DIR/env" << EOL
DEVICE_UUID=$DEVICE_UUID
API_TOKEN=$API_TOKEN
EOL
chmod 600 "$INSTALL_DIR/env"

# Create systemd service
echo -e "\\e[33mCreating systemd service...\\e[0m"
cat > "/etc/systemd/system/pulseguard-agent.service" << EOL
[Unit]
Description=PulseGuard Agent Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env bash $INSTALL_DIR/pulseguard-agent
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=10
StandardOutput=append:/var/log/pulseguard-agent.log
StandardError=append:/var/log/pulseguard-agent.log
SyslogIdentifier=pulseguard-agent
User=root
# Pass necessary original parameters as environment variables to the script
# The script itself will read its config from config.json primarily
Environment="PULSEGUARD_DEVICE_UUID=$DEVICE_UUID"
Environment="PULSEGUARD_API_TOKEN=$API_TOKEN"
Environment="PULSEGUARD_OS_TYPE=linux"

[Install]
WantedBy=multi-user.target
EOL

# Create log file with proper permissions
touch /var/log/pulseguard-agent.log
chmod 644 /var/log/pulseguard-agent.log
chown root:root /var/log/pulseguard-agent.log

# Reload systemd, enable and start service
echo -e "\\e[33mEnabling and starting service...\\e[0m"
systemctl daemon-reload
systemctl enable pulseguard-agent.service # Added .service suffix
systemctl restart pulseguard-agent.service # Added .service suffix

# Check if service is running
if systemctl is-active --quiet pulseguard-agent.service; then
    echo -e "\\e[32mPulseGuard Agent service installed and running successfully!\\e[0m"
    echo -e "\\e[32mInstallation complete. The agent will now begin reporting system metrics.\\e[0m"
    echo -e "\\e[33mTo check logs: sudo journalctl -u pulseguard-agent.service -f\\e[0m"
    echo -e "\\e[33mDetailed logs: sudo cat /opt/pulseguard/logs/agent.log\\e[0m"
    
    # Verify Express server is running
    if [ -f /opt/pulseguard/express.pid ] && kill -0 $(cat /opt/pulseguard/express.pid) 2>/dev/null; then
        echo -e "\\e[32mRemote command server is running on port $EXPRESS_PORT\\e[0m"
        echo -e "\\e[33mTo test API: curl http://localhost:$EXPRESS_PORT/api/status\\e[0m"
    else
        echo -e "\\e[31mWarning: Express server for remote commands is not running.\\e[0m"
        echo -e "\\e[33mCheck logs at /opt/pulseguard/logs/express.log\\e[0m"
        echo -e "\\e[33mYou can try to start it manually: cd /opt/pulseguard && node express-server.js\\e[0m"
    fi
else
    echo -e "\\e[31mService installation completed, but the service is not running or failed to start.\\e[0m"
    echo -e "\\e[33mPlease check the logs for errors:\\e[0m"
    echo -e "\\e[33msudo journalctl -u pulseguard-agent.service -n 50 --no-pager\\e[0m"
    echo -e "\\e[33msudo cat /opt/pulseguard/logs/agent.log\\e[0m"
    echo -e "\\e[33mYou can try to start it manually with: sudo systemctl start pulseguard-agent.service\\e[0m"
    
    # Try to start the service again
    echo -e "\\e[33mAttempting to restart the service...\\e[0m"
    systemctl restart pulseguard-agent.service
    sleep 5
    
    if systemctl is-active --quiet pulseguard-agent.service; then
        echo -e "\\e[32mService successfully restarted!\\e[0m"
    else
        echo -e "\\e[31mService restart failed. Please check the logs.\\e[0m"
    fi
fi

echo ""
echo -e "\\e[36mFor support, visit https://pulseguard.io/support\\e[0m" 