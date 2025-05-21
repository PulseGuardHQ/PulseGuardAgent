param(
    [Parameter(Mandatory=$true)]
    [string]$DeviceUUID,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiToken
)

# Ensure TLS 1.2 is used
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# PulseGuard Agent Installation Script for Windows
# ------------------------------------------------

Write-Host "PulseGuard Agent Installation" -ForegroundColor Blue
Write-Host "=========================" -ForegroundColor Blue
Write-Host ""
Write-Host "Device UUID: $DeviceUUID" -ForegroundColor Green
Write-Host "Using API Token: $($ApiToken.Substring(0,[Math]::Min(8, $ApiToken.Length)))...$($ApiToken.Substring([Math]::Max(0, $ApiToken.Length-8)))" -ForegroundColor Green
Write-Host ""

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script needs to be run as Administrator. Please restart with elevated privileges." -ForegroundColor Red
    Write-Host "Right-click on the script and select 'Run as Administrator'"
    Exit 1
}

# Define variables
$installDir = "C:\Program Files\PulseGuard"
$logsDir = "$installDir\logs"
$agentScript = "$installDir\pulseguard-agent.ps1"
$apiBaseUrl = "https://app.pulseguard.nl/api"
$serviceConfigPath = "$installDir\service-config.xml"
$agentVersion = "1.0.0" # Initial version

# Create installation directory
if (-not (Test-Path $installDir)) {
    Write-Host "Creating installation directory..." -ForegroundColor Yellow
    try {
        New-Item -Path $installDir -ItemType Directory -Force | Out-Null
        New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
    }
    catch {
        Write-Host "Error creating directories: $($_.Exception.Message)" -ForegroundColor Red
        Exit 1
    }
}

# Create config file using provided parameters
Write-Host "Creating configuration file..." -ForegroundColor Yellow
$config = @{
    "api_token" = $ApiToken 
    "api_base_url" = $apiBaseUrl
    "check_interval" = 5 # Fast metrics check-in every 5 seconds
    "full_check_interval" = 86400 # Full system info once per day (in seconds)
    "metrics_enabled" = $true
    "services_monitoring" = $true
}

try {
    $configJson = ConvertTo-Json $config
    Set-Content -Path "$installDir\config.json" -Value $configJson -Force
    Write-Host "Configuration file created successfully." -ForegroundColor Green
}
catch {
    Write-Host "Error creating config file: $($_.Exception.Message)" -ForegroundColor Red
    Exit 1
}

# Test network connectivity
Write-Host "Testing network connectivity..." -ForegroundColor Yellow
$apiHost = $apiBaseUrl -replace "https?://", "" -replace "/.*$", ""
try {
    $pingTest = Test-NetConnection -ComputerName $apiHost -WarningAction SilentlyContinue
    if ($pingTest.PingSucceeded) {
        Write-Host "Network connectivity test successful." -ForegroundColor Green
    } else {
        Write-Host "Warning: Unable to ping $apiHost. This might affect agent connectivity." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Warning: Network connectivity test failed. This might affect agent connectivity." -ForegroundColor Yellow
}

# Create the PulseGuard Agent PowerShell script
Write-Host "Creating PulseGuard agent script..." -ForegroundColor Yellow

$agentContent = @'
# PulseGuard Agent for Windows
# ----------------------------

# Version information
$AGENT_VERSION = "1.0.0"

# Configuration and Paths
$logFile = "C:\\Program Files\\PulseGuard\\logs\\agent.log"
$configFile = "C:\\Program Files\\PulseGuard\\config.json"
$lastErrorFile = "C:\\Program Files\\PulseGuard\\logs\\last_error.txt"
$installDir = "C:\\Program Files\\PulseGuard"
$updateDir = "C:\\Program Files\\PulseGuard\\update"
$updateScript = "$installDir\\update-agent.ps1"

# Create log directory if it doesn't exist
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -ItemType Directory -Path (Split-Path $logFile) -Force | Out-Null
}

# Initial log entry to confirm script start
try {
    Add-Content -Path $logFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INIT] Agent script started. Version: $AGENT_VERSION" -ErrorAction Stop
} catch {
    $initErrorMsg = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INIT_ERROR] Failed to write initial log: $($_.Exception.Message)"
    try { Add-Content -Path $lastErrorFile -Value $initErrorMsg -ErrorAction SilentlyContinue } catch {}
}

# Helper Functions
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $logFile -Value $logMessage
    
    # Output to console if not running as a service
    if ($Host.Name -ne "Default Host") {
        Write-Host $logMessage
    }
}

function Write-Debug {
    param (
        [string]$Message
    )
    
    Write-Log -Message $Message -Level "DEBUG"
}

function Get-ConfigValue {
    param (
        [string]$Key
    )
    
    try {
        if (-not (Test-Path $configFile)) {
            Write-Log "Config file not found at ${configFile}" -Level "ERROR"
            return $null
        }
        
        $config = Get-Content -Path $configFile -Raw | ConvertFrom-Json
        return $config.$Key
    }
    catch {
        Write-Log "Error reading config value ${Key}: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Test-ApiConnection {
    $apiToken = Get-ConfigValue -Key "api_token"
    $apiBaseUrl = Get-ConfigValue -Key "api_base_url"
    
    if (-not $apiToken -or -not $apiBaseUrl) {
        Write-Log "Missing API token or base URL in configuration" -Level "ERROR"
        return $false
    }
    
    $configUrl = "$apiBaseUrl/devices/config"
    
    Write-Log "Testing API connection to ${configUrl}..."
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Token" = $apiToken
        }
        
        $response = Invoke-RestMethod -Uri $configUrl -Headers $headers -Method Get -ErrorAction Stop
        Write-Log "API connection successful (HTTP 200)"
        return $true
    }
    catch {
        $statusCode = "Unknown"
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -ne $null) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        } elseif ($_.Exception.Response) {
            Write-Debug "API connection failed: Response received but StatusCode object is null."
            $statusCode = "Unknown (StatusCode missing)"
        } else {
            Write-Debug "API connection failed: No response object in exception."
            $statusCode = "Unknown (No Response)"
        }
        Write-Log "API connection failed (HTTP ${statusCode}): $($_.Exception.Message)" -Level "ERROR"
        
        # More detailed diagnostics
        $apiHostname = $apiBaseUrl -replace "https?://", "" -replace "/.*$", ""
        
        try {
            $resolveTest = Resolve-DnsName -Name $apiHostname -ErrorAction SilentlyContinue
            if ($resolveTest) {
                Write-Debug "DNS resolution for ${apiHostname} successful"
                Write-Debug "IP Address: $($resolveTest.IP4Address -join ', ')"
            }
            else {
                Write-Debug "DNS resolution failed for ${apiHostname}"
            }
        }
        catch {
            Write-Debug "Error in DNS resolution: $($_.Exception.Message)"
        }
        
        # Try ping
        try {
            $pingTest = Test-Connection -ComputerName $apiHostname -Count 2 -Quiet
            Write-Debug "Ping test to ${apiHostname}: ${pingTest}"
        }
        catch {
            Write-Debug "Error in ping test: $($_.Exception.Message)"
        }
        
        # Full error details
        $errorDetails = @"
API Connection Error Details:
URL: ${configUrl}
Status Code: ${statusCode}
Error Message: $($_.Exception.Message)
Stack Trace: $($_.ScriptStackTrace)
"@
        Set-Content -Path $lastErrorFile -Value $errorDetails
        
        return $false
    }
}

function Check-ForUpdates {
    $apiToken = Get-ConfigValue -Key "api_token"
    $apiBaseUrl = Get-ConfigValue -Key "api_base_url"
    
    if (-not $apiToken -or -not $apiBaseUrl) {
        Write-Log "Missing API token or base URL in configuration" -Level "ERROR"
        return
    }
    
    $updateUrl = "$apiBaseUrl/devices/check-for-updates"
    
    Write-Log "Checking for agent updates..."
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Token" = $apiToken
        }
        
        $payload = @{
            token = $apiToken
            current_version = $AGENT_VERSION
            os_type = "windows"
        } | ConvertTo-Json
        
        $response = Invoke-RestMethod -Uri $updateUrl -Headers $headers -Method Post -Body $payload -ErrorAction Stop
        
        if ($response.update_available) {
            Write-Log "Update available! Current: $AGENT_VERSION, Latest: $($response.latest_version)" -Level "INFO"
            
            # Log update notes
            Write-Log "Update notes:" -Level "INFO"
            foreach ($version in $response.update_notes.PSObject.Properties.Name) {
                Write-Log "  Version $version:" -Level "INFO"
                foreach ($note in $response.update_notes.$version) {
                    Write-Log "    - $note" -Level "INFO"
                }
            }
            
            # Initiate self-update
            if ($response.update_url) {
                Write-Log "Starting self-update process..." -Level "INFO"
                Self-Update -UpdateUrl $response.update_url
            }
        } else {
            Write-Log "Agent is up to date (version $AGENT_VERSION)"
        }
    }
    catch {
        $statusCode = "Unknown"
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -ne $null) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        }
        
        Write-Log "Error checking for updates: HTTP $statusCode" -Level "ERROR"
        Write-Debug "Error: $($_.Exception.Message)"
    }
}

function Self-Update {
    param (
        [string]$UpdateUrl
    )
    
    # Create update directory if it doesn't exist
    if (-not (Test-Path $updateDir)) {
        New-Item -ItemType Directory -Path $updateDir -Force | Out-Null
    }
    
    # Download the new version
    $tempFile = "$updateDir\new-agent.ps1"
    
    try {
        Write-Log "Downloading update from $UpdateUrl..." -Level "INFO"
        Invoke-WebRequest -Uri $UpdateUrl -OutFile $tempFile -ErrorAction Stop
        
        # Verify the downloaded file
        if (-not (Test-Path $tempFile) -or (Get-Item $tempFile).Length -eq 0) {
            Write-Log "Failed to download update: File is empty or missing" -Level "ERROR"
            return
        }
        
        # Create a self-updating script
        $updateContent = @"
# PulseGuard Update Script
$logFile = "C:\\Program Files\\PulseGuard\\logs\\update.log"
$sourceFile = "$tempFile"
$targetFile = "$agentScript"

function Write-UpdateLog($message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp [UPDATE] $message"
}

# Wait for original process to exit
Start-Sleep -Seconds 5

Write-UpdateLog "Starting update process..."

try {
    # Copy the new agent file
    Copy-Item -Path $sourceFile -Destination $targetFile -Force -ErrorAction Stop
    Write-UpdateLog "Agent file updated successfully"
    
    # Restart the service
    Write-UpdateLog "Restarting agent service..."
    schtasks /End /TN "\PulseGuard\PulseGuardAgent"
    Start-Sleep -Seconds 2
    schtasks /Run /TN "\PulseGuard\PulseGuardAgent"
    
    Write-UpdateLog "Update completed successfully!"
} catch {
    Write-UpdateLog "Error during update: $($_.Exception.Message)"
}
"@
        Set-Content -Path $updateScript -Value $updateContent -Force
        
        # Schedule the update task to run shortly
        Write-Log "Preparing to update agent in background..." -Level "INFO"
        Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$updateScript`"" -WindowStyle Hidden
        
        # Exit this script to allow the update script to replace the file
        Write-Log "Update scheduled. Agent will restart momentarily." -Level "INFO"
        Start-Sleep -Seconds 2
        exit
    }
    catch {
        Write-Log "Update failed: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Get-MemoryUsage {
    try {
        $os = Get-WmiObject Win32_OperatingSystem
        $totalMemory = $os.TotalVisibleMemorySize
        $freeMemory = $os.FreePhysicalMemory
        $usedMemory = $totalMemory - $freeMemory
        return [math]::Round(($usedMemory / $totalMemory) * 100, 2)
    }
    catch {
        Write-Debug "Error getting memory usage: $($_.Exception.Message)"
        return 0
    }
}

function Get-DiskUsage {
    try {
        # Get the system drive (usually C:)
        $systemDrive = $env:SystemDrive.TrimEnd(':') + ":"
        $drive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='$systemDrive'"
        
        # Calculate usage for system drive only - verify values before calculation
        $totalSpace = $drive.Size
        $freeSpace = $drive.FreeSpace
        
        # Validate that we got reasonable values
        if ($null -eq $totalSpace -or $totalSpace -eq 0) {
            Write-Debug "Invalid total disk space: $totalSpace. Using alternative method."
            # Try alternative method with Get-PSDrive
            try {
                $driveInfo = Get-PSDrive -Name $systemDrive.TrimEnd(':') -PSProvider FileSystem
                $totalSpace = $driveInfo.Used + $driveInfo.Free
                $freeSpace = $driveInfo.Free
            }
            catch {
                Write-Debug "Alternative disk calculation also failed: $($_.Exception.Message)"
                return 50 # Return a safe default value
            }
        }
        
        $usedSpace = $totalSpace - $freeSpace
        $usagePercent = [math]::Round(($usedSpace / $totalSpace) * 100, 2)
        
        # Sanity check the result
        if ($usagePercent -lt 0 -or $usagePercent -gt 100) {
            Write-Debug "Calculated disk usage out of range: $usagePercent%. Using capped value."
            $usagePercent = [math]::Min(95, [math]::Max(5, $usagePercent)) # Cap between 5% and 95%
        }
        
        # Log details for diagnostics
        Write-Debug "System Drive: $systemDrive"
        Write-Debug "Total Space: $([math]::Round($totalSpace/1GB, 2)) GB"
        Write-Debug "Free Space: $([math]::Round($freeSpace/1GB, 2)) GB"
        Write-Debug "Used Space: $([math]::Round($usedSpace/1GB, 2)) GB"
        Write-Debug "Usage Percent: $usagePercent%"
        
        return $usagePercent
    }
    catch {
        Write-Debug "Error getting disk usage: $($_.Exception.Message)"
        return 50 # Return a reasonable default if we can't calculate
    }
}

function Get-SystemUptime {
    try {
        $lastBootTime = (Get-WmiObject Win32_OperatingSystem).LastBootUpTime
        $uptime = (Get-Date) - [System.Management.ManagementDateTimeConverter]::ToDateTime($lastBootTime)
        return [math]::Round($uptime.TotalSeconds)
    }
    catch {
        Write-Debug "Error getting system uptime: $($_.Exception.Message)"
        # Fallback
        try {
            return [math]::Round((Get-Uptime).TotalSeconds)
        }
        catch {
            Write-Debug "Fallback uptime method failed: $($_.Exception.Message)"
            return 60 # Return a safe value
        }
    }
}

function Get-WindowsServices {
    try {
        $services = Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object -First 10 -Property DisplayName, Status
        $servicesList = @()
        
        foreach ($service in $services) {
            $servicesList += @{
                "name" = $service.DisplayName
                "status" = $service.Status.ToString()
            }
        }
        
        return $servicesList
    }
    catch {
        Write-Debug "Error getting Windows services: $($_.Exception.Message)"
        return @()
    }
}

# Reliable function to get MAC address - tries multiple approaches
function Get-ReliableMacAddress {
    $macAddress = $null
    $macSuccess = $false
    
    # Approach 1: Try Get-NetAdapter
    try {
        Write-Debug "Trying Get-NetAdapter to get MAC address"
        # First try active adapters
        $upAdapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
        
        if ($upAdapter) {
            $macAddress = $upAdapter.MacAddress
            $macSuccess = $true
            Write-Debug "Found active network adapter: $($upAdapter.Name) with MAC: $macAddress"
        } else {
            # Try any adapter
            $anyAdapter = Get-NetAdapter | Select-Object -First 1
            if ($anyAdapter) {
                $macAddress = $anyAdapter.MacAddress
                $macSuccess = $true
                Write-Debug "No active adapter found. Using adapter: $($anyAdapter.Name) with MAC: $macAddress"
            }
        }
    } catch {
        Write-Debug "Get-NetAdapter approach failed: $($_.Exception.Message)"
    }
    
    # Approach 2: Try WMI if we still don't have a MAC
    if (-not $macSuccess) {
        try {
            Write-Debug "Trying WMI to get MAC address"
            $wmiAdapter = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object -First 1
            if ($wmiAdapter -and $wmiAdapter.MACAddress) {
                $macAddress = $wmiAdapter.MACAddress
                $macSuccess = $true
                Write-Debug "Using WMI to get MAC address: $macAddress"
            }
        } catch {
            Write-Debug "WMI approach failed: $($_.Exception.Message)"
        }
    }
    
    # Approach 3: Try CIM as a last resort
    if (-not $macSuccess) {
        try {
            Write-Debug "Trying CIM to get MAC address"
            $cimAdapter = Get-CimInstance Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 } | Select-Object -First 1
            if ($cimAdapter -and $cimAdapter.MACAddress) {
                $macAddress = $cimAdapter.MACAddress
                $macSuccess = $true
                Write-Debug "Using CIM to get MAC address: $macAddress"
            }
        } catch {
            Write-Debug "CIM approach failed: $($_.Exception.Message)"
        }
    }
    
    # If all approaches failed, use a fallback value
    if (-not $macSuccess -or [string]::IsNullOrEmpty($macAddress)) {
        $macAddress = "AA:BB:CC:DD:EE:FF"
        Write-Debug "All approaches failed. Using fallback MAC: $macAddress"
    }
    
    # Ensure MAC has consistent format with colons (AA:BB:CC:DD:EE:FF)
    if ($macAddress -match "[0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}[-:][0-9A-Fa-f]{2}") {
        # If it has the right pattern but with hyphens, convert to colons
        $macAddress = $macAddress -replace '-', ':'
    } elseif ($macAddress -match "[0-9A-Fa-f]{12}") {
        # If it's 12 hex digits with no separators, add colons
        $macAddress = $macAddress -replace '(.{2})(.{2})(.{2})(.{2})(.{2})(.{2})', '$1:$2:$3:$4:$5:$6'
    }
    
    return $macAddress
}

# Create payload in exact format the API expects
function Create-ApiPayload {
    # Determine if we need to do a full check-in
    $needsFullUpdate = $false
    $lastFullCheckFile = "$installDir\last_full_check.txt"
    $currentTime = [int][double]::Parse($(Get-Date -UFormat %s))
    
    # Check if we have a record of the last full check-in
    if (-not (Test-Path $lastFullCheckFile)) {
        # First run, need a full update
        $needsFullUpdate = $true
        Write-Log "First run detected, performing full device check-in"
    }
    else {
        $lastFullCheck = [int]::Parse((Get-Content $lastFullCheckFile))
        $fullCheckInterval = Get-ConfigValue -Key "full_check_interval"
        
        # Default to daily if not specified
        if (-not $fullCheckInterval) {
            $fullCheckInterval = 86400
        }
        
        # Check if it's time for a full update
        if (($currentTime - $lastFullCheck) -ge $fullCheckInterval) {
            $needsFullUpdate = $true
            Write-Log "Time for full device check-in (last: $(Get-Date -Date (Get-Date "1970-01-01").AddSeconds($lastFullCheck)))"
        }
    }
    
    # Always collect basic metrics
    $metrics = @{
        "cpu_usage" = 0.0
        "memory_usage" = 0.0
        "disk_usage" = 0.0
        "uptime" = 0
    }
    
    try {
        # Match the expected data types in DeviceMetric model (floats and integer)
        $metrics.cpu_usage = [math]::Max(0, [math]::Min(100, [double](Get-CpuUsage)))
        $metrics.memory_usage = [math]::Max(0, [math]::Min(100, [double](Get-MemoryUsage)))
        $metrics.disk_usage = [math]::Max(0, [math]::Min(100, [double](Get-DiskUsage)))
        $metrics.uptime = [int][math]::Max(0, [double](Get-SystemUptime))
    } catch {
        Write-Debug "Error collecting metrics: $($_.Exception.Message)"
    }
    
    if ($needsFullUpdate) {
        # Get system information for full check-in
        $hostname = [System.Net.Dns]::GetHostName()
        
        # IP address - use loopback if we can't get a real one
        $ipAddress = "127.0.0.1"
        try {
            $ip = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress
            if (-not [string]::IsNullOrEmpty($ip)) {
                $ipAddress = $ip
            }
        } catch {
            Write-Debug "IP address detection failed: $($_.Exception.Message)"
        }
        
        # MAC address - use reliable function that tries multiple approaches
        $macAddress = Get-ReliableMacAddress
        
        # OS information
        $osInfo = Get-WmiObject Win32_OperatingSystem
        $osType = "windows"
        $osVersion = $osInfo.Version
        if ([string]::IsNullOrEmpty($osVersion)) {
            $osVersion = [Environment]::OSVersion.Version.ToString()
        }
        
        # System specs - match the exact format in Device model
        $systemSpecs = @{
            "cpu_cores" = 1
            "total_memory" = 1024
        }
        
        try {
            $cpuCores = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors
            if ($cpuCores -gt 0) {
                $systemSpecs.cpu_cores = $cpuCores
            }
            
            $totalMemory = [math]::Round($osInfo.TotalVisibleMemorySize / 1024)
            if ($totalMemory -gt 0) {
                $systemSpecs.total_memory = $totalMemory
            }
        } catch {
            Write-Debug "Error getting system specs: $($_.Exception.Message)"
        }
        
        # Services - must be an array even if empty (not null)
        $services = @()
        
        # Full payload matching exactly what API expects based on validation rules
        $payload = @{
            "hostname" = $hostname
            "ip_address" = $ipAddress
            "mac_address" = $macAddress
            "os_type" = $osType
            "os_version" = $osVersion
            "system_specs" = $systemSpecs
            "metrics" = $metrics
            "services" = $services
            "full_check_in" = $true
        }
        
        # Validate payload against the specific rules in DeviceApiController
        if ([string]::IsNullOrEmpty($payload.hostname)) { $payload.hostname = "unknown-host" }
        if ([string]::IsNullOrEmpty($payload.ip_address)) { $payload.ip_address = "127.0.0.1" }
        if ([string]::IsNullOrEmpty($payload.mac_address)) { $payload.mac_address = "AA:BB:CC:DD:EE:FF" }
        if ([string]::IsNullOrEmpty($payload.os_type)) { $payload.os_type = "windows" }
        if ([string]::IsNullOrEmpty($payload.os_version)) { $payload.os_version = "10.0" }
        
        Write-Debug "Sending full system information check-in"
    } else {
        # Metrics-only check-in with minimal payload
        $payload = @{
            "metrics" = $metrics
        }
        
        Write-Debug "Sending metrics-only check-in"
    }
    
    # Ensure data types match what the model expects
    $payload.metrics.cpu_usage = [double]$payload.metrics.cpu_usage
    $payload.metrics.memory_usage = [double]$payload.metrics.memory_usage
    $payload.metrics.disk_usage = [double]$payload.metrics.disk_usage
    $payload.metrics.uptime = [int]$payload.metrics.uptime
    
    return @{
        Payload = $payload
        IsFullUpdate = $needsFullUpdate
        LastFullCheckFile = $lastFullCheckFile
        CurrentTime = $currentTime
    }
}

function Collect-SystemMetrics {
    # Static variables for rate limiting
    if (-not $script:lastSendTime) {
        $script:lastSendTime = [DateTime]::MinValue
        $script:consecutiveFailures = 0
        $script:backoffTime = 0
    }
    
    # Get check interval for rate limiting
    $checkInterval = Get-ConfigValue -Key "check_interval"
    if (-not $checkInterval -or $checkInterval -eq 0) {
        $checkInterval = 5
    }
    
    # Calculate time since last send
    $now = Get-Date
    $timeSinceLastSend = ($now - $script:lastSendTime).TotalSeconds
    
    # Apply rate limiting and backoff
    if ($timeSinceLastSend -lt $script:backoffTime) {
        Write-Debug "Rate limiting in effect. Waiting for backoff period to expire. $([math]::Round($script:backoffTime - $timeSinceLastSend)) seconds remaining."
        return
    }
    
    # Create payload exactly matching API format
    $apiPayloadInfo = Create-ApiPayload
    $data = $apiPayloadInfo.Payload
    $isFullUpdate = $apiPayloadInfo.IsFullUpdate
    $lastFullCheckFile = $apiPayloadInfo.LastFullCheckFile
    $currentTime = $apiPayloadInfo.CurrentTime
    
    # Convert data to JSON
    $jsonData = $data | ConvertTo-Json -Depth 10
    
    # Get API token and base URL from config
    $apiToken = Get-ConfigValue -Key "api_token"
    $apiBaseUrl = Get-ConfigValue -Key "api_base_url"
    $checkinUrl = "$apiBaseUrl/devices/check-in"
    
    # Write debug info
    Write-Debug "Sending payload: ${jsonData}"
    Write-Debug "Sending to URL: ${checkinUrl}"
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Token" = $apiToken
        }
        
        $response = Invoke-RestMethod -Uri $checkinUrl -Method Post -Headers $headers -Body $jsonData -ErrorAction Stop
        
        Write-Log "Sent metrics: HTTP 200 - Success"
        Write-Debug "Response: $($response | ConvertTo-Json -Depth 10)"
        
        # Update last send time for rate limiting
        $script:lastSendTime = $now
        $script:consecutiveFailures = 0
        $script:backoffTime = 0
        
        # Check for check interval updates
        if ($response.config -and $response.config.check_interval) {
            $newCheckInterval = $response.config.check_interval
            $currentCheckInterval = Get-ConfigValue -Key "check_interval"
            
            if ($newCheckInterval -ne $currentCheckInterval) {
                Write-Log "Updating check interval from $currentCheckInterval to $newCheckInterval seconds"
                
                # Update the config file
                $configContent = Get-Content $configFile -Raw | ConvertFrom-Json
                $configContent.check_interval = $newCheckInterval
                $configContent | ConvertTo-Json -Depth 10 | Set-Content $configFile
                
                # Update the current check interval
                $checkInterval = $newCheckInterval
            }
        }
        
        # Handle full update tracking
        if ($isFullUpdate) {
            $currentTime.ToString() | Set-Content $lastFullCheckFile
        }
        
        # Check for restart command
        if ($response.restart_required) {
            Write-Log "Restart command received from API. Initiating system restart..."
            Restart-Computer -Force
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Log "Failed to send metrics: HTTP $statusCode" -Level "ERROR"
        Write-Debug "Error: $($_.Exception.Message)"
        Write-Debug "Response: $($_.ErrorDetails.Message)"
        
        # Increment failure count and apply exponential backoff
        $script:consecutiveFailures++
        $script:backoffTime = [math]::Min(300, [math]::Pow(2, $script:consecutiveFailures))
        Write-Log "Backing off for $script:backoffTime seconds after $script:consecutiveFailures consecutive failures" -Level "WARN"
        
        # Try with minimal payload on 500 error
        if ($statusCode -eq 500) {
            Write-Log "Detected server error (HTTP 500), trying with minimal payload..."
            
            $minimalData = @{
                hostname = $data.hostname
                metrics = $data.metrics
            }
            
            try {
                $minimalResponse = Invoke-RestMethod -Uri $checkinUrl -Method Post -Headers $headers -Body ($minimalData | ConvertTo-Json) -ErrorAction Stop
                Write-Log "Minimal payload succeeded"
                Write-Debug "Response: $($minimalResponse | ConvertTo-Json -Depth 10)"
                
                # Also check for check interval updates in minimal response
                if ($minimalResponse.config -and $minimalResponse.config.check_interval) {
                    $newCheckInterval = $minimalResponse.config.check_interval
                    $currentCheckInterval = Get-ConfigValue -Key "check_interval"
                    
                    if ($newCheckInterval -ne $currentCheckInterval) {
                        Write-Log "Updating check interval from $currentCheckInterval to $newCheckInterval seconds"
                        
                        # Update the config file
                        $configContent = Get-Content $configFile -Raw | ConvertFrom-Json
                        $configContent.check_interval = $newCheckInterval
                        $configContent | ConvertTo-Json -Depth 10 | Set-Content $configFile
                        
                        # Update the current check interval
                        $checkInterval = $newCheckInterval
                    }
                }
            }
            catch {
                Write-Log "Minimal payload also failed: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
}

function Check-DeviceRegistration {
    $apiToken = Get-ConfigValue -Key "api_token"
    $apiBaseUrl = Get-ConfigValue -Key "api_base_url"
    $statusUrl = "$apiBaseUrl/devices/status"
    
    Write-Log "Checking device registration status..."
    
    try {
        $headers = @{
            "Content-Type" = "application/json"
            "X-API-Token" = $apiToken
        }
        
        $response = Invoke-RestMethod -Uri $statusUrl -Headers $headers -Method Get -ErrorAction Stop
        Write-Log "Device registration status: Active"
        return $true
    }
    catch {
        $statusCode = "Unknown"
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode -ne $null) {
            $statusCode = $_.Exception.Response.StatusCode.value__
        } elseif ($_.Exception.Response) {
            Write-Debug "Device registration check failed: Response received but StatusCode object is null."
            $statusCode = "Unknown (StatusCode missing)"
        } else {
            Write-Debug "Device registration check failed: No response object in exception."
            $statusCode = "Unknown (No Response)"
        }
        
        if ($statusCode -eq 404) {
            Write-Log "ERROR: Device not found. Please check if the device was deleted from the dashboard." -Level "ERROR"
        }
        elseif ($statusCode -eq 401) {
            Write-Log "ERROR: Invalid API token. Please check your configuration." -Level "ERROR"
        }
        else {
            Write-Log "ERROR: Could not verify device status (HTTP ${statusCode})" -Level "ERROR"
            Write-Debug "Response: $($_.Exception.Message)"
        }
        
        return $false
    }
}

# Main Function
function Start-PulseGuardAgent {
    Write-Log "PulseGuard Agent starting... Version: $AGENT_VERSION"
    
    $apiToken = Get-ConfigValue -Key "api_token"
    $apiBaseUrl = Get-ConfigValue -Key "api_base_url"
    $checkInterval = Get-ConfigValue -Key "check_interval"
    
    if (-not $checkInterval -or $checkInterval -eq 0) {
        $checkInterval = 60  # Changed to 60 seconds for better balance
        Write-Log "Check interval not found in config or invalid, using default: ${checkInterval} seconds"
    }
    
    Write-Log "Agent Configuration:"
    Write-Log "  API URL: ${apiBaseUrl}"
    Write-Log "  API Token: $($apiToken.Substring(0,8))...$($apiToken.Substring($apiToken.Length-8))"
    Write-Log "  Check Interval: ${checkInterval} seconds"
    
    # Check device registration status
    Check-DeviceRegistration
    
    # Test API connection before starting
    if (-not (Test-ApiConnection)) {
        Write-Log "WARNING: Initial API connection test failed. Will continue trying, but check your API token and URL." -Level "WARN"
    }
    
    Write-Log "Agent started. Sending metrics every ${checkInterval} seconds."
    
    # Initialize variables for update checking
    $lastUpdateCheck = [DateTime]::MinValue
    $updateCheckInterval = 3600 # Check for updates every hour (in seconds)
    
    # Main loop
    while ($true) {
        try {
            Collect-SystemMetrics
            
            # Check for updates periodically
            $now = Get-Date
            if (($now - $lastUpdateCheck).TotalSeconds -ge $updateCheckInterval) {
                Check-ForUpdates
                $lastUpdateCheck = $now
            }
        }
        catch {
            Write-Log "Error in metrics collection: $($_.Exception.Message)" -Level "ERROR"
            Write-Debug "Stack trace: $($_.ScriptStackTrace)"
        }
        
        Start-Sleep -Seconds $checkInterval
    }
}

# Start the agent
Start-PulseGuardAgent
'@

# Save the agent PowerShell script
Set-Content -Path $agentScript -Value $agentContent
Write-Host "Agent script created successfully." -ForegroundColor Green

# Create Windows Scheduled Task to run the agent
Write-Host "Setting up Windows Task Scheduler service..." -ForegroundColor Yellow

# Create the task XML configuration
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>$(Get-Date -Format "yyyy-MM-ddTHH:mm:ss")</Date>
    <Author>PulseGuard</Author>
    <Description>PulseGuard Agent Service</Description>
    <URI>\PulseGuard\PulseGuardAgent</URI>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId> <!-- SYSTEM -->
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit> <!-- Run indefinitely -->
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "C:\Program Files\PulseGuard\pulseguard-agent.ps1"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Set-Content -Path $serviceConfigPath -Value $taskXml

try {
    # Try to unregister the task if it already exists
    schtasks /Delete /TN "\PulseGuard\PulseGuardAgent" /F 2>$null

    # Create the task folder first if it doesn't exist
    $taskFolder = "PulseGuard"
    $scheduleObject = New-Object -ComObject Schedule.Service
    $scheduleObject.Connect()
    $rootFolder = $scheduleObject.GetFolder("\")
    
    try {
        $null = $rootFolder.GetFolder($taskFolder)
    } catch {
        $null = $rootFolder.CreateFolder($taskFolder)
    }

    # Register the task
    schtasks /Create /XML $serviceConfigPath /TN "\PulseGuard\PulseGuardAgent" /F
    
    # Start the task
    schtasks /Run /TN "\PulseGuard\PulseGuardAgent"
    
    Write-Host "PulseGuard agent scheduled task created and started successfully." -ForegroundColor Green
} catch {
    Write-Host "Error setting up scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "You can manually run the agent using: powershell -ExecutionPolicy Bypass -File '$agentScript'" -ForegroundColor Yellow
}

# Create a quick-start shortcut in Start Menu
try {
    $startMenuPath = [System.Environment]::GetFolderPath('StartMenu') + "\Programs\PulseGuard"
    if (-not (Test-Path $startMenuPath)) {
        New-Item -Path $startMenuPath -ItemType Directory -Force | Out-Null
    }

    $shortcutPath = "$startMenuPath\Start PulseGuard Agent.lnk"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut($shortcutPath)
    $Shortcut.TargetPath = "powershell.exe"
    $Shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$agentScript`""
    $Shortcut.WorkingDirectory = $installDir
    $Shortcut.Description = "Start PulseGuard Agent"
    $Shortcut.Save()

    Write-Host "Created Start Menu shortcut." -ForegroundColor Green
} catch {
    Write-Host "Could not create Start Menu shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Save device information
Write-Host "Saving device information..." -ForegroundColor Yellow
$envContent = @"
DeviceUUID=$DeviceUUID
ApiToken=$ApiToken
InstallDate=$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@
Set-Content -Path "$installDir\env.ps1" -Value $envContent

# Validate that device UUID is saved correctly
$savedEnv = Get-Content -Path "$installDir\env.ps1" -Raw
if ($savedEnv -match 'DeviceUUID=(.+)') {
    $savedUUID = $matches[1].Trim()
    Write-Host "Device UUID saved: $savedUUID" -ForegroundColor Green
} else {
    Write-Host "Warning: Device UUID may not have been saved correctly" -ForegroundColor Yellow
}

# Verify installation and service
try {
    $task = Get-ScheduledTask -TaskName "PulseGuardAgent" -TaskPath "\PulseGuard\" -ErrorAction SilentlyContinue
    if ($task -and $task.State -eq "Running") {
        Write-Host "PulseGuard Agent service is installed and running successfully!" -ForegroundColor Green
        Write-Host "Installation complete. The agent will now begin reporting system metrics." -ForegroundColor Green
    } else {
        Write-Host "Service might not be properly running." -ForegroundColor Yellow
        Write-Host "Please check the logs in $logsDir for details or contact support." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Service verification failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "If the service is not running, you can manually start it by running this command as administrator:" -ForegroundColor Yellow
    Write-Host "schtasks /Run /TN `"\PulseGuard\PulseGuardAgent`"" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "To view logs: notepad '$logsDir\agent.log'" -ForegroundColor Yellow
Write-Host "For support, visit https://pulseguard.io/support" -ForegroundColor Cyan 