const { app, BrowserWindow, ipcMain, dialog, Tray, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const si = require('systeminformation');
const os = require('os');
const { networkInterfaces } = require('os');
const https = require('https');
const { exec } = require('child_process');
const AutoLaunch = require('auto-launch');

// Ensure ffmpeg is properly loaded
try {
  // Try to load ffmpeg from the static package
  require('ffmpeg-static');
} catch (error) {
  console.error('Failed to load ffmpeg-static:', error.message);
}

// Global references
let mainWindow;
let tray = null;
let isQuitting = false;
let metricsInterval = null;
let updateCheckInterval = null;

// Config and paths
const installDir = process.env.PROGRAMDATA + '\\PulseGuard';
const configFile = installDir + '\\config.json';
const logFile = installDir + '\\logs\\agent.log';

// Metrics collection state variables
let lastSendTime = new Date(0);
let consecutiveFailures = 0;
let backoffTime = 0;
let lastFullCheckTime = 0;

// Agent version
const AGENT_VERSION = app.getVersion() || '1.0.0';

// Default configuration
let config = {
  api_token: '',
  device_uuid: '',
  api_base_url: 'https://app.pulseguard.nl',
  check_interval: 15,
  full_check_interval: 86400,
  metrics_enabled: true
};

// Ensure directories exist
function ensureDirectories() {
  if (!fs.existsSync(installDir)) {
    fs.mkdirSync(installDir, { recursive: true });
  }
  
  if (!fs.existsSync(installDir + '\\logs')) {
    fs.mkdirSync(installDir + '\\logs', { recursive: true });
  }
}

// Logger functions
function logToFile(message, level = 'INFO') {
  try {
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    const logMessage = `${timestamp} [${level}] ${message}\n`;
    fs.appendFileSync(logFile, logMessage);
    console.log(message);
  } catch (error) {
    console.error('Failed to write to log file:', error);
  }
}

// Load configuration from file
function loadConfig() {
  try {
    if (fs.existsSync(configFile)) {
      const fileContents = fs.readFileSync(configFile, 'utf8');
      const loadedConfig = JSON.parse(fileContents);
      config = { ...config, ...loadedConfig };
      
      logToFile(`Configuration loaded successfully - API URL: ${config.api_base_url}`);
      return true;
    } else {
      logToFile('Configuration file does not exist yet', 'WARN');
      return false;
    }
  } catch (error) {
    logToFile(`Error loading configuration: ${error.message}`, 'ERROR');
    return false;
  }
}

// Save configuration to file
function saveConfig() {
  try {
    fs.writeFileSync(configFile, JSON.stringify(config, null, 2));
    logToFile('Configuration saved successfully');
    return true;
  } catch (error) {
    logToFile(`Error saving configuration: ${error.message}`, 'ERROR');
    return false;
  }
}

// Check if running as administrator (Windows)
function isAdmin() {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') {
      resolve(false);
      return;
    }

    exec('net session', (error) => {
      resolve(!error);
    });
  });
}

// Set up auto launch
function setupAutoLaunch() {
  const autoLauncher = new AutoLaunch({
    name: 'PulseGuard Agent',
    path: process.execPath,
    isHidden: true,
    args: ['--startup']
  });

  autoLauncher.isEnabled().then((isEnabled) => {
    if (!isEnabled) {
      autoLauncher.enable().then(() => {
        logToFile('Auto-launch enabled');
      }).catch((err) => {
        logToFile(`Failed to enable auto-launch: ${err.message}`, 'ERROR');
      });
    } else {
      logToFile('Auto-launch is already enabled');
    }
  }).catch((err) => {
    logToFile(`Auto-launch setup error: ${err.message}`, 'ERROR');
  });
}

// Create main window
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false
    },
    icon: path.join(__dirname, 'assets/website-icon.png'),
    show: false
  });

  mainWindow.loadFile('index.html');

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow.hide();
      return false;
    }
    return true;
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Create tray icon
function createTray() {
  tray = new Tray(path.join(__dirname, 'assets/website-icon.png'));
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open PulseGuard', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'Send Metrics Now', click: () => { collectAndSendMetrics(true); } },
    { type: 'separator' },
    { 
      label: 'Power Management',
      submenu: [
        { label: 'Lock Computer', click: () => { executePowerCommand('lock'); } },
        { label: 'Sleep', click: () => { executePowerCommand('sleep'); } },
        { label: 'Restart', click: () => { 
          dialog.showMessageBox({
            type: 'question',
            buttons: ['Yes', 'No'],
            title: 'Confirm Restart',
            message: 'Are you sure you want to restart your computer?'
          }).then(result => {
            if (result.response === 0) {
              executePowerCommand('restart');
            }
          });
        }},
        { label: 'Shutdown', click: () => {
          dialog.showMessageBox({
            type: 'question',
            buttons: ['Yes', 'No'],
            title: 'Confirm Shutdown',
            message: 'Are you sure you want to shutdown your computer?'
          }).then(result => {
            if (result.response === 0) {
              executePowerCommand('shutdown');
            }
          });
        }}
      ]
    },
    { type: 'separator' },
    { label: 'Quit', click: () => { 
      isQuitting = true;
      app.quit(); 
    } }
  ]);
  
  tray.setToolTip('PulseGuard Agent');
  tray.setContextMenu(contextMenu);
  
  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) {
        mainWindow.hide();
      } else {
        mainWindow.show();
      }
    }
  });
}

// Get MAC address using systeminformation
async function getMacAddress() {
  try {
    const networkData = await si.networkInterfaces();
    
    // Find the first active, non-virtual network adapter
    const activeAdapter = networkData.find(adapter => 
      adapter.operstate === 'up' && 
      !adapter.virtual && 
      adapter.mac && 
      adapter.mac.length > 0
    );
    
    if (activeAdapter && activeAdapter.mac) {
      return activeAdapter.mac;
    }
    
    // If no active adapter, get the first physical one
    const anyAdapter = networkData.find(adapter => 
      !adapter.virtual && 
      adapter.mac && 
      adapter.mac.length > 0
    );
    
    if (anyAdapter && anyAdapter.mac) {
      return anyAdapter.mac;
    }
    
    logToFile('Could not find any network adapter with a MAC address', 'WARN');
    return 'AA:BB:CC:DD:EE:FF';
  } catch (error) {
    logToFile(`Error getting MAC address: ${error.message}`, 'ERROR');
    return 'AA:BB:CC:DD:EE:FF';
  }
}

// Get the primary IPv4 address
function getIPAddress() {
  try {
    const interfaces = networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        // Skip internal and non-IPv4 addresses
        if (!iface.internal && iface.family === 'IPv4') {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  } catch (error) {
    logToFile(`Error getting IP address: ${error.message}`, 'ERROR');
    return '127.0.0.1';
  }
}

// Execute power management command
function executePowerCommand(action) {
  try {
    logToFile(`Executing power command: ${action}`, 'INFO');
    
    // Define commands for Windows
    const commands = {
      'restart': 'shutdown /r /t 5',
      'shutdown': 'shutdown /s /t 5',
      'sleep': 'rundll32.exe powrprof.dll,SetSuspendState 0,1,0',
      'lock': 'rundll32.exe user32.dll,LockWorkStation'
    };
    
    // Check if the command is supported
    if (commands[action]) {
      logToFile(`Executing command: ${commands[action]}`, 'DEBUG');
      
      exec(commands[action], (error, stdout, stderr) => {
        if (error) {
          logToFile(`Failed to execute power command: ${error.message}`, 'ERROR');
          logToFile(`Command output: ${stdout}`, 'DEBUG');
          logToFile(`Command error: ${stderr}`, 'DEBUG');
          
          // Try to diagnose permission issues
          isAdmin().then(adminStatus => {
            logToFile(`Admin rights check: ${adminStatus ? 'Running as admin' : 'NOT running as admin'}`, 'INFO');
            if (!adminStatus) {
              logToFile('Power commands may require administrative privileges. Check your agent installation.', 'WARN');
            }
          });
          return;
        }
        
        if (stdout) logToFile(`Command stdout: ${stdout}`, 'DEBUG');
        if (stderr) logToFile(`Command stderr: ${stderr}`, 'DEBUG');
        
        logToFile(`Power command executed successfully: ${action}`, 'INFO');
      });
    } else {
      logToFile(`Unsupported power command: ${action}`, 'ERROR');
      logToFile(`Supported commands are: ${Object.keys(commands).join(', ')}`, 'INFO');
    }
  } catch (error) {
    logToFile(`Error executing power command: ${error.message}`, 'ERROR');
  }
}

// Make HTTP request to PulseGuard API
function makeApiRequest(endpoint, method, data = null) {
  return new Promise((resolve, reject) => {
    try {
      const apiUrl = new URL('/api' + endpoint, config.api_base_url);
      
      const options = {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': config.api_token
        }
      };

      // Debug info
      logToFile(`Making API request to: ${apiUrl}`, 'DEBUG');
      if (data) {
        logToFile(`Request payload: ${JSON.stringify(data)}`, 'DEBUG');
      }

      const req = https.request(apiUrl, options, (res) => {
        let responseBody = '';
        
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const response = JSON.parse(responseBody);
              logToFile(`API response: ${res.statusCode} OK`, 'DEBUG');
              resolve({ statusCode: res.statusCode, body: response });
            } catch (e) {
              resolve({ statusCode: res.statusCode, body: responseBody });
            }
          } else {
            logToFile(`API error response: HTTP ${res.statusCode}`, 'DEBUG');
            if (responseBody) {
              logToFile(`Response body: ${responseBody.substring(0, 500)}...`, 'DEBUG');
            }
            reject({ 
              statusCode: res.statusCode, 
              message: `HTTP request failed with status ${res.statusCode}`,
              body: responseBody
            });
          }
        });
      });
      
      req.on('error', (error) => {
        logToFile(`API request network error: ${error.message}`, 'ERROR');
        reject({ statusCode: 0, message: error.message });
      });
      
      if (data) {
        req.write(JSON.stringify(data));
      }
      
      req.end();
    } catch (error) {
      logToFile(`API request error: ${error.message}`, 'ERROR');
      reject({ statusCode: 0, message: error.message });
    }
  });
}

// Test API connection
async function testApiConnection() {
  try {
    logToFile('Testing API connection...');
    
    // Probeer eerst de config endpoint - GET in plaats van POST
    try {
      const configResult = await makeApiRequest('/devices/config', 'GET');
      logToFile('API config connection successful (HTTP 200)');
      return true;
    } catch (configError) {
      logToFile(`API config test failed: ${configError.message}, trying status endpoint...`, 'WARN');
    }
    
    // Probeer dan de status endpoint
    try {
      const statusResult = await makeApiRequest('/devices/status', 'GET');
      logToFile('API status connection successful (HTTP 200)');
      return true;
    } catch (statusError) {
      logToFile(`API status test failed: ${statusError.message}, trying check-in...`, 'WARN');
    }
    
    // Als laatste proberen we de check-in endpoint met minimale data
    const testPayload = {
      token: config.api_token,
      uuid: config.device_uuid,
      device_uuid: config.device_uuid,
      hostname: os.hostname(),
      metrics: {
        cpu_usage: 0,
        memory_usage: 0,
        disk_usage: 0,
        uptime: 0
      }
    };
    
    const result = await makeApiRequest('/devices/check-in', 'POST', testPayload);
    logToFile('API check-in connection successful (HTTP 200)');
    return true;
  } catch (error) {
    logToFile(`All API connection tests failed: ${error.message}`, 'ERROR');
    
    // Perform additional diagnostics
    try {
      const apiUrl = new URL(config.api_base_url);
      const host = apiUrl.hostname;
      logToFile(`Running network diagnostics for ${host}...`);
      
      // Try to ping the domain
      exec(`ping -n 3 ${host}`, (error, stdout, stderr) => {
        if (error) {
          logToFile(`Ping test failed: ${error.message}`, 'DEBUG');
        } else {
          logToFile(`Ping test results: ${stdout.split('\n')[0]}`, 'DEBUG');
        }
      });
    } catch (e) {
      logToFile(`Diagnostics error: ${e.message}`, 'ERROR');
    }
    
    return false;
  }
}

// Get detailed metrics and hardware info
async function getDetailedSystemInfo() {
  try {
    const [cpuInfo, memInfo, diskInfo, networkInfo] = await Promise.all([
      si.cpu(),
      si.mem(),
      si.fsSize(),
      si.networkInterfaces()
    ]);
    
    // Calculate disk usage (system drive)
    let systemDrive = diskInfo.find(d => d.mount === 'C:' || d.mount === '/');
    if (!systemDrive && diskInfo.length > 0) {
      systemDrive = diskInfo[0];
    }
    
    // Find primary network adapter
    const primaryAdapter = networkInfo.find(adapter => 
      adapter.operstate === 'up' && 
      !adapter.virtual && 
      adapter.mac && 
      adapter.mac.length > 0
    ) || networkInfo[0];
    
    return {
      cpu: cpuInfo,
      memory: memInfo,
      disk: systemDrive,
      network: primaryAdapter
    };
  } catch (error) {
    logToFile(`Error getting detailed system info: ${error.message}`, 'ERROR');
    return {
      cpu: { cores: 1, manufacturer: 'Unknown', brand: 'Unknown' },
      memory: { total: 1024 * 1024 * 1024, free: 512 * 1024 * 1024 },
      disk: { size: 100 * 1024 * 1024 * 1024, used: 50 * 1024 * 1024 * 1024 }
    };
  }
}

// Get basic system metrics with fallbacks and validations
async function getBasicMetrics() {
  try {
    // Use systeminformation to get accurate metrics
    const [cpu, mem, disk] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize()
    ]);
    
    // Calculate CPU usage with validation - ensure it's a NUMBER type, not string
    let cpuUsage = parseFloat(cpu.currentLoad.toFixed(2));
    if (isNaN(cpuUsage) || cpuUsage < 0 || cpuUsage > 100) {
      logToFile(`Invalid CPU usage value: ${cpuUsage}, using fallback`, 'WARN');
      cpuUsage = 5.0; // Safe fallback value
    }
    
    // Calculate memory usage with validation - ensure it's a NUMBER type, not string
    let memoryTotal = mem.total;
    let memoryUsed = mem.used;
    let memUsage = parseFloat(((memoryUsed / memoryTotal) * 100).toFixed(2));
    if (isNaN(memUsage) || memUsage < 0 || memUsage > 100) {
      logToFile(`Invalid memory usage value: ${memUsage}, using fallback`, 'WARN');
      memUsage = 50.0; // Safe fallback value
    }
    
    // Calculate disk usage (system drive) - ensure it's a NUMBER type, not string
    let diskUsage = 0;
    const systemDrive = disk.find(d => d.mount === 'C:' || d.mount === '/');
    if (systemDrive) {
      diskUsage = parseFloat(systemDrive.use.toFixed(2));
    } else if (disk.length > 0) {
      diskUsage = parseFloat(disk[0].use.toFixed(2));
    }
    if (isNaN(diskUsage) || diskUsage < 0 || diskUsage > 100) {
      logToFile(`Invalid disk usage value: ${diskUsage}, using fallback`, 'WARN');
      diskUsage = 50.0; // Safe fallback value
    }
    
    // Get uptime in seconds as an INTEGER, not string or float
    const uptime = Math.floor(os.uptime());
    
    // Force numeric types for compatibility with API
    return {
      cpu_usage: Number(cpuUsage),
      memory_usage: Number(memUsage),
      disk_usage: Number(diskUsage),
      uptime: Number(uptime)
    };
  } catch (error) {
    logToFile(`Error getting system metrics: ${error.message}`, 'ERROR');
    return {
      cpu_usage: Number(5.0),
      memory_usage: Number(50.0),
      disk_usage: Number(50.0),
      uptime: Number(60)
    };
  }
}

// Check for agent updates
async function checkForUpdates() {
  try {
    logToFile('Checking for agent updates...');
    
    const data = {
      token: config.api_token,
      uuid: config.device_uuid,
      device_uuid: config.device_uuid,
      current_version: AGENT_VERSION,
      os_type: 'windows'
    };
    
    const response = await makeApiRequest('/devices/check-for-updates', 'POST', data);
    
    if (response.body.update_available) {
      logToFile(`Update available! Current: ${AGENT_VERSION}, Latest: ${response.body.latest_version}`);
      
      // Log update notes
      if (response.body.update_notes) {
        logToFile('Update notes:');
        for (const version in response.body.update_notes) {
          logToFile(`  Version ${version}:`);
          for (const note of response.body.update_notes[version]) {
            logToFile(`    - ${note}`);
          }
        }
      }
      
      // Notify user about the update in the UI
      if (mainWindow) {
        mainWindow.webContents.send('update-available', {
          currentVersion: AGENT_VERSION,
          newVersion: response.body.latest_version,
          updateUrl: response.body.update_url,
          updateNotes: response.body.update_notes
        });
      }
    } else {
      logToFile(`Agent is up to date (version ${AGENT_VERSION})`);
    }
  } catch (error) {
    logToFile(`Error checking for updates: ${error.message}`, 'ERROR');
  }
}

// Create full system information payload
async function createFullPayload() {
  try {
    // Get basic metrics
    const metrics = await getBasicMetrics();
    
    // Get detailed hardware information
    const detailedInfo = await getDetailedSystemInfo();
    
    // System specs
    const systemSpecs = {
      cpu_cores: detailedInfo.cpu.cores || 1,
      total_memory: Math.round((detailedInfo.memory.total || 1024 * 1024 * 1024) / (1024 * 1024)) // Convert to MB
    };
    
    // Get hostname or use a fallback
    let hostname = os.hostname();
    if (!hostname || hostname.length === 0) {
      hostname = "unknown-host";
      logToFile("Could not determine hostname, using fallback", "WARN");
    }
    
    // Get IP address with fallback
    let ipAddress = getIPAddress();
    if (!ipAddress || ipAddress.length === 0) {
      ipAddress = "127.0.0.1";
      logToFile("Could not determine IP address, using fallback", "WARN");
    }
    
    // Get MAC address with fallback
    let macAddress = await getMacAddress();
    if (!macAddress || macAddress.length === 0) {
      macAddress = "AA:BB:CC:DD:EE:FF";
      logToFile("Could not determine MAC address, using fallback", "WARN");
    }
    
    // Get OS version with validation
    let osVersion = os.release();
    if (!osVersion || osVersion.length === 0) {
      osVersion = "10.0";
      logToFile("Could not determine OS version, using fallback", "WARN");
    }
    
    // Get a list of running services (Windows only)
    let services = [];
    if (process.platform === 'win32') {
      try {
        const serviceData = await si.services('*');
        services = serviceData.slice(0, 10).map(service => ({
          name: service.name || service.display_name || "Unknown Service",
          status: service.running ? 'running' : 'stopped'
        }));
      } catch (e) {
        logToFile(`Error getting services: ${e.message}`, 'DEBUG');
      }
    }
    
    // Payload met token ipv uuid - proberen verschillende opties
    return {
      token: config.api_token, // Proberen met token in plaats van device_uuid
      uuid: config.device_uuid, // Alternatieve naam
      device_uuid: config.device_uuid, // Originele naam als backup
      hostname: hostname,
      ip_address: ipAddress,
      mac_address: macAddress,
      os_type: 'windows',
      os_version: osVersion,
      system_specs: systemSpecs,
      metrics: metrics,
      services: services,
      full_check_in: true
    };
  } catch (error) {
    logToFile(`Error creating full payload: ${error.message}`, 'ERROR');
    
    // Return a minimal payload in case of error
    const metrics = await getBasicMetrics();
    return {
      token: config.api_token,
      uuid: config.device_uuid,
      device_uuid: config.device_uuid,
      hostname: os.hostname() || "unknown-host",
      ip_address: "127.0.0.1",
      mac_address: "AA:BB:CC:DD:EE:FF",
      os_type: "windows",
      os_version: "10.0",
      metrics: metrics,
      full_check_in: true
    };
  }
}

// Create metrics-only payload
async function createMetricsPayload() {
  const metrics = await getBasicMetrics();
  return {
    token: config.api_token,
    uuid: config.device_uuid,
    device_uuid: config.device_uuid,
    metrics: metrics
  };
}

// Main function to collect and send metrics
async function collectAndSendMetrics(forceFullUpdate = false) {
  try {
    // Skip sending metrics if not configured yet
    if (!config.api_token || !config.device_uuid) {
      logToFile('Skipping metrics collection - API token and Device UUID not configured yet', 'WARN');
      return;
    }
    
    // Apply backoff logic if we had recent failures
    const now = new Date();
    const timeSinceLastSend = (now - lastSendTime) / 1000;
    
    if (timeSinceLastSend < backoffTime) {
      logToFile(`Rate limiting in effect. Waiting for backoff period to expire. ${Math.round(backoffTime - timeSinceLastSend)} seconds remaining.`, 'DEBUG');
      return;
    }
    
    // Determine if we need to do a full check-in
    const currentTime = Math.floor(Date.now() / 1000);
    let needsFullUpdate = forceFullUpdate;
    
    if (!needsFullUpdate) {
      // Check if we've ever done a full check-in
      if (lastFullCheckTime === 0) {
        needsFullUpdate = true;
        logToFile('First run detected, performing full device check-in');
      } else {
        // Check if it's time for a full update based on config interval
        const fullCheckInterval = config.full_check_interval || 86400; // Default to daily
        if ((currentTime - lastFullCheckTime) >= fullCheckInterval) {
          needsFullUpdate = true;
          logToFile(`Time for full device check-in (last: ${new Date(lastFullCheckTime * 1000).toISOString()})`);
        }
      }
    }
    
    // Create payload based on update type
    const payload = needsFullUpdate 
      ? await createFullPayload()
      : await createMetricsPayload();
    
    // Send data to API
    logToFile(`Sending ${needsFullUpdate ? 'full' : 'metrics-only'} payload to API`);
    
    try {
      const response = await makeApiRequest('/devices/check-in', 'POST', payload);
      
      // Update successful send tracking
      lastSendTime = now;
      consecutiveFailures = 0;
      backoffTime = 0;
      
      // Update last full check time if this was a full update
      if (needsFullUpdate) {
        lastFullCheckTime = currentTime;
      }
      
      logToFile('Metrics sent successfully');
      
      // Log response details for debugging
      logApiResponse(response);
      
      // Check for configuration updates from server response
      if (response.body.config) {
        if (response.body.config.check_interval && response.body.config.check_interval !== config.check_interval) {
          logToFile(`Updating check interval from ${config.check_interval} to ${response.body.config.check_interval} seconds`);
          config.check_interval = response.body.config.check_interval;
          saveConfig();
          
          // Update the metrics collection interval
          if (metricsInterval) {
            clearInterval(metricsInterval);
            metricsInterval = setInterval(collectAndSendMetrics, config.check_interval * 1000);
          }
        }
      }
      
      // Check for power commands from server
      if (response.body.power_command) {
        // Extract the action from the power_command object
        const powerCommand = response.body.power_command;
        let powerAction;
        
        if (typeof powerCommand === 'string') {
          // Handle case where it's a direct string for backward compatibility
          powerAction = powerCommand;
        } else if (typeof powerCommand === 'object' && powerCommand.action) {
          // Handle case where it's an object with action and requested_at
          powerAction = powerCommand.action;
          const requestedAt = powerCommand.requested_at ? new Date(powerCommand.requested_at) : new Date();
          logToFile(`Power command was requested at: ${requestedAt.toISOString()}`);
        } else {
          logToFile(`Invalid power command format received: ${JSON.stringify(powerCommand)}`, 'ERROR');
          return;
        }
        
        logToFile(`Power command received from API: ${powerAction}`);
        executePowerCommand(powerAction);
      }
      
      // Check for restart command from server
      if (response.body.restart_required) {
        logToFile('Restart command received from API. Restarting application...');
        app.relaunch();
        app.exit();
      }
      
      // Update UI if window is open
      if (mainWindow) {
        mainWindow.webContents.send('metrics-sent', payload.metrics);
      }
    } catch (error) {
      // Handle API errors
      logToFile(`Failed to send metrics: ${error.message}`, 'ERROR');
      
      // Implement exponential backoff
      consecutiveFailures++;
      backoffTime = Math.min(300, Math.pow(2, consecutiveFailures)); // Max 5 minutes backoff
      logToFile(`Backing off for ${backoffTime} seconds after ${consecutiveFailures} consecutive failures`, 'WARN');
      
      // Try with minimal payload if it was a 500 error and we sent a full payload
      if (error.statusCode === 500 && payload.full_check_in) {
        try {
          logToFile('Detected server error (HTTP 500), trying with minimal payload...', 'WARN');
          const minimalPayload = {
            device_uuid: config.device_uuid,
            metrics: payload.metrics
          };
          
          const response = await makeApiRequest('/devices/check-in', 'POST', minimalPayload);
          logToFile('Minimal payload succeeded');
          
          // Reset failure tracking
          consecutiveFailures = 0;
          backoffTime = 0;
        } catch (retryError) {
          logToFile(`Minimal payload also failed: ${retryError.message}`, 'ERROR');
        }
      }
    }
  } catch (error) {
    logToFile(`Error in metrics collection: ${error.message}`, 'ERROR');
  }
}

// Set up metrics collection interval
function startMetricsCollection() {
  // Clear any existing interval
  if (metricsInterval) {
    clearInterval(metricsInterval);
  }
  
  // Start collecting metrics at the configured interval
  const intervalMs = (config.check_interval || 60) * 1000;
  metricsInterval = setInterval(collectAndSendMetrics, intervalMs);
  logToFile(`Metrics collection started. Sending metrics every ${config.check_interval} seconds.`);
  
  // Send initial metrics right away
  collectAndSendMetrics(true);
  
  // Also set up the update check interval (hourly)
  if (updateCheckInterval) {
    clearInterval(updateCheckInterval);
  }
  
  updateCheckInterval = setInterval(checkForUpdates, 3600 * 1000); // Check once per hour
  
  // Initial update check
  checkForUpdates();
}

// Handle the onboarding process via UI
ipcMain.on('save-config', async (event, { deviceUUID, apiToken }) => {
  try {
    // Validate inputs
    if (!deviceUUID || !apiToken) {
      event.reply('config-error', 'Device UUID and API Token are required');
      return;
    }
    
    // Validate UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(deviceUUID)) {
      event.reply('config-error', 'Device UUID format is invalid. Please use the format provided by PulseGuard.');
      return;
    }
    
    // Validate API token has minimum length
    if (apiToken.length < 20) {
      event.reply('config-error', 'API Token is too short. Please enter a valid API Token.');
      return;
    }
    
    logToFile(`Saving new configuration with Device UUID: ${deviceUUID.substring(0, 8)}...`);
    
    // Update config
    config.device_uuid = deviceUUID;
    config.api_token = apiToken;
    
    // Save config to file
    ensureDirectories();
    if (saveConfig()) {
      event.reply('config-saved');
      
      // Test API connection with new config
      logToFile('Testing API connection with new configuration...');
      const connectionSuccess = await testApiConnection();
      if (connectionSuccess) {
        logToFile('API connection test successful with new configuration');
        mainWindow.webContents.send('connection-status', { success: true, message: 'Connection to PulseGuard API successful!' });
      } else {
        logToFile('API connection test failed with new configuration, but will continue trying', 'WARN');
        mainWindow.webContents.send('connection-status', { success: false, message: 'Could not connect to PulseGuard API, but will continue trying.' });
      }
      
      // Restart metrics collection with new configuration
      startMetricsCollection();
      
      // Set up auto-launch
      setupAutoLaunch();
    } else {
      event.reply('config-error', 'Failed to save configuration file');
    }
  } catch (error) {
    logToFile(`Error saving configuration: ${error.message}`, 'ERROR');
    event.reply('config-error', `Error: ${error.message}`);
  }
});

// Get current configuration and status for UI
ipcMain.on('get-status', (event) => {
  event.reply('status-update', {
    configured: config.api_token && config.device_uuid,
    deviceUUID: config.device_uuid,
    apiBaseUrl: config.api_base_url,
    checkInterval: config.check_interval,
    version: AGENT_VERSION
  });
});

// Trigger an immediate metrics collection from UI
ipcMain.on('send-metrics-now', (event) => {
  collectAndSendMetrics(true)
    .then(() => {
      event.reply('metrics-sent-response', { success: true });
    })
    .catch((error) => {
      event.reply('metrics-sent-response', { success: false, error: error.message });
    });
});

// Check for startup argument
const isStartup = process.argv.includes('--startup');

// App ready event
app.on('ready', async () => {
  ensureDirectories();
  loadConfig();
  
  // Check if admin
  const adminStatus = await isAdmin();
  if (!adminStatus) {
    logToFile('Application is not running with administrator privileges. Some features may not work correctly.', 'WARN');
  }
  
  createWindow();
  createTray();
  setupAutoLaunch();
  
  // Start with main window hidden if this is startup launch
  if (isStartup) {
    if (mainWindow) mainWindow.hide();
    logToFile('Started in background mode');
  } else {
    // Only show window if not startup
    if (mainWindow) mainWindow.show();
  }
  
  // Start metrics collection if configured
  if (config.api_token && config.device_uuid) {
    startMetricsCollection();
  } else {
    logToFile('Application started but not fully configured yet - metrics collection disabled', 'WARN');
  }
});

// Handle window activation
app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Handle app quit
app.on('before-quit', () => {
  isQuitting = true;
  
  // Clear intervals
  if (metricsInterval) {
    clearInterval(metricsInterval);
  }
  
  if (updateCheckInterval) {
    clearInterval(updateCheckInterval);
  }
  
  logToFile('PulseGuard Agent shutting down');
});

// Prevent multiple instances of the app
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    // Show the main window if another instance tries to launch
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.show();
      mainWindow.focus();
    }
  });
}

// Log important API responses for troubleshooting
function logApiResponse(response) {
  try {
    if (!response || !response.body) {
      logToFile('Empty API response received', 'WARN');
      return;
    }
    
    // Log power command status
    if (response.body.power_command) {
      logToFile(`Power command in response: ${JSON.stringify(response.body.power_command)}`, 'DEBUG');
    }
    
    // Log config updates
    if (response.body.config) {
      logToFile(`Config in response: ${JSON.stringify(response.body.config)}`, 'DEBUG');
    }
    
    // Log restart flag
    if (response.body.restart_required) {
      logToFile('Restart required flag is set in response', 'DEBUG');
    }
  } catch (error) {
    logToFile(`Error logging API response: ${error.message}`, 'ERROR');
  }
} 