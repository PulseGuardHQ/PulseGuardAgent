const { app, BrowserWindow, ipcMain, dialog, Tray, Menu } = require('electron');
const path = require('path');
const fs = require('fs');
const si = require('systeminformation');
const os = require('os');
const { networkInterfaces } = require('os');
const https = require('https');
const { exec } = require('child_process');
const AutoLaunch = require('auto-launch');

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
  api_base_url: 'https://app.pulseguard.nl/api',
  check_interval: 60,
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
    isHidden: true
  });

  autoLauncher.isEnabled().then((isEnabled) => {
    if (!isEnabled) {
      autoLauncher.enable();
      logToFile('Auto-launch enabled');
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
    icon: path.join(__dirname, 'assets/icon.ico'),
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
  tray = new Tray(path.join(__dirname, 'assets/icon.ico'));
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Open PulseGuard', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'Send Metrics Now', click: () => { collectAndSendMetrics(true); } },
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

// Make HTTP request to PulseGuard API
function makeApiRequest(endpoint, method, data = null) {
  return new Promise((resolve, reject) => {
    try {
      const apiUrl = new URL(endpoint, config.api_base_url);
      const options = {
        method: method,
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': config.api_token
        }
      };

      const req = https.request(apiUrl, options, (res) => {
        let responseBody = '';
        
        res.on('data', (chunk) => {
          responseBody += chunk;
        });
        
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              const response = JSON.parse(responseBody);
              resolve({ statusCode: res.statusCode, body: response });
            } catch (e) {
              resolve({ statusCode: res.statusCode, body: responseBody });
            }
          } else {
            reject({ 
              statusCode: res.statusCode, 
              message: `HTTP request failed with status ${res.statusCode}`,
              body: responseBody
            });
          }
        });
      });
      
      req.on('error', (error) => {
        reject({ statusCode: 0, message: error.message });
      });
      
      if (data) {
        req.write(JSON.stringify(data));
      }
      
      req.end();
    } catch (error) {
      reject({ statusCode: 0, message: error.message });
    }
  });
}

// Test API connection
async function testApiConnection() {
  try {
    logToFile('Testing API connection...');
    const result = await makeApiRequest('/devices/config', 'GET');
    logToFile('API connection successful (HTTP 200)');
    return true;
  } catch (error) {
    logToFile(`API connection failed: ${error.message}`, 'ERROR');
    
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

// Get basic system metrics
async function getBasicMetrics() {
  try {
    // Use systeminformation to get accurate metrics
    const [cpu, mem, disk] = await Promise.all([
      si.currentLoad(),
      si.mem(),
      si.fsSize()
    ]);
    
    // Calculate CPU usage
    const cpuUsage = parseFloat(cpu.currentLoad.toFixed(2));
    
    // Calculate memory usage
    const memUsage = parseFloat(((mem.used / mem.total) * 100).toFixed(2));
    
    // Calculate disk usage (system drive)
    let diskUsage = 0;
    const systemDrive = disk.find(d => d.mount === 'C:' || d.mount === '/');
    if (systemDrive) {
      diskUsage = parseFloat(systemDrive.use.toFixed(2));
    } else if (disk.length > 0) {
      diskUsage = parseFloat(disk[0].use.toFixed(2));
    }
    
    // Get uptime in seconds
    const uptime = Math.floor(os.uptime());
    
    return {
      cpu_usage: cpuUsage,
      memory_usage: memUsage,
      disk_usage: diskUsage,
      uptime: uptime
    };
  } catch (error) {
    logToFile(`Error getting system metrics: ${error.message}`, 'ERROR');
    return {
      cpu_usage: 0,
      memory_usage: 0,
      disk_usage: 0,
      uptime: 0
    };
  }
}

// Check for agent updates
async function checkForUpdates() {
  try {
    logToFile('Checking for agent updates...');
    
    const data = {
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
    
    // Get hardware information
    const [cpu, mem] = await Promise.all([
      si.cpu(),
      si.mem()
    ]);
    
    // System specs
    const systemSpecs = {
      cpu_cores: cpu.cores,
      total_memory: Math.round(mem.total / (1024 * 1024)) // Convert to MB
    };
    
    // Get a list of running services (Windows only)
    let services = [];
    if (process.platform === 'win32') {
      try {
        const serviceData = await si.services('*');
        services = serviceData.slice(0, 10).map(service => ({
          name: service.name || service.display_name,
          status: service.running ? 'running' : 'stopped'
        }));
      } catch (e) {
        logToFile(`Error getting services: ${e.message}`, 'DEBUG');
      }
    }
    
    // Full payload
    return {
      hostname: os.hostname(),
      ip_address: getIPAddress(),
      mac_address: await getMacAddress(),
      os_type: 'windows',
      os_version: os.release(),
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
      hostname: os.hostname(),
      metrics: metrics,
      full_check_in: true
    };
  }
}

// Create metrics-only payload
async function createMetricsPayload() {
  const metrics = await getBasicMetrics();
  return {
    metrics: metrics
  };
}

// Main function to collect and send metrics
async function collectAndSendMetrics(forceFullUpdate = false) {
  try {
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
    const response = await makeApiRequest('/devices/check-in', 'POST', payload);
    
    // Update successful send tracking
    lastSendTime = now;
    consecutiveFailures = 0;
    backoffTime = 0;
    
    // Update last full check time if this was a full update
    if (needsFullUpdate) {
      lastFullCheckTime = currentTime;
      // Store this in memory, no need to write to disk for our Electron app
    }
    
    logToFile('Metrics sent successfully');
    
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
          hostname: os.hostname(),
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
    
    // Update config
    config.device_uuid = deviceUUID;
    config.api_token = apiToken;
    
    // Save config to file
    ensureDirectories();
    if (saveConfig()) {
      event.reply('config-saved');
      
      // Restart metrics collection with new configuration
      startMetricsCollection();
      
      // Set up auto-launch
      setupAutoLaunch();
    } else {
      event.reply('config-error', 'Failed to save configuration file');
    }
  } catch (error) {
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

// App ready handler
app.whenReady().then(async () => {
  // Ensure required directories exist
  ensureDirectories();
  
  // Log application start
  logToFile(`PulseGuard Agent starting... Version: ${AGENT_VERSION}`);
  
  // Check admin privileges
  const admin = await isAdmin();
  if (!admin) {
    logToFile('Running without administrator privileges. Some functionality may be limited.', 'WARN');
  }
  
  // Load configuration
  loadConfig();
  
  // Create window and tray
  createWindow();
  createTray();
  
  // Start metrics collection if configured
  if (config.api_token && config.device_uuid) {
    startMetricsCollection();
  } else {
    // Show window for onboarding if not configured
    if (mainWindow) {
      mainWindow.show();
    }
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