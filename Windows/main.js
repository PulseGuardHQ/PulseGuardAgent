const { app, BrowserWindow, Tray, Menu, dialog, ipcMain, autoUpdater } = require('electron');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
const fsSync = require('fs');
const os = require('os');
const { exec, spawn } = require('child_process');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const { networkInterfaces } = require('os');
const si = require('systeminformation');
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

// Update checking state
let lastUpdateCheck = 0;
const UPDATE_CHECK_INTERVAL = 24 * 60 * 60 * 1000; // Check every 24 hours

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

// Configuration
let config = {
    api_base_url: '',
    api_token: '',
    device_uuid: '',
    device_name: os.hostname(),
    check_interval: 60000 // 1 minute default
};

// Express app for API endpoints
const expressApp = express();
const PORT = 3001;

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fsSync.existsSync(uploadDir)) {
            fsSync.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit
    }
});

// Express middleware
expressApp.use(cors());
expressApp.use(express.json({ limit: '50mb' }));
expressApp.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Ensure directories exist
async function ensureDirectories() {
  try {
    await fs.access(installDir);
  } catch {
    await fs.mkdir(installDir, { recursive: true });
  }
  
  try {
    await fs.access(installDir + '\\logs');
  } catch {
    await fs.mkdir(installDir + '\\logs', { recursive: true });
  }
}

// Logger functions
async function logToFile(message, level = 'INFO') {
  try {
    const timestamp = new Date().toISOString().replace('T', ' ').substr(0, 19);
    const logMessage = `${timestamp} [${level}] ${message}\n`;
    await fs.appendFile(logFile, logMessage);
    console.log(message);
  } catch (error) {
    console.error('Failed to write to log file:', error);
  }
}

// Load configuration from file
async function loadConfig() {
  try {
    await fs.access(configFile);
    const fileContents = await fs.readFile(configFile, 'utf8');
    const loadedConfig = JSON.parse(fileContents);
    config = { ...config, ...loadedConfig };
    
    await logToFile(`Configuration loaded successfully - API URL: ${config.api_base_url}`);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') {
      await logToFile('Configuration file does not exist yet', 'WARN');
    } else {
      await logToFile(`Error loading configuration: ${error.message}`, 'ERROR');
    }
    return false;
  }
}

// Save configuration to file
async function saveConfig() {
  try {
    await fs.writeFile(configFile, JSON.stringify(config, null, 2));
    await logToFile('Configuration saved successfully');
    return true;
  } catch (error) {
    await logToFile(`Error saving configuration: ${error.message}`, 'ERROR');
    return false;
  }
}

// Check if running as administrator (Windows)
async function isAdmin() {
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
  // First try the auto-launch library (for backwards compatibility)
  const autoLauncher = new AutoLaunch({
    name: 'PulseGuard Agent',
    path: process.execPath,
    isHidden: true,
    args: ['--startup']
  });

  autoLauncher.isEnabled().then((isEnabled) => {
    if (!isEnabled) {
      autoLauncher.enable().then(() => {
        logToFile('Auto-launch enabled via auto-launch library');
        // Also set up our backup methods
        setupBackupAutoLaunch();
      }).catch((err) => {
        logToFile(`Auto-launch library failed: ${err.message}, trying backup methods`, 'WARN');
        setupBackupAutoLaunch();
      });
    } else {
      logToFile('Auto-launch is already enabled via auto-launch library');
      // Still set up backup methods to ensure redundancy
      setupBackupAutoLaunch();
    }
  }).catch((err) => {
    logToFile(`Auto-launch library error: ${err.message}, using backup methods`, 'WARN');
    setupBackupAutoLaunch();
  });
}

// Backup auto-launch methods for better reliability
function setupBackupAutoLaunch() {
  try {
    // Method 1: Windows Registry Run key
    setupRegistryAutoLaunch();
    
    // Method 2: Windows Task Scheduler (more reliable for services)
    setupTaskSchedulerAutoLaunch();
    
    logToFile('Backup auto-launch methods configured');
  } catch (error) {
    logToFile(`Error setting up backup auto-launch: ${error.message}`, 'ERROR');
  }
}

function setupRegistryAutoLaunch() {
  try {
    const appName = 'PulseGuardAgent';
    const executablePath = `"${process.execPath}" --startup`;
    
    // Add to current user registry (doesn't require admin)
    const userRegCommand = `reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "${appName}" /t REG_SZ /d "${executablePath}" /f`;
    
    exec(userRegCommand, (error, stdout, stderr) => {
      if (error) {
        logToFile(`Failed to add user registry auto-launch: ${error.message}`, 'WARN');
      } else {
        logToFile('Registry auto-launch (user) configured successfully');
      }
    });
    
    // Try to add to system registry if we have admin rights
    isAdmin().then(adminStatus => {
      if (adminStatus) {
        const systemRegCommand = `reg add "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "${appName}" /t REG_SZ /d "${executablePath}" /f`;
        
        exec(systemRegCommand, (error, stdout, stderr) => {
          if (error) {
            logToFile(`Failed to add system registry auto-launch: ${error.message}`, 'DEBUG');
          } else {
            logToFile('Registry auto-launch (system) configured successfully');
          }
        });
      }
    });
  } catch (error) {
    logToFile(`Registry auto-launch setup error: ${error.message}`, 'ERROR');
  }
}

function setupTaskSchedulerAutoLaunch() {
  try {
    const taskName = 'PulseGuard Agent Startup';
    const executablePath = process.execPath;
    
    // Create a Windows Task Scheduler task for auto-startup
    // This is more reliable than registry entries for some Windows configurations
    const createTaskCommand = `schtasks /create /tn "${taskName}" /tr "\\"${executablePath}\\" --startup" /sc onlogon /rl limited /f`;
    
    exec(createTaskCommand, (error, stdout, stderr) => {
      if (error) {
        logToFile(`Failed to create scheduled task: ${error.message}`, 'DEBUG');
      } else {
        logToFile('Scheduled task auto-launch configured successfully');
        
        // Set the task to run with highest privileges if we're admin
        isAdmin().then(adminStatus => {
          if (adminStatus) {
            const elevateTaskCommand = `schtasks /change /tn "${taskName}" /rl highest`;
            exec(elevateTaskCommand, (error) => {
              if (!error) {
                logToFile('Scheduled task elevated to highest privileges');
              }
            });
          }
        });
      }
    });
  } catch (error) {
    logToFile(`Task scheduler auto-launch setup error: ${error.message}`, 'ERROR');
  }
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

      // Determine whether to use http or https based on the URL protocol
      const requestModule = apiUrl.protocol === 'https:' ? https : http;

      const req = requestModule.request(apiUrl, options, (res) => {
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

// Remote access functionality (SSH, RDP, VNC)
async function setupRemoteAccess() {
  try {
    // Check if remote access is enabled in the agent configuration
    if (!config.remote_access_enabled) {
      logToFile('Remote access not enabled in configuration', 'INFO');
      return;
    }

    // Get remote access configuration from the server
    try {
      const response = await makeApiRequest('/devices/remote-access-config', 'GET');
      if (response && response.body && response.body.config) {
        logToFile('Remote access configuration received from server', 'INFO');
      
        const serverConfig = response.body.config;
        
        // Update remote access master toggle if provided
        if (serverConfig.remote_access_enabled !== undefined) {
          config.remote_access_enabled = serverConfig.remote_access_enabled;
          logToFile(`Remote access ${config.remote_access_enabled ? 'enabled' : 'disabled'} by server config`, 'INFO');
          
          // If remote access is disabled, don't proceed further
          if (!config.remote_access_enabled) {
            saveConfig();
            return;
          }
        }
        
        // Update SSH configuration
        if (serverConfig.ssh_enabled !== undefined) {
          config.ssh_enabled = serverConfig.ssh_enabled;
          config.ssh_port = serverConfig.ssh_port || 22;
          logToFile(`SSH ${config.ssh_enabled ? 'enabled' : 'disabled'} on port ${config.ssh_port}`, 'INFO');
        }
        
        // Update RDP configuration
        if (serverConfig.rdp_enabled !== undefined) {
          config.rdp_enabled = serverConfig.rdp_enabled;
          config.rdp_port = serverConfig.rdp_port || 3389;
          logToFile(`RDP ${config.rdp_enabled ? 'enabled' : 'disabled'} on port ${config.rdp_port}`, 'INFO');
        }
        
        // Update VNC configuration
        if (serverConfig.vnc_enabled !== undefined) {
          config.vnc_enabled = serverConfig.vnc_enabled;
          config.vnc_port = serverConfig.vnc_port || 5900;
          logToFile(`VNC ${config.vnc_enabled ? 'enabled' : 'disabled'} on port ${config.vnc_port}`, 'INFO');
        }
      
      // Save updated configuration
      saveConfig();
      }
    } catch (apiError) {
      logToFile(`Error fetching remote access configuration: ${apiError.message}`, 'WARN');
      logToFile('Using local configuration for remote access', 'INFO');
    }
    
    // Configure each remote access service based on current configuration
    if (config.remote_access_enabled) {
      if (config.ssh_enabled) setupSshServer();
      if (config.rdp_enabled) setupRdpServer();
      if (config.vnc_enabled) setupVncServer();
    } else {
      logToFile('Remote access is disabled in configuration', 'INFO');
    }
  } catch (error) {
    logToFile(`Error setting up remote access: ${error.message}`, 'ERROR');
  }
}

// SSH Server Configuration
async function setupSshServer() {
  try {
    if (!config.ssh_enabled) {
      logToFile('SSH server not enabled, skipping setup', 'INFO');
      return;
    }
    
    logToFile(`Setting up SSH server on port ${config.ssh_port}`, 'INFO');
    
    // Check if OpenSSH is installed on Windows
    exec('sc query sshd', async (error) => {
      if (error) {
        logToFile('OpenSSH Server not installed, attempting to install...', 'INFO');
        try {
          // Install OpenSSH Server using PowerShell
          await installOpenSSH();
        } catch (installError) {
          logToFile(`Failed to install OpenSSH: ${installError.message}`, 'ERROR');
          return;
        }
      }
      
      // Configure and start SSH server
      configureAndStartSshServer();
    });
  } catch (error) {
    logToFile(`Error setting up SSH server: ${error.message}`, 'ERROR');
  }
}

// Install OpenSSH Server on Windows
function installOpenSSH() {
  return new Promise((resolve, reject) => {
    // PowerShell command to install OpenSSH Server
    const installCommand = 'powershell -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"';
    
    exec(installCommand, (error, stdout, stderr) => {
      if (error) {
        logToFile(`Failed to install OpenSSH Server: ${error.message}`, 'ERROR');
        reject(error);
        return;
      }
      
      logToFile('OpenSSH Server installed successfully', 'INFO');
      resolve();
    });
  });
}

// Configure and start SSH server
function configureAndStartSshServer() {
  try {
    // Set OpenSSH service to auto-start
    exec('sc config sshd start=auto', (error) => {
      if (error) {
        logToFile(`Failed to set OpenSSH service to auto-start: ${error.message}`, 'ERROR');
      } else {
        logToFile('OpenSSH service set to auto-start', 'INFO');
      }
      
      // Start or restart the SSH service
      restartSshServer();
    });
  } catch (error) {
    logToFile(`Error configuring SSH server: ${error.message}`, 'ERROR');
  }
}

// Start or restart SSH server
function restartSshServer() {
  try {
    if (!config.ssh_enabled) {
      logToFile('SSH server not enabled, skipping restart', 'INFO');
      return;
    }
    
    logToFile(`Starting SSH server on port ${config.ssh_port}`, 'INFO');
    
    // Stop the service if it's running
    exec('sc stop sshd', () => {
      // Start the service
      exec('sc start sshd', (error, stdout, stderr) => {
      if (error) {
          logToFile(`Failed to start SSH server: ${error.message}`, 'ERROR');
        return;
      }
        logToFile('SSH server started successfully', 'INFO');
        
        // Configure the Windows Firewall to allow SSH traffic
        configureFirewallForSSH();
      });
    });
  } catch (error) {
    logToFile(`Error restarting SSH server: ${error.message}`, 'ERROR');
  }
}

// Configure Windows Firewall for SSH
function configureFirewallForSSH() {
  const port = config.ssh_port || 22;
  const firewallCommand = `powershell -Command "New-NetFirewallRule -DisplayName 'PulseGuard SSH' -Direction Inbound -LocalPort ${port} -Protocol TCP -Action Allow -Profile Any -Description 'PulseGuard Remote Access - SSH' -ErrorAction SilentlyContinue"`;
  
  exec(firewallCommand, (error, stdout, stderr) => {
    if (error) {
      logToFile(`Failed to configure firewall for SSH: ${error.message}`, 'WARN');
      return;
    }
    logToFile(`Firewall configured for SSH on port ${port}`, 'INFO');
  });
}

// RDP Server Configuration
function setupRdpServer() {
  try {
    if (!config.rdp_enabled) {
      logToFile('RDP server not enabled, skipping setup', 'INFO');
      return;
    }
    
    logToFile(`Setting up RDP server on port ${config.rdp_port}`, 'INFO');
    
    // Enable Remote Desktop via registry
    const enableRdpCommand = `powershell -Command "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 0"`;
    exec(enableRdpCommand, (error) => {
      if (error) {
        logToFile(`Failed to enable RDP: ${error.message}`, 'ERROR');
        return;
      }
      
      logToFile('Remote Desktop enabled', 'INFO');
      
      // Configure RDP port if different from default
      if (config.rdp_port && config.rdp_port !== 3389) {
        const setPortCommand = `powershell -Command "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'PortNumber' -Value ${config.rdp_port}"`;
        exec(setPortCommand, (portError) => {
          if (portError) {
            logToFile(`Failed to change RDP port: ${portError.message}`, 'ERROR');
          } else {
            logToFile(`RDP port set to ${config.rdp_port}`, 'INFO');
          }
          
          // Configure firewall for RDP
          configureFirewallForRDP();
          
          // Restart RDP service
          restartRdpService();
        });
      } else {
        // Use default port
        configureFirewallForRDP();
      }
    });
  } catch (error) {
    logToFile(`Error setting up RDP server: ${error.message}`, 'ERROR');
  }
}

// Configure Windows Firewall for RDP
function configureFirewallForRDP() {
  const port = config.rdp_port || 3389;
  const firewallCommand = `powershell -Command "New-NetFirewallRule -DisplayName 'PulseGuard RDP' -Direction Inbound -LocalPort ${port} -Protocol TCP -Action Allow -Profile Any -Description 'PulseGuard Remote Access - RDP' -ErrorAction SilentlyContinue"`;
  
  exec(firewallCommand, (error, stdout, stderr) => {
    if (error) {
      logToFile(`Failed to configure firewall for RDP: ${error.message}`, 'WARN');
      return;
    }
    logToFile(`Firewall configured for RDP on port ${port}`, 'INFO');
  });
}

// Restart Remote Desktop Service
function restartRdpService() {
  exec('net stop TermService && net start TermService', (error) => {
    if (error) {
      logToFile(`Failed to restart Remote Desktop service: ${error.message}`, 'ERROR');
      return;
    }
    logToFile('Remote Desktop service restarted successfully', 'INFO');
  });
}

// VNC Server Configuration
function setupVncServer() {
  try {
    if (!config.vnc_enabled) {
      logToFile('VNC server not enabled, skipping setup', 'INFO');
      return;
    }
    
    logToFile(`Setting up VNC server on port ${config.vnc_port}`, 'INFO');
    
    // For VNC, we'll use TightVNC which we'll need to download and install silently
    // Check if TightVNC is already installed
    checkAndInstallTightVNC();
  } catch (error) {
    logToFile(`Error setting up VNC server: ${error.message}`, 'ERROR');
  }
}

// Check if TightVNC is installed, if not download and install it
function checkAndInstallTightVNC() {
  const tightVNCPath = path.join(installDir, 'tightvnc');
  const tightVNCExe = path.join(tightVNCPath, 'tvnserver.exe');
  
  // Check if the TightVNC executable exists
  if (fs.existsSync(tightVNCExe)) {
    logToFile('TightVNC already installed, configuring...', 'INFO');
    configureTightVNC();
    return;
  }
  
  // Create directory if it doesn't exist
  if (!fs.existsSync(tightVNCPath)) {
    fs.mkdirSync(tightVNCPath, { recursive: true });
  }
  
  // Download and install TightVNC
  const downloadUrl = 'https://www.tightvnc.com/download/2.8.59/tightvnc-2.8.59-gpl-setup-64bit.msi';
  const installerPath = path.join(tightVNCPath, 'tightvnc-installer.msi');
  
  logToFile('Downloading TightVNC installer...', 'INFO');
  
  // Download the installer
  const file = fs.createWriteStream(installerPath);
  https.get(downloadUrl, function(response) {
    response.pipe(file);
    file.on('finish', function() {
      file.close(() => {
        logToFile('TightVNC installer downloaded, installing...', 'INFO');
        
        // Install TightVNC silently
        const installCommand = `msiexec /i "${installerPath}" /quiet /norestart ADDLOCAL="Server" SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1`;
        exec(installCommand, (error, stdout, stderr) => {
          if (error) {
            logToFile(`Failed to install TightVNC: ${error.message}`, 'ERROR');
            return;
          }
          
          logToFile('TightVNC installed successfully', 'INFO');
          
          // Configure TightVNC after installation
          setTimeout(() => {
            configureTightVNC();
          }, 5000); // Wait 5 seconds to ensure installation is complete
        });
      });
    });
  }).on('error', function(err) {
    fs.unlink(installerPath, () => {});
    logToFile(`Failed to download TightVNC: ${err.message}`, 'ERROR');
  });
}

// Configure TightVNC with our settings
function configureTightVNC() {
  try {
    const port = config.vnc_port || 5900;
    
    // Configure TightVNC settings via registry
    const vncConfigCommands = [
      // Set VNC port
      `reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /v "RfbPort" /t REG_DWORD /d "${port}" /f`,
      // Enable VNC server
      `reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /v "EnableRfbServer" /t REG_DWORD /d "1" /f`,
      // Set password (would use a secure mechanism in a real implementation)
      `reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /v "Password" /t REG_BINARY /d "0123456789abcdef" /f`,
      // Add firewall exception
      `netsh advfirewall firewall add rule name="TightVNC Server" dir=in action=allow protocol=TCP localport=${port}`,
      // Restart TightVNC service
      `net stop tvnserver && net start tvnserver`
    ];
    
    // Execute the commands in sequence
    for (const command of vncConfigCommands) {
      exec(command, (error, stdout, stderr) => {
        if (error) {
          logToFile(`VNC configuration error: ${error.message}`, 'ERROR');
        }
      });
    }
    
    logToFile(`TightVNC configured on port ${port}`, 'INFO');
  } catch (error) {
    logToFile(`Error configuring TightVNC: ${error.message}`, 'ERROR');
  }
}

// Get the status of remote access services
async function getRemoteServicesStatus() {
  const remoteServices = [];
  
  try {
    // Check SSH service status
    if (config.ssh_enabled) {
      try {
        const sshStatus = await checkServiceRunning('sshd');
        remoteServices.push({
          name: 'SSH Server (PulseGuard)',
          status: sshStatus ? 'running' : 'stopped'
        });
      } catch (e) {
        logToFile(`Error checking SSH service: ${e.message}`, 'DEBUG');
      }
    }
    
    // Check RDP service status
    if (config.rdp_enabled) {
      try {
        const rdpStatus = await checkServiceRunning('TermService');
        remoteServices.push({
          name: 'Remote Desktop (PulseGuard)',
          status: rdpStatus ? 'running' : 'stopped'
        });
      } catch (e) {
        logToFile(`Error checking RDP service: ${e.message}`, 'DEBUG');
      }
    }
    
    // Check VNC service status
    if (config.vnc_enabled) {
      try {
        const vncStatus = await checkServiceRunning('tvnserver');
        remoteServices.push({
          name: 'VNC Server (PulseGuard)',
          status: vncStatus ? 'running' : 'stopped'
        });
      } catch (e) {
        logToFile(`Error checking VNC service: ${e.message}`, 'DEBUG');
      }
    }
  } catch (error) {
    logToFile(`Error getting remote services status: ${error.message}`, 'ERROR');
  }
  
  return remoteServices;
}

// Check if a Windows service is running
function checkServiceRunning(serviceName) {
  return new Promise((resolve, reject) => {
    exec(`sc query ${serviceName} | findstr "RUNNING"`, (error, stdout) => {
      if (error) {
        // Service might not be installed or not running
        resolve(false);
        return;
      }
      
      resolve(stdout.toLowerCase().includes('running'));
    });
  });
}

// Check for scheduled power actions
async function checkScheduledActions() {
  try {
    logToFile('Checking for scheduled power actions', 'DEBUG');
    
    try {
      const response = await makeApiRequest('/devices/scheduled-actions', 'GET');
      
      if (response && response.body && response.body.actions && response.body.actions.length > 0) {
        const actions = response.body.actions;
        logToFile(`Received ${actions.length} scheduled actions from server`, 'INFO');
        
        // Check for any actions that need to be executed now
        for (const action of actions) {
          if (action.execute_now) {
            logToFile(`Executing scheduled power action: ${action.action_type}`, 'INFO');
            executePowerCommand(action.action_type);
            
            // Notify server that action was executed
            try {
              await makeApiRequest('/devices/scheduled-actions/executed', 'POST', {
                action_id: action.id,
                executed_at: new Date().toISOString(),
                status: 'completed'
              });
            } catch (error) {
              logToFile(`Failed to notify server about action execution: ${error.message}`, 'ERROR');
            }
          }
        }
      }
    } catch (error) {
      // 404 errors kunnen optreden als de endpoint niet bestaat - deze stil negeren op ontwikkelomgevingen
      if (error.statusCode === 404) {
        logToFile('Scheduled actions endpoint niet gevonden, mogelijk niet beschikbaar op ontwikkelomgeving', 'DEBUG');
      } else {
        logToFile(`Error checking scheduled actions: ${error.message}`, 'ERROR');
      }
    }
  } catch (error) {
    logToFile(`Error in checkScheduledActions: ${error.message}`, 'ERROR');
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
        
        // Add remote access service statuses
        const remoteServicesStatus = await getRemoteServicesStatus();
        services = services.concat(remoteServicesStatus);
      } catch (e) {
        logToFile(`Error getting services: ${e.message}`, 'DEBUG');
      }
    }
    
    // Payload met metrics op toplevel in plaats van genest
    return {
      token: config.api_token,
      uuid: config.device_uuid,
      device_uuid: config.device_uuid,
      hostname: hostname,
      ip_address: ipAddress,
      mac_address: macAddress,
      os_type: 'windows',
      os_version: osVersion,
      system_specs: systemSpecs,
      cpu_usage: metrics.cpu_usage,
      memory_usage: metrics.memory_usage,
      disk_usage: metrics.disk_usage,
      uptime_seconds: metrics.uptime,
      services: services,
      network_stats: [],
      process_stats: [],
      additional_metrics: {}
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
      cpu_usage: metrics.cpu_usage,
      memory_usage: metrics.memory_usage,
      disk_usage: metrics.disk_usage,
      uptime_seconds: metrics.uptime
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
    hostname: os.hostname() || "unknown-host",
    cpu_usage: metrics.cpu_usage,
    memory_usage: metrics.memory_usage,
    disk_usage: metrics.disk_usage,
    uptime_seconds: metrics.uptime
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
        
        // Check for remote access configuration updates
        let remoteAccessChanged = false;
        
        // Remote access master toggle
        if (response.body.config.remote_access_enabled !== undefined) {
          config.remote_access_enabled = response.body.config.remote_access_enabled;
          remoteAccessChanged = true;
        }
        
        // SSH configuration updates
        if (response.body.config.ssh_enabled !== undefined) {
          config.ssh_enabled = response.body.config.ssh_enabled;
          config.ssh_port = response.body.config.ssh_port || 22;
          remoteAccessChanged = true;
        }
        
        // RDP configuration updates
        if (response.body.config.rdp_enabled !== undefined) {
          config.rdp_enabled = response.body.config.rdp_enabled;
          config.rdp_port = response.body.config.rdp_port || 3389;
          remoteAccessChanged = true;
        }
        
        // VNC configuration updates
        if (response.body.config.vnc_enabled !== undefined) {
          config.vnc_enabled = response.body.config.vnc_enabled;
          config.vnc_port = response.body.config.vnc_port || 5900;
          remoteAccessChanged = true;
        }
        
        // If any remote access setting changed, save config and update services
        if (remoteAccessChanged) {
          saveConfig();
          
          // Update remote access services
          setupRemoteAccess();
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
      
      // Check for scheduled actions
      if (response.body.check_scheduled_actions) {
        logToFile('Server requested to check scheduled actions', 'INFO');
        checkScheduledActions();
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
  
  // Check for SSH configuration
  setupSshServer();
  
  // Initial check for scheduled actions
  checkScheduledActions();
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
    await ensureDirectories();
    if (await saveConfig()) {
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

// Update API URL from UI
ipcMain.on('update-api-url', async (event, apiUrl) => {
  try {
    // Validate URL format
    try {
      new URL(apiUrl);
    } catch (e) {
      event.reply('settings-error', 'Invalid URL format. Please enter a valid URL.');
      return;
    }
    
    logToFile(`Updating API URL to: ${apiUrl}`);
    
    // Update config
    config.api_base_url = apiUrl;
    
    // Save config to file
    if (await saveConfig()) {
      // Test connection with new URL
      const connectionSuccess = await testApiConnection();
      
      if (connectionSuccess) {
        logToFile('API connection test successful with new URL');
        event.reply('settings-saved');
      } else {
        logToFile('API connection test failed with new URL, maar toch opgeslagen', 'WARN');
        event.reply('settings-error', 'Kon geen verbinding maken met de nieuwe URL. De instelling is wel opgeslagen, maar check of de server juist is geconfigureerd.');
      }
      
      // Restart metrics collection with new configuration
      startMetricsCollection();
    } else {
      event.reply('settings-error', 'Failed to save configuration file');
    }
  } catch (error) {
    logToFile(`Error updating API URL: ${error.message}`, 'ERROR');
    event.reply('settings-error', `Error: ${error.message}`);
  }
});

// Check for updates from UI
ipcMain.on('check-for-updates', async (event) => {
  try {
    logToFile('Manual update check requested from UI');
    const result = await checkForUpdates();
    event.reply('update-check-result', result);
  } catch (error) {
    logToFile(`Manual update check failed: ${error.message}`, 'ERROR');
    event.reply('update-check-result', { 
      updateAvailable: false, 
      error: error.message 
    });
  }
});

// Check for startup argument
const isStartup = process.argv.includes('--startup');

// App ready event
app.on('ready', async () => {
  await ensureDirectories();
  await loadConfig();
  
  // Perform cleanup of old versions FIRST (before anything else)
  await performOldVersionCleanup();
  
  // Start Express server for API endpoints
  startExpressServer();
  
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
  
  // Start update checker
  startUpdateChecker();
  
  // Initialize remote access services
  setupRemoteAccess();
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

// Check for updates from GitHub Releases
async function checkGithubForUpdates() {
  try {
    logToFile('Checking GitHub for application updates...');
    
    const repoOwner = 'your-github-username';
    const repoName = 'your-repo-name';
    
    // GitHub API URL for releases
    const apiUrl = `https://api.github.com/repos/${repoOwner}/${repoName}/releases/latest`;
    
    const response = await makeApiRequest(apiUrl, 'GET');
    
    if (response && response.body && response.body.tag_name) {
      const latestVersion = response.body.tag_name.replace('v', '');
      logToFile(`Latest version on GitHub: ${latestVersion}`);
      
      // Compare with current version
      if (latestVersion !== AGENT_VERSION) {
        logToFile(`New version available! (${latestVersion})`);
        
        // Notify user about the update in the UI
        if (mainWindow) {
          mainWindow.webContents.send('update-available', {
            currentVersion: AGENT_VERSION,
            newVersion: latestVersion,
            updateUrl: response.body.html_url,
            updateNotes: response.body.body
          });
        }
      } else {
        logToFile('No new version available on GitHub');
      }
    } else {
      logToFile('Invalid response from GitHub API', 'ERROR');
    }
  } catch (error) {
    logToFile(`Error checking GitHub for updates: ${error.message}`, 'ERROR');
  }
}

// Update checker functions
function checkForUpdates() {
  return new Promise((resolve, reject) => {
    const githubApiUrl = 'https://api.github.com/repos/pulseguard-nl/PulseGuardAgent/releases/latest';
    
    logToFile('Checking for updates...');
    
    https.get(githubApiUrl, {
      headers: {
        'User-Agent': 'PulseGuard-Agent'
      }
    }, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          if (res.statusCode !== 200) {
            logToFile(`GitHub API returned status ${res.statusCode}`, 'ERROR');
            reject(new Error(`HTTP ${res.statusCode}`));
            return;
          }
          
          const release = JSON.parse(data);
          const latestVersion = release.tag_name.replace(/^v/, ''); // Remove 'v' prefix if present
          const currentVersion = AGENT_VERSION;
          
          logToFile(`Current version: ${currentVersion}, Latest version: ${latestVersion}`);
          
          if (isNewerVersion(latestVersion, currentVersion)) {
            logToFile(`New version available: ${latestVersion}`);
            
            // Perform cleanup of old versions when new version is detected
            setTimeout(() => {
              performOldVersionCleanup();
            }, 2000); // Wait 2 seconds before cleanup
            
            // Show notification in tray
            if (tray) {
              tray.displayBalloon({
                iconType: 'info',
                title: 'PulseGuard Update Available',
                content: `Version ${latestVersion} is available. Click to download.`
              });
            }
            
            // Update tray menu to include update option
            updateTrayMenuWithUpdate(release.html_url, latestVersion);
            
            resolve({
              updateAvailable: true,
              latestVersion: latestVersion,
              downloadUrl: release.html_url,
              releaseNotes: release.body
            });
          } else {
            logToFile('Agent is up to date');
            resolve({ updateAvailable: false });
          }
          
        } catch (error) {
          logToFile(`Error parsing GitHub API response: ${error.message}`, 'ERROR');
          reject(error);
        }
      });
    }).on('error', (error) => {
      logToFile(`Error checking for updates: ${error.message}`, 'ERROR');
      reject(error);
    });
  });
}

function isNewerVersion(latest, current) {
  const latestParts = latest.split('.').map(Number);
  const currentParts = current.split('.').map(Number);
  
  for (let i = 0; i < Math.max(latestParts.length, currentParts.length); i++) {
    const latestPart = latestParts[i] || 0;
    const currentPart = currentParts[i] || 0;
    
    if (latestPart > currentPart) return true;
    if (latestPart < currentPart) return false;
  }
  
  return false;
}

function updateTrayMenuWithUpdate(downloadUrl, version) {
  if (!tray) return;
  
  const contextMenu = Menu.buildFromTemplate([
    { 
      label: `🔄 Update Available (v${version})`, 
      click: () => { 
        shell.openExternal(downloadUrl);
      }
    },
    { type: 'separator' },
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
    }}
  ]);
  
  tray.setContextMenu(contextMenu);
}

function startUpdateChecker() {
  if (!config.auto_update_check) {
    logToFile('Automatic update checking is disabled');
    return;
  }
  
  // Check immediately on startup
  setTimeout(() => {
    checkForUpdates().catch(error => {
      logToFile(`Initial update check failed: ${error.message}`, 'ERROR');
    });
  }, 5000); // Wait 5 seconds after startup
  
  // Set up periodic checking
  updateCheckInterval = setInterval(() => {
    const now = Date.now();
    if (now - lastUpdateCheck >= UPDATE_CHECK_INTERVAL) {
      lastUpdateCheck = now;
      checkForUpdates().catch(error => {
        logToFile(`Periodic update check failed: ${error.message}`, 'ERROR');
      });
    }
  }, 60 * 60 * 1000); // Check every hour, but only execute every 24 hours
  
  logToFile('Update checker started');
}

// Function to clean up old installation files
function cleanupOldVersions() {
  try {
    logToFile('Starting cleanup of old PulseGuard versions...');
    
    // Common installation directories where old versions might be stored
    const commonDirs = [
      path.join(os.homedir(), 'AppData', 'Local', 'Programs'),
      path.join(os.homedir(), 'AppData', 'Local', 'Programs', 'PulseGuard'),
      path.join(os.homedir(), 'AppData', 'Local', 'Programs', 'pulseguard-agent'),
      path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files'),
      path.join(process.env.PROGRAMFILES || 'C:\\Program Files', 'PulseGuard'),
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)'),
      path.join(process.env['PROGRAMFILES(X86)'] || 'C:\\Program Files (x86)', 'PulseGuard'),
      path.join(os.homedir(), 'Downloads'),
      path.join(os.homedir(), 'Desktop'),
      path.join(os.homedir(), 'Documents'),
      'C:\\PulseGuard',
      'C:\\Program Files\\PulseGuard',
      'C:\\Program Files (x86)\\PulseGuard'
    ];
    
    // Patterns to look for old PulseGuard files
    const pulseguardPatterns = [
      /PulseGuardAgent.*\.exe$/i,
      /PulseGuard.*Agent.*\.exe$/i,
      /pulseguard.*agent.*\.exe$/i,
      /PulseGuard-.*\.exe$/i,
      /pulseguard-.*\.exe$/i
    ];
    
    for (const dir of commonDirs) {
      if (fsSync.existsSync(dir)) {
        cleanupDirectory(dir, pulseguardPatterns);
      }
    }
    
    // Also cleanup temporary directories
    const tempDirs = [
      os.tmpdir(),
      path.join(os.homedir(), 'AppData', 'Local', 'Temp'),
      path.join(process.env.WINDIR || 'C:\\Windows', 'Temp')
    ];
    
    for (const tempDir of tempDirs) {
      if (fsSync.existsSync(tempDir)) {
        cleanupDirectory(tempDir, pulseguardPatterns);
      }
    }
    
    // Clean up old auto-launch entries
    cleanupOldAutoLaunchEntries();
    
    logToFile('Old version cleanup completed');
  } catch (error) {
    logToFile(`Error during old version cleanup: ${error.message}`, 'ERROR');
  }
}

function cleanupDirectory(directory, patterns) {
  try {
    const files = fsSync.readdirSync(directory);
    const currentExecutable = process.execPath;
    const currentExecutableName = path.basename(currentExecutable);
    
    for (const file of files) {
      const fullPath = path.join(directory, file);
      
      // Skip if it's the current running executable
      if (fullPath === currentExecutable || file === currentExecutableName) {
        continue;
      }
      
      // Check if file matches any of the patterns
      const matchesPattern = patterns.some(pattern => pattern.test(file));
      
      if (matchesPattern) {
        try {
          const stats = fsSync.statSync(fullPath);
          
          // Check if it's actually an older version by looking at file version or date
          // Only delete files that are older than 30 minutes (to avoid deleting currently downloading files)
          const thirtyMinutesAgo = Date.now() - (30 * 60 * 1000);
          if (stats.mtime.getTime() < thirtyMinutesAgo) {
            // Try to kill the process if it's running (synchronously)
            try {
              const processName = path.basename(fullPath, '.exe');
              exec(`taskkill /F /IM "${processName}.exe"`, () => {}); // Fire and forget
              
              // Wait a moment for the process to terminate
              const maxWaitTime = 3000; // 3 seconds max
              const startTime = Date.now();
              let processKilled = false;
              
              while (!processKilled && (Date.now() - startTime) < maxWaitTime) {
                try {
                  // Try to access the file - if it fails, the process might still be running
                  fsSync.accessSync(fullPath, fsSync.constants.W_OK);
                  processKilled = true;
                } catch (accessError) {
                  // Wait 100ms and try again
                  const waitStart = Date.now();
                  while (Date.now() - waitStart < 100) {
                    // Busy wait for 100ms
                  }
                }
              }
            } catch (killError) {
              // Ignore kill errors
            }
            
            // Try to delete the file
            try {
              fsSync.unlinkSync(fullPath);
              logToFile(`Removed old version file: ${fullPath}`);
            } catch (deleteError) {
              // If deletion fails, try to rename it so it doesn't interfere
              try {
                const deletedPath = fullPath + '.deleted_' + Date.now();
                fsSync.renameSync(fullPath, deletedPath);
                logToFile(`Marked old version for deletion: ${deletedPath}`);
              } catch (renameError) {
                logToFile(`Could not delete or mark ${fullPath}: ${deleteError.message}`, 'DEBUG');
              }
            }
          } else {
            logToFile(`Skipping recent file: ${fullPath}`, 'DEBUG');
          }
        } catch (statError) {
          // File might be in use or protected, log but don't fail
          logToFile(`Could not access ${fullPath}: ${statError.message}`, 'DEBUG');
        }
      }
    }
  } catch (error) {
    logToFile(`Error scanning directory ${directory}: ${error.message}`, 'DEBUG');
  }
}

// Function to cleanup old PulseGuard registry entries (Windows)
function cleanupOldRegistryEntries() {
  if (process.platform !== 'win32') return;
  
  try {
    logToFile('Cleaning up old registry entries...');
    
    // Use synchronous execution for more reliable cleanup
    const { execSync } = require('child_process');
    
    // Common registry paths where old versions might be registered
    const registryPaths = [
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
      'HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
    ];
    
    for (const regPath of registryPaths) {
      try {
        const command = `reg query "${regPath}" /f "PulseGuard" /s 2>nul`;
        const stdout = execSync(command, { encoding: 'utf8', timeout: 10000 });
        
        if (stdout) {
          // Parse the output to find old PulseGuard entries
          const lines = stdout.split('\n');
          for (const line of lines) {
            if (line.includes('PulseGuard') && line.includes('HKEY_')) {
              const keyPath = line.trim();
              
              try {
                // Check if this is an old version by querying the version
                const versionCommand = `reg query "${keyPath}" /v "DisplayVersion" 2>nul`;
                const versionStdout = execSync(versionCommand, { encoding: 'utf8', timeout: 5000 });
                
                if (versionStdout) {
                  const versionMatch = versionStdout.match(/DisplayVersion\s+REG_SZ\s+([\d.]+)/);
                  if (versionMatch) {
                    const installedVersion = versionMatch[1];
                    if (isNewerVersion(AGENT_VERSION, installedVersion)) {
                      // This is an older version, remove it
                      try {
                        execSync(`reg delete "${keyPath}" /f`, { timeout: 5000 });
                        logToFile(`Removed old registry entry: ${keyPath} (version ${installedVersion})`);
                      } catch (deleteError) {
                        logToFile(`Could not remove registry entry ${keyPath}: ${deleteError.message}`, 'DEBUG');
                      }
                    }
                  }
                }
              } catch (versionError) {
                // Skip if we can't read version
                logToFile(`Could not read version for ${keyPath}`, 'DEBUG');
              }
            }
          }
        }
      } catch (queryError) {
        // Skip this registry path if we can't access it
        logToFile(`Could not query registry path ${regPath}: ${queryError.message}`, 'DEBUG');
      }
    }
  } catch (error) {
    logToFile(`Error during registry cleanup: ${error.message}`, 'ERROR');
  }
}

// Function to clean up old auto-launch entries
function cleanupOldAutoLaunchEntries() {
  try {
    logToFile('Cleaning up old auto-launch entries...');
    
    const { execSync } = require('child_process');
    
    // Clean up old registry entries
    const autoLaunchKeys = [
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    ];
    
    for (const regKey of autoLaunchKeys) {
      try {
        // Look for old PulseGuard entries
        const command = `reg query "${regKey}" 2>nul | findstr /i "pulseguard"`;
        const stdout = execSync(command, { encoding: 'utf8', timeout: 5000 });
        
        if (stdout) {
          const lines = stdout.split('\n');
          for (const line of lines) {
            const match = line.trim().match(/(\w+)\s+REG_SZ\s+(.+)/);
            if (match) {
              const valueName = match[1];
              const executablePath = match[2].replace(/"/g, ''); // Remove quotes
              
              // If this is not the current executable path, remove it
              if (executablePath !== process.execPath && 
                  !executablePath.includes(path.basename(process.execPath)) &&
                  executablePath.toLowerCase().includes('pulseguard')) {
                try {
                  execSync(`reg delete "${regKey}" /v "${valueName}" /f`, { timeout: 5000 });
                  logToFile(`Removed old auto-launch entry: ${valueName} -> ${executablePath}`);
                } catch (deleteError) {
                  logToFile(`Could not remove auto-launch entry ${valueName}: ${deleteError.message}`, 'DEBUG');
                }
              }
            }
          }
        }
      } catch (queryError) {
        // Skip this registry key if we can't access it
        logToFile(`Could not query auto-launch registry ${regKey}: ${queryError.message}`, 'DEBUG');
      }
    }
    
    // Clean up old scheduled tasks
    try {
      const taskListCommand = `schtasks /query /fo csv | findstr /i "pulseguard"`;
      const stdout = execSync(taskListCommand, { encoding: 'utf8', timeout: 10000 });
      
      if (stdout) {
        const lines = stdout.split('\n');
        for (const line of lines) {
          if (line.includes('PulseGuard') || line.includes('pulseguard')) {
            // Parse CSV format: "TaskName","Status",...
            const taskMatch = line.match(/"([^"]*PulseGuard[^"]*)"/i);
            if (taskMatch) {
              const taskName = taskMatch[1];
              
              // Don't delete our current task
              if (taskName !== 'PulseGuard Agent Startup') {
                try {
                  execSync(`schtasks /delete /tn "${taskName}" /f`, { timeout: 5000 });
                  logToFile(`Removed old scheduled task: ${taskName}`);
                } catch (deleteError) {
                  logToFile(`Could not remove scheduled task ${taskName}: ${deleteError.message}`, 'DEBUG');
                }
              }
            }
          }
        }
      }
    } catch (taskError) {
      logToFile(`Could not query scheduled tasks: ${taskError.message}`, 'DEBUG');
    }
    
    // Also clean up startup folder shortcuts
    const startupFolders = [
      path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    ];
    
    for (const startupFolder of startupFolders) {
      if (fsSync.existsSync(startupFolder)) {
        try {
          const files = fsSync.readdirSync(startupFolder);
          for (const file of files) {
            if (file.toLowerCase().includes('pulseguard') && (file.endsWith('.lnk') || file.endsWith('.exe'))) {
              const fullPath = path.join(startupFolder, file);
              try {
                fsSync.unlinkSync(fullPath);
                logToFile(`Removed old startup file: ${fullPath}`);
              } catch (deleteError) {
                logToFile(`Could not remove startup file ${fullPath}: ${deleteError.message}`, 'DEBUG');
              }
            }
          }
        } catch (readError) {
          logToFile(`Could not read startup folder ${startupFolder}: ${readError.message}`, 'DEBUG');
        }
      }
    }
  } catch (error) {
    logToFile(`Error cleaning up auto-launch entries: ${error.message}`, 'ERROR');
  }
}

// Function to perform complete cleanup of old versions
function performOldVersionCleanup() {
  return new Promise(async (resolve) => {
    try {
      logToFile('Performing comprehensive cleanup of old PulseGuard versions...');
      
      // First, cleanup files (this includes process termination)
      cleanupOldVersions();
      
      // Wait a moment for file operations to complete
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Cleanup registry entries (Windows only)
      if (process.platform === 'win32') {
        cleanupOldRegistryEntries();
        
        // Wait for registry operations to complete
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
      
      // Perform a final check and log the results
      logToFile('Old version cleanup process completed successfully');
      
      // Check if auto-startup is working after cleanup
      setTimeout(async () => {
        try {
          const startupStatus = await checkAutoStartupStatus();
          const hasAnyStartup = Object.values(startupStatus).some(status => status === true);
          
          if (!hasAnyStartup) {
            logToFile('No auto-startup methods detected after cleanup, reconfiguring...', 'WARN');
            setupAutoLaunch();
          } else {
            logToFile(`Auto-startup status after cleanup: ${JSON.stringify(startupStatus)}`);
          }
        } catch (error) {
          logToFile(`Error checking auto-startup after cleanup: ${error.message}`, 'WARN');
        }
        resolve();
      }, 3000);
      
    } catch (error) {
      logToFile(`Error during cleanup: ${error.message}`, 'ERROR');
      resolve(); // Don't block startup even if cleanup fails
    }
  });
}

// Cleanup old versions from UI
ipcMain.on('cleanup-old-versions', async (event) => {
  try {
    logToFile('Manual cleanup of old versions requested from UI');
    performOldVersionCleanup();
    event.reply('cleanup-result', { success: true });
  } catch (error) {
    logToFile(`Manual cleanup failed: ${error.message}`, 'ERROR');
    event.reply('cleanup-result', { 
      success: false, 
      error: error.message 
    });
  }
});

// SSH Command Execution Functions
async function executeSshCommand(command, params = {}) {
    logToFile(`Executing SSH command: ${command}`, 'INFO');
    
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
            case 'get_event_logs':
                return await getEventLogs(params.logName, params.count);
            case 'get_installed_software':
                return await getInstalledSoftware();
            case 'get_environment_variables':
                return await getEnvironmentVariables();
            case 'set_environment_variable':
                return await setEnvironmentVariable(params.name, params.value, params.scope);
            case 'get_registry_value':
                return await getRegistryValue(params.key, params.value);
            case 'set_registry_value':
                return await setRegistryValue(params.key, params.value, params.data, params.type);
            case 'backup_files':
                return await backupFiles(params.sources, params.destination);
            case 'restore_files':
                return await restoreFiles(params.backup, params.destination);
            case 'system_scan':
                return await performSystemScan(params.type);
            case 'cleanup_temp':
                return await cleanupTempFiles();
            case 'defragment_disk':
                return await defragmentDisk(params.drive);
            case 'check_disk':
                return await checkDisk(params.drive, params.fix);
            default:
                throw new Error(`Unknown SSH command: ${command}`);
        }
    } catch (error) {
        logToFile(`SSH command error: ${error.message}`, 'ERROR');
        throw error;
    }
}

// Shell Command Execution
async function executeShellCommand(command, timeout = 30000) {
    return new Promise((resolve, reject) => {
        const { exec } = require('child_process');
        
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
        
        // Handle timeout manually
        setTimeout(() => {
            child.kill();
            reject(new Error(`Command timed out after ${timeout}ms`));
        }, timeout);
    });
}

// Process Management
async function getProcessList(filter = null) {
    try {
        const command = filter ? 
            `Get-Process | Where-Object { $_.Name -like "*${filter}*" } | Select-Object Id, ProcessName, CPU, WorkingSet, StartTime | ConvertTo-Json` :
            `Get-Process | Select-Object Id, ProcessName, CPU, WorkingSet, StartTime | ConvertTo-Json`;
        
        const result = await executeShellCommand(`powershell -Command "${command}"`);
        const processes = JSON.parse(result.stdout);
        
        return {
            success: true,
            processes: Array.isArray(processes) ? processes : [processes]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function killProcess(pid, force = false) {
    try {
        const command = force ? 
            `taskkill /PID ${pid} /F` : 
            `taskkill /PID ${pid}`;
        
        await executeShellCommand(command);
        return { success: true, message: `Process ${pid} terminated` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Service Management
async function getServicesList(status = null) {
    try {
        const command = status ? 
            `Get-Service | Where-Object { $_.Status -eq "${status}" } | Select-Object Name, Status, StartType, DisplayName | ConvertTo-Json` :
            `Get-Service | Select-Object Name, Status, StartType, DisplayName | ConvertTo-Json`;
        
        const result = await executeShellCommand(`powershell -Command "${command}"`);
        const services = JSON.parse(result.stdout);
        
        return {
            success: true,
            services: Array.isArray(services) ? services : [services]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function controlService(serviceName, action) {
    try {
        let command;
        switch (action) {
            case 'start':
                command = `Start-Service -Name "${serviceName}"`;
                break;
            case 'stop':
                command = `Stop-Service -Name "${serviceName}"`;
                break;
            case 'restart':
                command = `Restart-Service -Name "${serviceName}"`;
                break;
            case 'pause':
                command = `Suspend-Service -Name "${serviceName}"`;
                break;
            case 'resume':
                command = `Resume-Service -Name "${serviceName}"`;
                break;
            default:
                throw new Error(`Invalid service action: ${action}`);
        }
        
        await executeShellCommand(`powershell -Command "${command}"`);
        return { success: true, message: `Service ${serviceName} ${action}ed successfully` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// File Management
async function listDirectory(path, recursive = false) {
    try {
        const command = recursive ? 
            `Get-ChildItem -Path "${path}" -Recurse | Select-Object Name, FullName, Length, LastWriteTime, Attributes | ConvertTo-Json` :
            `Get-ChildItem -Path "${path}" | Select-Object Name, FullName, Length, LastWriteTime, Attributes | ConvertTo-Json`;
        
        const result = await executeShellCommand(`powershell -Command "${command}"`);
        const items = JSON.parse(result.stdout);
        
        return {
            success: true,
            items: Array.isArray(items) ? items : [items]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function createDirectory(path) {
    try {
        await executeShellCommand(`powershell -Command "New-Item -Path '${path}' -ItemType Directory -Force"`);
        return { success: true, message: `Directory created: ${path}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function deleteFile(path, force = false) {
    try {
        const command = force ? 
            `Remove-Item -Path "${path}" -Force -Recurse` :
            `Remove-Item -Path "${path}"`;
        
        await executeShellCommand(`powershell -Command "${command}"`);
        return { success: true, message: `File/Directory deleted: ${path}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function copyFile(source, destination) {
    try {
        await executeShellCommand(`powershell -Command "Copy-Item -Path '${source}' -Destination '${destination}' -Force"`);
        return { success: true, message: `File copied from ${source} to ${destination}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function moveFile(source, destination) {
    try {
        await executeShellCommand(`powershell -Command "Move-Item -Path '${source}' -Destination '${destination}' -Force"`);
        return { success: true, message: `File moved from ${source} to ${destination}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function readFile(path, lines = null) {
    try {
        const command = lines ? 
            `Get-Content -Path "${path}" -TotalCount ${lines}` :
            `Get-Content -Path "${path}"`;
        
        const result = await executeShellCommand(`powershell -Command "${command}"`);
        return {
            success: true,
            content: result.stdout,
            encoding: 'utf-8'
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function writeFile(path, content, append = false) {
    try {
        const command = append ? 
            `Add-Content -Path "${path}" -Value "${content}"` :
            `Set-Content -Path "${path}" -Value "${content}"`;
        
        await executeShellCommand(`powershell -Command "${command}"`);
        return { success: true, message: `File written: ${path}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getFileInfo(path) {
    try {
        const result = await executeShellCommand(`powershell -Command "Get-Item -Path '${path}' | Select-Object Name, FullName, Length, CreationTime, LastWriteTime, LastAccessTime, Attributes | ConvertTo-Json"`);
        const fileInfo = JSON.parse(result.stdout);
        
        return {
            success: true,
            fileInfo: fileInfo
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Network Diagnostics
async function networkPing(host, count = 4) {
    try {
        const result = await executeShellCommand(`ping -n ${count} ${host}`);
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
        const result = await executeShellCommand(`tracert ${host}`);
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
        let command = 'netstat -an';
        if (filter) {
            command += ` | findstr ${filter}`;
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
        const result = await executeShellCommand(`powershell -Command "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MediaType | ConvertTo-Json"`);
        const interfaces = JSON.parse(result.stdout);
        
        return {
            success: true,
            interfaces: Array.isArray(interfaces) ? interfaces : [interfaces]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// System Information
async function getDiskUsage(path = null) {
    try {
        const command = path ? 
            `Get-WmiObject -Class Win32_LogicalDisk | Where-Object { $_.DeviceID -eq "${path}" } | Select-Object DeviceID, Size, FreeSpace | ConvertTo-Json` :
            `Get-WmiObject -Class Win32_LogicalDisk | Select-Object DeviceID, Size, FreeSpace, VolumeName | ConvertTo-Json`;
        
        const result = await executeShellCommand(`powershell -Command "${command}"`);
        const disks = JSON.parse(result.stdout);
        
        return {
            success: true,
            disks: Array.isArray(disks) ? disks : [disks]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getEventLogs(logName = 'System', count = 100) {
    try {
        const result = await executeShellCommand(`powershell -Command "Get-EventLog -LogName ${logName} -Newest ${count} | Select-Object TimeGenerated, Source, EventID, EntryType, Message | ConvertTo-Json"`);
        const events = JSON.parse(result.stdout);
        
        return {
            success: true,
            events: Array.isArray(events) ? events : [events]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getInstalledSoftware() {
    try {
        const result = await executeShellCommand(`powershell -Command "Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor, InstallDate | ConvertTo-Json"`);
        const software = JSON.parse(result.stdout);
        
        return {
            success: true,
            software: Array.isArray(software) ? software : [software]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Environment and Registry
async function getEnvironmentVariables() {
    try {
        const result = await executeShellCommand(`powershell -Command "Get-ChildItem Env: | Select-Object Name, Value | ConvertTo-Json"`);
        const variables = JSON.parse(result.stdout);
        
        return {
            success: true,
            variables: Array.isArray(variables) ? variables : [variables]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function setEnvironmentVariable(name, value, scope = 'User') {
    try {
        await executeShellCommand(`powershell -Command "[Environment]::SetEnvironmentVariable('${name}', '${value}', '${scope}')"`);
        return { success: true, message: `Environment variable ${name} set to ${value}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function getRegistryValue(key, valueName) {
    try {
        const result = await executeShellCommand(`powershell -Command "Get-ItemProperty -Path '${key}' -Name '${valueName}' | ConvertTo-Json"`);
        const regValue = JSON.parse(result.stdout);
        
        return {
            success: true,
            value: regValue[valueName]
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function setRegistryValue(key, valueName, data, type = 'String') {
    try {
        await executeShellCommand(`powershell -Command "Set-ItemProperty -Path '${key}' -Name '${valueName}' -Value '${data}' -Type ${type}"`);
        return { success: true, message: `Registry value ${valueName} set in ${key}` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Maintenance Functions
async function cleanupTempFiles() {
    try {
        const commands = [
            'del /q /f /s %TEMP%\\*.*',
            'del /q /f /s C:\\Windows\\Temp\\*.*',
            'powershell -Command "Get-ChildItem -Path $env:TEMP -Recurse | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue"'
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

async function defragmentDisk(drive) {
    try {
        await executeShellCommand(`defrag ${drive}: /O`);
        return { success: true, message: `Disk ${drive}: defragmentation started` };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function checkDisk(drive, fix = false) {
    try {
        const command = fix ? 
            `chkdsk ${drive}: /f /r` : 
            `chkdsk ${drive}:`;
        
        const result = await executeShellCommand(command);
        return {
            success: true,
            output: result.stdout,
            drive: drive
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// Backup Functions
async function backupFiles(sources, destination) {
    try {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupPath = `${destination}\\backup_${timestamp}`;
        
        await executeShellCommand(`powershell -Command "New-Item -Path '${backupPath}' -ItemType Directory -Force"`);
        
        for (const source of sources) {
            await executeShellCommand(`powershell -Command "Copy-Item -Path '${source}' -Destination '${backupPath}' -Recurse -Force"`);
        }
        
        return {
            success: true,
            message: `Backup created at ${backupPath}`,
            backupPath: backupPath
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function restoreFiles(backupPath, destination) {
    try {
        await executeShellCommand(`powershell -Command "Copy-Item -Path '${backupPath}\\*' -Destination '${destination}' -Recurse -Force"`);
        return {
            success: true,
            message: `Files restored from ${backupPath} to ${destination}`
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

// System Scan
async function performSystemScan(type = 'quick') {
    try {
        let command;
        switch (type) {
            case 'sfc':
                command = 'sfc /scannow';
                break;
            case 'dism':
                command = 'DISM /Online /Cleanup-Image /RestoreHealth';
                break;
            case 'memory':
                command = 'mdsched';
                break;
            default:
                command = 'sfc /verifyonly';
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

// API endpoint handlers
expressApp.get('/api/status', (req, res) => {
    res.json({
        status: 'running',
        version: '1.0.0',
        device_uuid: config.device_uuid || 'not-configured',
        uptime: process.uptime()
    });
});

// New SSH Command endpoint
expressApp.post('/api/ssh-command', async (req, res) => {
    try {
        const { command, params = {}, timeout = 30000 } = req.body;
        
        if (!command) {
            return res.status(400).json({
                success: false,
                error: 'Command is required'
            });
        }
        
        logToFile(`Received SSH command: ${command} with params: ${JSON.stringify(params)}`, 'INFO');
        
        // Execute the SSH command
        const result = await executeSshCommand(command, params);
        
        logToFile(`SSH command ${command} completed successfully`, 'INFO');
        res.json({
            success: true,
            result: result,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        logToFile(`SSH command error: ${error.message}`, 'ERROR');
        res.status(500).json({
            success: false,
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// File upload endpoint for file management
expressApp.post('/api/upload-file', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                success: false,
                error: 'No file uploaded'
            });
        }
        
        const { destination } = req.body;
        const sourcePath = req.file.path;
        const targetPath = destination || path.join(__dirname, 'uploads', req.file.filename);
        
        // Move the uploaded file to the target location
        await executeShellCommand(`powershell -Command "Move-Item -Path '${sourcePath}' -Destination '${targetPath}' -Force"`);
        
        res.json({
            success: true,
            message: `File uploaded to ${targetPath}`,
            filename: req.file.filename,
            path: targetPath
        });
        
    } catch (error) {
        logToFile(`File upload error: ${error.message}`, 'ERROR');
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// File download endpoint
expressApp.get('/api/download-file', async (req, res) => {
    try {
        const { path: filePath } = req.query;
        
        if (!filePath) {
            return res.status(400).json({
                success: false,
                error: 'File path is required'
            });
        }
        
        // Check if file exists
        const fileInfo = await getFileInfo(filePath);
        if (!fileInfo.success) {
            return res.status(404).json({
                success: false,
                error: 'File not found'
            });
        }
        
        // Send the file
        res.download(filePath, (err) => {
            if (err) {
                logToFile(`File download error: ${err.message}`, 'ERROR');
                if (!res.headersSent) {
                    res.status(500).json({
                        success: false,
                        error: 'Download failed'
                    });
                }
            }
        });
        
    } catch (error) {
        logToFile(`File download error: ${error.message}`, 'ERROR');
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Remote terminal endpoint for real-time command execution
expressApp.post('/api/terminal', async (req, res) => {
    try {
        const { command, workingDirectory } = req.body;
        
        if (!command) {
            return res.status(400).json({
                success: false,
                error: 'Command is required'
            });
        }
        
        // Change to working directory if specified
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

// Start Express server
function startExpressServer() {
    expressApp.listen(PORT, '127.0.0.1', () => {
        logToFile(`Express server started on port ${PORT}`, 'INFO');
    });
}

// Function to check if auto-startup is properly configured
async function checkAutoStartupStatus() {
  const status = {
    autoLaunchLibrary: false,
    registryUser: false,
    registrySystem: false,
    scheduledTask: false,
    startupFolder: false
  };
  
  try {
    const { execSync } = require('child_process');
    
    // Check auto-launch library
    try {
      const autoLauncher = new AutoLaunch({
        name: 'PulseGuard Agent',
        path: process.execPath
      });
      status.autoLaunchLibrary = await autoLauncher.isEnabled();
    } catch (error) {
      logToFile(`Auto-launch library check failed: ${error.message}`, 'DEBUG');
    }
    
    // Check user registry
    try {
      const userRegCommand = `reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "PulseGuardAgent" 2>nul`;
      const userResult = execSync(userRegCommand, { encoding: 'utf8' });
      status.registryUser = userResult.includes(process.execPath) || userResult.includes('PulseGuardAgent');
    } catch (error) {
      // Key doesn't exist
    }
    
    // Check system registry (if we have admin rights)
    try {
      const systemRegCommand = `reg query "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "PulseGuardAgent" 2>nul`;
      const systemResult = execSync(systemRegCommand, { encoding: 'utf8' });
      status.registrySystem = systemResult.includes(process.execPath) || systemResult.includes('PulseGuardAgent');
    } catch (error) {
      // Key doesn't exist or no admin rights
    }
    
    // Check scheduled task
    try {
      const taskCommand = `schtasks /query /tn "PulseGuard Agent Startup" 2>nul`;
      const taskResult = execSync(taskCommand, { encoding: 'utf8' });
      status.scheduledTask = taskResult.includes('PulseGuard Agent Startup') && taskResult.includes('Ready');
    } catch (error) {
      // Task doesn't exist
    }
    
    // Check startup folders
    const startupFolders = [
      path.join(os.homedir(), 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
      path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    ];
    
    for (const startupFolder of startupFolders) {
      if (fsSync.existsSync(startupFolder)) {
        try {
          const files = fsSync.readdirSync(startupFolder);
          const hasStartupFile = files.some(file => 
            file.toLowerCase().includes('pulseguard') && 
            (file.endsWith('.lnk') || file.endsWith('.exe'))
          );
          if (hasStartupFile) {
            status.startupFolder = true;
            break;
          }
        } catch (error) {
          // Can't read folder
        }
      }
    }
    
    logToFile(`Auto-startup status: ${JSON.stringify(status)}`);
    return status;
  } catch (error) {
    logToFile(`Error checking auto-startup status: ${error.message}`, 'ERROR');
    return status;
  }
}

// IPC handler to check auto-startup status from UI
ipcMain.on('check-autostart-status', async (event) => {
  try {
    const status = await checkAutoStartupStatus();
    event.reply('autostart-status-result', { success: true, status });
  } catch (error) {
    logToFile(`Auto-startup status check failed: ${error.message}`, 'ERROR');
    event.reply('autostart-status-result', { 
      success: false, 
      error: error.message 
    });
  }
});

// IPC handler to force auto-startup setup from UI
ipcMain.on('setup-autostart', async (event) => {
  try {
    logToFile('Manual auto-startup setup requested from UI');
    setupAutoLaunch();
    
    // Wait a moment and then check status
    setTimeout(async () => {
      const status = await checkAutoStartupStatus();
      event.reply('autostart-setup-result', { success: true, status });
    }, 2000);
  } catch (error) {
    logToFile(`Manual auto-startup setup failed: ${error.message}`, 'ERROR');
    event.reply('autostart-setup-result', { 
      success: false, 
      error: error.message 
    });
  }
});