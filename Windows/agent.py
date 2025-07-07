import requests
import json
import os
import sys
import time
import psutil
import subprocess
import logging
from pathlib import Path
import platform
import threading
import asyncio
import websockets

# --- Windows Service Imports ---
# This block will only work on Windows with pywin32 installed.
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

# --- Agent Configuration ---
SERVICE_NAME = "PulseGuardAgent"
SERVICE_DISPLAY_NAME = "PulseGuard Monitoring Agent"
SERVICE_DESCRIPTION = "Actively monitors this system and reports metrics to PulseGuard."

def get_base_path():
    """Gets the base path for the executable or script."""
    if getattr(sys, 'frozen', False):
        # The application is frozen (packaged by PyInstaller)
        return Path(sys.executable).parent
    else:
        # The application is running as a normal Python script
        return Path(__file__).parent

# Set up logging to a file in the agent's directory
log_file_path = get_base_path() / "agent.log"
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

# --- Agent Logic (Functions remain mostly the same) ---

CONFIG_CACHE = None
CONFIG_LOCK = threading.Lock()

def load_config(force_reload=False):
    """Loads configuration from config.json, with caching."""
    global CONFIG_CACHE
    with CONFIG_LOCK:
        if CONFIG_CACHE and not force_reload:
            return CONFIG_CACHE
        
        config_path = get_base_path() / "config.json"
        logging.info(f"Loading configuration from: {config_path}")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            if not config.get("api_url") or not config.get("api_token"):
                logging.error("api_url and api_token must be set in config.json")
                return None
            
            # Add websocket_url to config, default to empty string if not present
            if "websocket_url" not in config:
                config["websocket_url"] = ""

            logging.info("Configuration loaded successfully.")
            CONFIG_CACHE = config
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file not found at {config_path}")
            return None
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading config: {e}")
            return None

def collect_metrics(config):
    """Gathers system metrics."""
    try:
        hostname = os.environ.get("COMPUTERNAME", "unknown")
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        try:
            disk_info = psutil.disk_usage('C:\\')
            disk_usage = disk_info.percent
        except FileNotFoundError:
            logging.warning("C:\\ drive not found. Reporting 0 disk usage.")
            disk_usage = 0
        boot_time_timestamp = psutil.boot_time()
        uptime_seconds = int(time.time() - boot_time_timestamp)
        
        os_version = platform.platform(terse=True)
        
        return {
            "token": config["api_token"],
            "hostname": hostname,
            "cpu_usage": round(cpu_usage, 2),
            "memory_usage": round(memory_info.percent, 2),
            "disk_usage": round(disk_usage, 2),
            "uptime_seconds": uptime_seconds,
            "os_version": os_version,
            "os_type": "windows",
        }
    except Exception as e:
        logging.error(f"Error collecting metrics: {e}")
        return None

def run_command(command, path):
    """Executes a shell command safely."""
    if not os.path.isdir(path):
        return f"Error: Path '{path}' does not exist or is not a directory.", True

    try:
        # Use PowerShell on Windows, sh on Linux/macOS
        shell = ["powershell.exe", "-NoProfile", "-Command"] if sys.platform == "win32" else ["/bin/sh", "-c"]
        process = subprocess.run(
            shell + [command],
            cwd=path,
            capture_output=True,
            text=True,
            timeout=30,  # 30-second timeout for commands
            check=False # Do not raise exception on non-zero exit codes
        )
        
        if process.returncode != 0:
            # Return stderr if there's an error
            return process.stderr or f"Command failed with exit code {process.returncode}", True
        else:
            # Return stdout on success
            return process.stdout, False
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds.", True
    except Exception as e:
        return f"An unexpected error occurred: {e}", True

def handle_power_command(command):
    """Executes power commands."""
    if not command: return
    logging.info(f"Received power command: {command}")
    command_map = {
        "restart": ["shutdown", "/r", "/t", "5", "/c", "PulseGuard Agent requested a restart."],
        "shutdown": ["shutdown", "/s", "/t", "5", "/c", "PulseGuard Agent requested a shutdown."],
    }
    if command in command_map:
        try:
            subprocess.run(command_map[command], check=True, capture_output=True, text=True)
            logging.info(f"Successfully executed power command: {command}")
        except Exception as e:
            logging.error(f"Failed to execute power command '{command}'. Error: {e}")
    else:
        logging.warning(f"Unknown power command received: {command}")

def perform_check_in(config):
    """Performs a single check-in to the backend."""
    metrics = collect_metrics(config)
    if not metrics:
        return config.get("check_interval", 60)

    check_in_url = f"{config['api_url']}/api/devices/check-in"
    logging.info(f"Checking in to {check_in_url}")

    try:
        response = requests.post(
            check_in_url, json=metrics,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=30
        )
        response.raise_for_status()
        data = response.json()
        if data.get("success"):
            logging.info(f"Check-in successful. Message: {data.get('message')}")
            handle_power_command(data.get("power_command"))
            return data.get("check_interval", 60)
        else:
            logging.warning(f"Check-in was not successful: {data.get('message')}")
    except Exception as e:
        logging.error(f"An error occurred during check-in: {e}")
    
    return config.get("check_interval", 60)

# --- WebSocket Remote Terminal Client ---

async def websocket_client_handler():
    """Handles the persistent WebSocket client connection to the main server."""
    global agent_config
    
    ws_url = agent_config.get("websocket_url")
    api_token = agent_config.get("api_token")

    if not ws_url:
        logging.info("WebSocket client is disabled (websocket_url is not set in config).")
        return
        
    # Append the token as a query parameter for authentication on the server
    auth_ws_url = f"{ws_url}?token={api_token}"

    while True:
        try:
            async with websockets.connect(auth_ws_url) as websocket:
                logging.info(f"Successfully connected to WebSocket server at {ws_url}")
                
                # Listen for incoming commands from the server
                async for message in websocket:
                    try:
                        data = json.loads(message)
                        logging.info(f"Received command from server: {data.get('command')}")
                        
                        response_data = {}
                        command_type = data.get('command')

                        if command_type == 'get_processes':
                            processes_json_str = get_processes()
                            processes_data = json.loads(processes_json_str)
                            if 'error' in processes_data:
                                response_data = {'type': 'error', 'message': processes_data['error']}
                            else:
                                response_data = {'type': 'processes', 'data': processes_data}
                        else:
                            # Default to terminal command execution
                            command_result_str = execute_command(data)
                            command_result = json.loads(command_result_str)
                            
                            if 'error' in command_result:
                                response_data = {'type': 'terminal', 'error': command_result['error'], 'path': command_result.get('path')}
                            else:
                                response_data = {
                                    'type': 'terminal',
                                    'output': command_result.get('output', ''),
                                    'path': command_result.get('path')
                                }
                        
                        # Include the original client_id in the response for server-side routing
                        if 'client_id' in data:
                            response_data['client_id'] = data['client_id']

                        await websocket.send(json.dumps(response_data))

                    except json.JSONDecodeError:
                        logging.error("Failed to decode JSON from server message.")
                    except Exception as e:
                        logging.error(f"Error processing command from server: {e}")

        except (websockets.exceptions.ConnectionClosedError, websockets.exceptions.InvalidURI, ConnectionRefusedError) as e:
            logging.warning(f"WebSocket connection failed: {e}. Retrying in 60 seconds...")
        except Exception as e:
            logging.error(f"An unexpected WebSocket error occurred: {e}. Retrying in 60 seconds...")
        
        await asyncio.sleep(60) # Wait before trying to reconnect


def start_websocket_client():
    """Starts the WebSocket client in a new thread."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    logging.info("Starting WebSocket client...")
    loop.run_until_complete(websocket_client_handler())


# --- Windows Service Class ---

class PulseGuardAgentService(win32serviceutil.ServiceFramework if IS_WINDOWS else object):
    if IS_WINDOWS:
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        if IS_WINDOWS:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_running = True
            self.ws_thread = None
        
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main_loop()

    def main_loop(self):
        """This is the main loop of the service."""
        # Start the WebSocket client in a background thread
        self.ws_thread = threading.Thread(target=start_websocket_client, daemon=True)
        self.ws_thread.start()
        logging.info("WebSocket client thread started.")

        logging.info("PulseGuard Agent Service starting...")
        global agent_config
        agent_config = load_config()
        if not agent_config:
            logging.error("Agent exiting due to configuration error.")
            return

        check_interval = agent_config.get("check_interval", 60)
        
        try:
            new_interval = perform_check_in(agent_config)
            if new_interval: check_interval = new_interval
        except Exception as e:
            logging.error(f"An error occurred during initial check-in: {e}")

        while self.is_running if IS_WINDOWS else True:
            try:
                # In service mode, we wait for the stop event.
                # In debug mode, this will just be a sleep.
                if IS_WINDOWS:
                    rc = win32event.WaitForSingleObject(self.hWaitStop, check_interval * 1000)
                    if rc == win32event.WAIT_OBJECT_0:
                        # Stop signal received
                        break
                else:
                    time.sleep(check_interval)

                new_interval = perform_check_in(agent_config)
                if new_interval and new_interval != check_interval:
                    check_interval = new_interval
                    logging.info(f"Check interval updated to {check_interval} seconds.")
            
            except KeyboardInterrupt:
                logging.info("Shutdown signal received.")
                break
            except Exception as e:
                logging.error(f"An unexpected error occurred in the main loop: {e}")
                time.sleep(60)
        
        logging.info("Agent main loop finished.")

def debug_run():
    """Runs the agent logic directly for debugging purposes."""
    agent = PulseGuardAgentService(sys.argv)
    agent.main_loop()

if __name__ == '__main__':
    if IS_WINDOWS:
        if len(sys.argv) == 1:
            # When run with no arguments, try to start as a service
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(PulseGuardAgentService)
                servicemanager.StartServiceCtrlDispatcher()
            except win32service.error as ex:
                # If not a service, it might be an interactive session
                if ex.winerror == 1063:
                     debug_run()
                else:
                    raise
        else:
            # Handle command-line arguments like 'install', 'start', 'stop'
            if sys.argv[1].lower() == 'debug':
                debug_run()
            else:
                win32serviceutil.HandleCommandLine(PulseGuardAgentService)
    else:
        # Fallback for non-windows environments for simple testing
        logging.info("Running in non-Windows debug mode.")
        debug_run() 