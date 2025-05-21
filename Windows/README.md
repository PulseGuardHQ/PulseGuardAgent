# PulseGuard Agent for Windows

This is the Windows agent application for PulseGuard monitoring services. It collects system metrics and sends them to the PulseGuard server.

## Features

- Monitors CPU, memory and disk usage
- Runs in the background with system tray icon
- Automatically starts with Windows
- Adjustable check interval
- Full system information collection
- Power management capabilities (restart, shutdown, sleep, lock)

## Requirements

- Windows 7/8/10/11
- Internet connection
- Node.js (for development only)

## Installation

1. Download the latest release from the releases page
2. Run the installer
3. Enter your Device UUID and API Token when prompted
4. The agent will start automatically

## For Developers

### Setup Development Environment

1. Clone the repository
2. Install dependencies:
```
npm install
```

3. Run the application in development mode:
```
npm start
```

### Building an Executable

To build a standalone Windows executable:

```
npm run package-win
```

This will create a distributable package in the `dist` folder.

To build an installer:

```
npm run build
```

## Configuration

Configuration is stored in `%PROGRAMDATA%\PulseGuard\config.json` and includes:

- API token
- Device UUID
- Check interval
- API URL

## Power Management

The PulseGuard Agent supports remote power management features:

- **Lock** - Locks the computer
- **Sleep** - Puts the computer into sleep mode
- **Restart** - Restarts the computer with a 5-second delay
- **Shutdown** - Shuts down the computer with a 5-second delay

These commands can be sent from the PulseGuard dashboard and will be executed during the next agent check-in.

**Note:** Power management commands require administrative privileges. Make sure the agent is installed and running with the appropriate permissions.

## Troubleshooting

Logs are stored in `%PROGRAMDATA%\PulseGuard\logs\agent.log`

Common issues:
- **Agent not connecting**: Check your internet connection and firewall settings
- **High CPU usage**: Check your check interval settings
- **Agent not starting**: Run as administrator or check Windows event logs

## License

MIT License - See LICENSE file for details 