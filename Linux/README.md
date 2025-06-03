# PulseGuard Agent for Linux

This is the Linux version of the PulseGuard Agent, a monitoring tool that sends system metrics to the PulseGuard dashboard.

## Installation

### Prerequisites
- Node.js 14 or higher
- npm

### Building from source
1. Clone the repository
2. Navigate to the Linux directory
3. Run `npm install` to install dependencies
4. Run `npm start` to start the application in development mode
5. Run `npm run build` to build the application for distribution

### Using pre-built packages
- Download the latest .deb package or AppImage from the releases page
- For .deb: `sudo dpkg -i pulseguard-agent_x.y.z.deb`
- For AppImage: Make the file executable and run it

## Configuration
- The agent requires a Device UUID and API Token from the PulseGuard dashboard
- Configuration is stored in `~/.config/pulseguard/config.json`
- System-wide configuration (when installed as root) is stored in `/etc/pulseguard/config.json`
- Logs are stored in `/var/log/pulseguard/agent.log` or `~/.config/pulseguard/agent.log`

## Features
- System metrics collection (CPU, memory, disk usage)
- Remote power management (shutdown, restart, sleep, lock)
- Automatic updates
- SSH server management

## Running as a service
To run the agent as a system service:
1. Install the agent as root
2. The agent will automatically create a systemd service
3. You can manage it with: `systemctl start/stop/restart pulseguard`

## Support
For support, please contact PulseGuard support or visit the PulseGuard dashboard. 