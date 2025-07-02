const Service = require('node-windows').Service;
const path = require('path');

// Create a new service object
const svc = new Service({
  name: 'PulseGuard Agent',
  script: path.join(__dirname, 'main.js')
});

// Listen for the "uninstall" event
svc.on('uninstall', function() {
  console.log('PulseGuard Agent service uninstalled.');
});

// Listen for the "error" event
svc.on('error', function(err) {
  console.log('An error occurred during uninstall: ', err);
});

// Uninstall the service.
if (process.argv[2] === 'uninstall') {
    console.log('Uninstalling PulseGuard Agent service...');
    svc.uninstall();
} else {
    console.log('This script should be run with the "uninstall" argument.');
} 