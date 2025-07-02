const Service = require('node-windows').Service;
const path = require('path');

// Create a new service object
const svc = new Service({
  name: 'PulseGuard Agent',
  description: 'The PulseGuard monitoring agent.',
  script: path.join(__dirname, 'main.js'),
  nodeOptions: [
    '--harmony',
    '--max_old_space_size=4096'
  ],
  //, workingDirectory: 'C:\\...\\path\\to\\your\\project'
  //, allowServiceLogon: true
});

// Listen for the "install" event, which indicates the
// process is available as a service.
svc.on('install', function() {
  console.log('PulseGuard Agent service installed.');
  console.log('The service exists: ', svc.exists);
  svc.start();
  console.log('PulseGuard Agent service started.');
});

// Listen for the "alreadyinstalled" event
svc.on('alreadyinstalled', function() {
  console.log('PulseGuard Agent service is already installed.');
});

// Listen for the "invalidinstallation" event
svc.on('invalidinstallation', function() {
  console.log('Invalid installation.');
});

// Listen for the "uninstall" event
svc.on('uninstall', function() {
  console.log('PulseGuard Agent service uninstalled.');
  console.log('The service exists: ', svc.exists);
});

// Listen for the "error" event
svc.on('error', function(err) {
  console.log('An error occurred: ', err);
});

// Install the service.
if (process.argv[2] === 'install') {
  console.log('Installing PulseGuard Agent service...');
  svc.install();
} else {
  console.log('This script should be run with the "install" argument.');
} 