const fs = require('fs');
const path = require('path');

// Paths
const electronModulePath = path.join(__dirname, 'node_modules', 'electron', 'dist');
const ffmpegDistPath = path.join(electronModulePath, 'ffmpeg.dll');
const ffmpegStaticPath = path.join(__dirname, 'node_modules', 'ffmpeg-static');
const destPath = path.join(__dirname, 'ffmpeg.dll');
const resourcesDir = path.join(__dirname, 'resources');
const buildDir = path.join(__dirname, 'build');

// Create necessary directories
console.log('Creating necessary directories...');
if (!fs.existsSync(resourcesDir)) {
  fs.mkdirSync(resourcesDir, { recursive: true });
}

if (!fs.existsSync(buildDir)) {
  fs.mkdirSync(buildDir, { recursive: true });
}

console.log('Copying ffmpeg.dll files...');

// First try to copy from electron/dist
try {
  if (fs.existsSync(ffmpegDistPath)) {
    console.log(`Copying from: ${ffmpegDistPath}`);
    fs.copyFileSync(ffmpegDistPath, destPath);
    
    // Also copy to resources directory
    const resourceDestPath = path.join(resourcesDir, 'ffmpeg.dll');
    fs.copyFileSync(ffmpegDistPath, resourceDestPath);
    
    console.log(`Successfully copied ffmpeg.dll to: ${destPath}`);
  } else {
    console.log('ffmpeg.dll not found in electron/dist, trying ffmpeg-static');
    
    // If not found, try to find in ffmpeg-static
    let ffmpegBinaryPath = '';
    try {
      ffmpegBinaryPath = require('ffmpeg-static');
      console.log(`Found ffmpeg binary at: ${ffmpegBinaryPath}`);
      
      // Extract directory
      const ffmpegDir = path.dirname(ffmpegBinaryPath);
      const possibleDllPath = path.join(ffmpegDir, 'ffmpeg.dll');
      
      if (fs.existsSync(possibleDllPath)) {
        console.log(`Copying from: ${possibleDllPath}`);
        fs.copyFileSync(possibleDllPath, destPath);
        
        // Also copy to resources directory
        const resourceDestPath = path.join(resourcesDir, 'ffmpeg.dll');
        fs.copyFileSync(possibleDllPath, resourceDestPath);
        
        console.log(`Successfully copied ffmpeg.dll to: ${destPath}`);
      } else {
        console.error('Could not find ffmpeg.dll in ffmpeg-static directory');
      }
      
      // Also copy ffmpeg.exe to resources
      const resourceExePath = path.join(resourcesDir, 'ffmpeg.exe');
      fs.copyFileSync(ffmpegBinaryPath, resourceExePath);
      console.log(`Copied ffmpeg.exe to: ${resourceExePath}`);
    } catch (error) {
      console.error('Error finding ffmpeg-static: ', error);
    }
  }
  
  // Copy website-icon.png to use as the application icon
  const iconsDir = path.join(buildDir, 'icons');
  if (!fs.existsSync(iconsDir)) {
    fs.mkdirSync(iconsDir, { recursive: true });
  }
  
  // Make sure the assets directory exists and has the website-icon.png
  const assetsDir = path.join(__dirname, 'assets');
  if (!fs.existsSync(assetsDir)) {
    fs.mkdirSync(assetsDir, { recursive: true });
  }
  
  // If the icon doesn't exist, create a dummy icon
  const iconSrc = path.join(assetsDir, 'website-icon.png');
  if (!fs.existsSync(iconSrc)) {
    console.log('Icon file not found, creating a dummy icon');
    
    // Use a sample PNG file or create a basic one
    try {
      // Sample 16x16 PNG data (a simple black square)
      const pngData = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABGdBTUEAAK/INwWK6QAAABl0RVh0U29mdHdhcmUAQWRvYmUgSW1hZ2VSZWFkeXHJZTwAAAATSURBVHjaYvj//z8DJYCJgUIAEGAAQPcB4Lgc8FsAAAAASUVORK5CYII=', 'base64');
      fs.writeFileSync(iconSrc, pngData);
      console.log(`Created dummy icon at ${iconSrc}`);
    } catch (error) {
      console.error('Error creating dummy icon:', error);
    }
  }
} catch (error) {
  console.error('Error in setup process:', error);
} 