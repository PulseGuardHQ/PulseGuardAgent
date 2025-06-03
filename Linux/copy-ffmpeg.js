const fs = require('fs');
const path = require('path');

try {
  // Get the path to ffmpeg-static
  const ffmpegPath = require('ffmpeg-static');
  console.log(`Found ffmpeg at: ${ffmpegPath}`);
  
  // Create a destination directory if it doesn't exist
  const destDir = path.join(__dirname, 'bin');
  if (!fs.existsSync(destDir)) {
    fs.mkdirSync(destDir, { recursive: true });
  }
  
  // Copy the ffmpeg binary
  const destPath = path.join(destDir, 'ffmpeg');
  fs.copyFileSync(ffmpegPath, destPath);
  fs.chmodSync(destPath, 0o755); // Make it executable
  
  console.log(`Successfully copied ffmpeg to ${destPath}`);
} catch (error) {
  console.error(`Error copying ffmpeg: ${error.message}`);
  process.exit(1);
} 