const fs = require('fs');
const path = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(path, 'utf8');

// Disable localhost bypasses so the extension functions on our local test server
code = code.replace(/if\s*\(hostname\s*===\s*"localhost"\s*\|\|\s*hostname\s*===\s*"127\.0\.0\.1"\s*\|\|\s*hostname\s*===\s*""\)\s*return;/g, '// Localhost check disabled for testing');
code = code.replace(/if\s*\(!hostname\s*\|\|\s*hostname\s*===\s*"localhost"\s*\|\|\s*hostname\s*===\s*"127\.0\.0\.1"\)\s*return;/g, '// Localhost check disabled for testing');

fs.writeFileSync(path, code);
console.log("Successfully patched content_script.js to allow testing on localhost!");
