const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/app.js';
let code = fs.readFileSync(filepath, 'utf8');

code = code.replace(/}, 30000\);/g, '}, 2000);');

fs.writeFileSync(filepath, code);
console.log("Dashboard real-time polling interval updated to 2000ms!");
