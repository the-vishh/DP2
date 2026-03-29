const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/index.html';
let code = fs.readFileSync(filepath, 'utf8');

// Replace any corrupted characters inside the h1 tag
code = code.replace(/<h1>.*?PhishGuard Test Environment<\/h1>/, '<h1>PhishGuard Test Environment</h1>');

fs.writeFileSync(filepath, code);
console.log("Title fixed in index.html");
