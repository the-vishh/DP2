const fs = require('fs');
const path = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(path, 'utf8');

const regex = /document\.getElementById\('phishguard-go-back'\)\.onclick = \(\) => \{[\s\S]*?\}\);[\s\S]*?\};/g;

const newCode = `document.getElementById('phishguard-go-back').onclick = () => {
      reportToBackground('userAction', { action: 'went_back', alertType: type });
      try { window.close(); } catch(e) {}
      chrome.runtime.sendMessage({ action: "closeCurrentTab" });
    };`;

code = code.replace(regex, newCode);
fs.writeFileSync(path, code);
console.log("Replaced strict abort logic");
