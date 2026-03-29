const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

// replace the event listener for Web3 alert to include an alert for debug
code = code.replace(/window\.addEventListener\('message', \(event\) => {[\s\S]*?showInPageWarning\("WEB3_WALLET_DRAINER", { method: event\.data\.method }\);/m, 
`window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.type !== 'PHISHGUARD_WEB3_ALERT') {
          return;
        }
        console.log("PHISHGUARD WEB3 EVENT RECEIVED IN CONTENT SCRIPT:", event.data);
        showInPageWarning("WEB3_WALLET_DRAINER", { method: event.data.method });`);

fs.writeFileSync(filepath, code);
