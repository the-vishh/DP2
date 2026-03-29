const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

// Replace the messed up block
const regex = /document\.getElementById\('phishguard-go-back'\)\.onclick = \(\) => {[\s\S]*?};\s*\n\s*document\.getElementById\('phishguard-continue'\)\.onclick/m;

const replacement = `document.getElementById('phishguard-go-back').onclick = () => {
      overlay.remove();
      reportToBackground('userAction', { action: 'went_back', alertType: type });
      if (window.history.length > 2) {
          window.history.back();
      } else {
          document.body.innerHTML = "<div style='display:flex;height:100vh;width:100vw;align-items:center;justify-content:center;background:#0f172a;color:#38bdf8;font-family:sans-serif;font-size:24px;'><h1>Ìª°Ô∏è PhishGuard: Threat Neutralized. Connection Severed Safely.</h1></div>";
      }
    };

    document.getElementById('phishguard-continue').onclick`;

code = code.replace(regex, replacement);

fs.writeFileSync(filepath, code);
console.log("Safety Abort fixed cleanly!");
