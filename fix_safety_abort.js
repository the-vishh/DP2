const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

const oldAbort = /document\.getElementById\('phishguard-go-back'\)\.onclick = \(\) => {[\s\S]*?};/m;
const newAbort = `document.getElementById('phishguard-go-back').onclick = () => {
        reportToBackground('userAction', { action: 'went_back', alertType: type });
        // Instead of conditionally going back, forcefully navigate them to Google or a blank safety page,
        // and notify the background script to close the tab if possible.
        chrome.runtime.sendMessage({ action: "closeCurrentTab" }, (response) => {
            if (chrome.runtime.lastError) {
                // If background closing fails, replace the dom immediately as fallback
                document.documentElement.innerHTML = "<div style='display:flex;height:100vh;width:100vw;align-items:center;justify-content:center;background:#0f172a;color:#38bdf8;font-family:sans-serif;font-size:24px;'><h1>Ìª°Ô∏è PhishGuard: Threat Neutralized. Connection Severed Safely.</h1></div>";
                window.location.replace("about:blank");
            }
        });
      };`;

if (code.match(oldAbort)) {
    code = code.replace(oldAbort, newAbort);
    fs.writeFileSync(filepath, code);
    console.log("Safety Abort logic forcefully patched!");
} else {
    console.log("Could not find Safety Abort logic");
}
