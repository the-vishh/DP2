const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/background.js';
let code = fs.readFileSync(filepath, 'utf8');

const oldListener = /chrome\.runtime\.onMessage\.addListener\(\(message, sender, sendResponse\) => \{/;
const newListener = `chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "closeCurrentTab" && sender.tab) {
    chrome.tabs.remove(sender.tab.id);
    return true;
  }`;

if (code.match(oldListener)) {
    code = code.replace(oldListener, newListener);
    fs.writeFileSync(filepath, code);
    console.log("Background script patched to allow tab closing!");
} else {
    console.log("Could not find onMessage listener");
}
