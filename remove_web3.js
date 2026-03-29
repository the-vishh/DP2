const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

const regex = /\s*\/\/ ============================================================================\s*\/\/ PHASE 5: WEB3 \/ DECENTRALIZED PROTECTION\s*\/\/ ============================================================================\s*const Web3Interceptor = \{[\s\S]*?Web3Interceptor\.init\(\);\s*/;

if (code.match(regex)) {
    code = code.replace(regex, '\n\n');
    fs.writeFileSync(filepath, code);
    console.log("Successfully removed Web3 Engine");
} else {
    console.log("Could not find Web3 logic to remove");
}
