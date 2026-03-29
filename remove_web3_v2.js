const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let code = fs.readFileSync(filepath, 'utf8');

const regex = /\/\/ PHASE 5: WEB3 \/ DECENTRALIZED PROTECTION[\s\S]*?Web3Interceptor\.init\(\);/m;

if (code.match(regex)) {
    code = code.replace(regex, '');
    
    // Also remove the empty comment header for Phase 5 if it exists right before
    code = code.replace(/\/\/ ============================================================================\s*\/\/ ============================================================================\s*/g, '');
    
    fs.writeFileSync(filepath, code);
    console.log("Successfully removed Web3 Engine");
} else {
    console.log("Still failed to match");
}
