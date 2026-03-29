const fs = require('fs');
const filepath = "c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js";
let code = fs.readFileSync(filepath, 'utf8');

// We need to keep only the FIRST definition of each engine.
// Let's just find the first instance of `// ============================================================================
// PHASE 1: ZERO-DAY VISUAL & DOM LAYOUT ENGINE
// ============================================================================`
// and completely replace the end of the file. No, let's just strip everything from the first PHASE 1 occurrence, and re-append a pristine copy of all phases!

let phase1Index = code.indexOf("// PHASE 1: ZERO-DAY");
if (phase1Index !== -1) {
    // Find the enclosing line matching `// ============` right before PHASE 1
    let cutoff = code.lastIndexOf("// ====", phase1Index);
    code = code.substring(0, cutoff);
}

fs.writeFileSync(filepath, code);
console.log("Stripped appended phases. Length is now " + code.length);
