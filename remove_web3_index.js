const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/index.html';
let code = fs.readFileSync(filepath, 'utf8');

const regex = /<div class="test-card" style="border-left-color: #eab308;">[\s\S]*?Test Phase 5<\/a>\s*<\/div>/m;
if (code.match(regex)) {
    code = code.replace(regex, '');
    fs.writeFileSync(filepath, code);
    console.log("Successfully removed Web3 from index.html");
}
