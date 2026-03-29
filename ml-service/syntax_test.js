const fs = require('fs');
const vm = require('vm');
try {
  const code = fs.readFileSync('c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js', 'utf8');
  const script = new vm.Script(code);
  console.log("SYNTAX IS PERFECT!");
} catch (e) {
  console.log("SYNTAX ERROR:", e.message);
}
