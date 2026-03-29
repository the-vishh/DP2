const fs = require('fs');
const filePath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let c = fs.readFileSync(filePath, 'utf8');

const engineTarget = `  window.PhishGuardContentScript = {`;
const warningTarget = `      WEB3_WALLET_DRAINER: {`;
const warningReplacement = `      HOMOGRAPH_ATTACK: {
        title: 'Cryptographic URL Spoof (Punycode)',
        message: 'The URL contains Cyrillic or Greek characters disguised as standard English letters to trick you into trusting it.',
        recommendation: 'Exit site immediately. It is not the real domain.',
        severity: 'CRITICAL'
      },
      OBFUSCATION_BOMB: {
        title: 'Obfuscated Payload Detected',
        message: 'Massive blocks of encrypted JavaScript were found, commonly used by exploit kits and advanced phishing to hide their operations.',
        recommendation: 'Close tab. Code is actively attempting to evade security scanners.',
        severity: 'HIGH'
      },
      WEB3_WALLET_DRAINER: {`;

const engineCode = `
  // ============================================================================
  // PHASE 3: CRYPTOGRAPHIC & DNS FORENSICS
  // ============================================================================

  const CryptographicEngine = {
    init: function() {
      this.detectHomographAttacks();
    },

    detectHomographAttacks: function() {
      const hostname = window.location.hostname;
      
      // Look for multiple non-ASCII characters mixing with ASCII to form a fake brand name
      // e.g., "applе.com" where the e is Cyrillic (U+0435)
      
      const mixedScriptRegex = /(?:[A-Za-z]+[^A-Za-z0-9.\\-][A-Za-z]+)|(?:[^A-Za-z0-9.\\-]+[A-Za-z]+)|(?:[A-Za-z]+[^A-Za-z0-9.\\-]+)/;
      const cyrillicRegex = /[\\u0400-\\u04FF\\u0500-\\u052F]/;
      
      if (hostname.includes('xn--') || (cyrillicRegex.test(hostname) && /[a-z]/i.test(hostname))) {
        showInPageWarning("HOMOGRAPH_ATTACK", { url: hostname });
        reportSuspiciousActivity("cryptographic_homograph", { hostname: hostname });
      }
    }
  };

  CryptographicEngine.init();

  // ============================================================================
  // PHASE 4: ANTI-EVASION & SANDBOXING (THE "INVISIBLE" THREATS)
  // ============================================================================

  const AntiEvasionEngine = {
    init: function() {
      if (document.readyState === "complete") {
        this.scanForObfuscation();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.scanForObfuscation(), 2000));
      }
    },

    scanForObfuscation: function() {
      // Find massive unreadable scripts (often eval blocks or huge base64 arrays) 
      const scripts = document.querySelectorAll('script:not([src])');
      let maxBlockSize = 0;
      let evalCount = 0;
      
      scripts.forEach(s => {
        const text = s.innerText || s.textContent || "";
        
        // Count eval() or window['eval']
        const localEvalMatch = text.match(/eval\\s*\\(/g);
        if (localEvalMatch) evalCount += localEvalMatch.length;
        
        // Look for dense unspaced blocks common in packers like JSFuck or Obfuscator.io
        const denseBlocks = text.split(/\\s+/);
        for (let b of denseBlocks) {
          if (b.length > maxBlockSize) maxBlockSize = b.length;
        }
      });
      
      // An unspaced continuous block of > 8,000 characters is highly unusual for organic JS
      // More than 5 eval() calls in an inline script is also very suspicious
      if (maxBlockSize > 8000 || evalCount > 5) {
         showInPageWarning("OBFUSCATION_BOMB", { maxBlock: maxBlockSize, evalCount: evalCount });
         reportSuspiciousActivity("anti_evasion_obfuscator", { maxBlock: maxBlockSize, evals: evalCount });
      }
    }
  };

  AntiEvasionEngine.init();

  window.PhishGuardContentScript = {`;

if (c.includes(warningTarget) && c.includes(engineTarget)) {
    c = c.replace(warningTarget, warningReplacement);
    c = c.replace(engineTarget, engineCode);
    fs.writeFileSync(filePath, c);
    console.log("Successfully injected Phase 3 & Phase 4!");
} else {
    console.log("Failed to find targets for P3 & P4");
}
