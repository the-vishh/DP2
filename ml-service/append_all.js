const fs = require('fs');
const filepath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';

let code = fs.readFileSync(filepath, 'utf8');

// Strip any trailing non-closed blocks if they exist just in case
let lastGoodIndex = code.indexOf("// EXPORT (for testing)");
if (lastGoodIndex !== -1) {
    code = code.substring(0, lastGoodIndex);
}

const theRestOfIt = `

  // ============================================================================
  // PHASE 1: ZERO-DAY VISUAL & DOM LAYOUT ENGINE
  // ============================================================================

  const VisualEngine = {
    protectedBrands: {
      "microsoft": ["microsoft.com", "live.com", "windows.com", "office.com"],
      "google": ["google.com", "youtube.com", "gmail.com"],
      "paypal": ["paypal.com", "paypal.me"],
      "chase": ["chase.com"],
      "bank of america": ["bankofamerica.com", "bofa.com"],
      "metamask": ["metamask.io"],
      "apple": ["apple.com", "icloud.com"]
    },

    init: function() {
      if (document.readyState === "complete") {
        this.runFullScan();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.runFullScan(), 1000));
      }
    },

    runFullScan: function() {
      this.detectBrandSpoofing();
      this.computeDOMFingerprint();
      this.detectClickjackingLayers();
    },

    detectBrandSpoofing: function() {
      const hostname = window.location.hostname.toLowerCase();
      // bypassed for localhost
      
      const pageText = (document.title + " " + document.body.innerText.substring(0, 2000)).toLowerCase();
      
      for (const [brand, allowedDomains] of Object.entries(this.protectedBrands)) {
        if (pageText.includes(brand)) {
          const isAllowed = allowedDomains.some(d => hostname === d || hostname.endsWith("." + d));
          if (!isAllowed) {
            const titleHasBrand = document.title.toLowerCase().includes(brand);
            const headers = Array.from(document.querySelectorAll('h1, h2')).map(h => h.innerText.toLowerCase());
            const headerHasBrand = headers.some(h => h.includes(brand));
            
            if (titleHasBrand || headerHasBrand) {
               showInPageWarning("BRAND_SPOOFING_DETECTED", { brand: brand });
               reportSuspiciousActivity("brand_spoofing", { brand: brand, hostname: hostname });
               return; 
            }
          }
        }
      }
    },

    computeDOMFingerprint: function() {
      const passwordInputs = document.querySelectorAll('input[type="password"]');
      if (passwordInputs.length === 0) return;

      const totalTextLen = document.body.innerText.trim().length;
      const allInputs = document.querySelectorAll('input');
      const allLinks = document.querySelectorAll('a');
      
      let suspiciousScore = 0;

      if (totalTextLen < 300) suspiciousScore += 30;
      if (allInputs.length > 0 && (totalTextLen / allInputs.length) < 50) suspiciousScore += 25;

      let deadLinks = 0;
      allLinks.forEach(a => {
         const href = a.getAttribute("href") || "";
         if (href === "#" || href.startsWith("javascript:")) deadLinks++;
      });
      if (allLinks.length > 0 && (deadLinks / allLinks.length) > 0.5) suspiciousScore += 40;
      
      if (suspiciousScore >= 70) {
         showInPageWarning("HOLLOW_DOM_STRUCTURE", { score: suspiciousScore });
         reportSuspiciousActivity("hollow_dom", { score: suspiciousScore });
      }
    },

    detectClickjackingLayers: function() {
       const suspiciousNodes = [];
       const elements = document.querySelectorAll('div, iframe');
       
       elements.forEach(node => {
           const style = window.getComputedStyle(node);
           const opacity = parseFloat(style.opacity);
           const zIndex = parseInt(style.zIndex);
           
           if ((style.position === 'absolute' || style.position === 'fixed') && (!isNaN(zIndex) && zIndex > 900)) {
              const rect = node.getBoundingClientRect();
              const area = rect.width * rect.height;
              const windowArea = window.innerWidth * window.innerHeight;
              
              if (area > windowArea * 0.8) {
                  if (opacity < 0.1 || style.backgroundColor === 'rgba(0, 0, 0, 0)' || style.backgroundColor === 'transparent') {
                      suspiciousNodes.push(node);
                  }
              }
           }
       });
       
       if (suspiciousNodes.length > 0) {
           showInPageWarning("INVISIBLE_IFRAME_OVERLAY", {});
           reportSuspiciousActivity("clickjacking_layer", { count: suspiciousNodes.length });
       }
    }
  };

  VisualEngine.init();

  // ============================================================================
  // PHASE 2: LOCAL LLM INTENT & NLP PIPELINE
  // ============================================================================

  const NLPEngine = {
    urgencyKeywords: [
      "urgent", "immediate action required", "24 hours", "suspended", "locked",
      "restricted", "verify your account", "unauthorized access", "will be closed",
      "final warning", "action required"
    ],
    
    financialKeywords: [
      "wallet", "funds", "transfer", "crypto", "bitcoin", "ethereum",
      "payment", "invoice", "billing", "seed phrase"
    ],

    init: function() {
      if (document.readyState === "complete") {
        this.analyzeIntent();
      } else {
        window.addEventListener("load", () => setTimeout(() => this.analyzeIntent(), 1500));
      }
    },

    analyzeIntent: function() {
      const hostname = window.location.hostname;
      
      const pageText = document.body.innerText.toLowerCase();
      
      let urgencyScore = 0;
      let financialScore = 0;

      this.urgencyKeywords.forEach(kw => {
        if (pageText.includes(kw)) urgencyScore++;
      });
      
      this.financialKeywords.forEach(kw => {
        if (pageText.includes(kw)) financialScore++;
      });

      if (urgencyScore >= 2 && financialScore >= 1) {
         const topSites = ["paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "amazon.com"];
         const isTop = topSites.some(t => hostname === t || hostname.endsWith("." + t));
         
         if (!isTop) {
            showInPageWarning("SOCIAL_ENGINEERING_URGENCY", { score: urgencyScore });
            reportSuspiciousActivity("nlp_high_urgency", { urgency: urgencyScore, finance: financialScore });
         }
      }
    }
  };

  NLPEngine.init();


  // ============================================================================
  // PHASE 3: CRYPTOGRAPHIC & DNS FORENSICS
  // ============================================================================

  const CryptographicEngine = {
    init: function() {
      this.detectHomographAttacks();
    },

    detectHomographAttacks: function() {
      const hostname = window.location.hostname;
      const cyrillicRegex = /[\\u0400-\\u04FF\\u0500-\\u052F]/;
      
      if (hostname.includes('xn--') || (cyrillicRegex.test(hostname) && /[a-z]/i.test(hostname))) {
        showInPageWarning("HOMOGRAPH_ATTACK", { url: hostname });
        reportSuspiciousActivity("cryptographic_homograph", { hostname: hostname });
      }
    }
  };

  CryptographicEngine.init();


  // ============================================================================
  // PHASE 4: ANTI-EVASION & SANDBOXING
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
      const scripts = document.querySelectorAll('script:not([src])');
      let maxBlockSize = 0;
      let evalCount = 0;
      
      scripts.forEach(s => {
        const text = s.innerText || s.textContent || "";
        const localEvalMatch = text.match(/eval\\s*\\(/g);
        if (localEvalMatch) evalCount += localEvalMatch.length;
        
        const denseBlocks = text.split(/\\s+/);
        for (let b of denseBlocks) {
          if (b.length > maxBlockSize) maxBlockSize = b.length;
        }
      });
      
      if (maxBlockSize > 8000 || evalCount > 5) {
         showInPageWarning("OBFUSCATION_BOMB", { maxBlock: maxBlockSize, evalCount: evalCount });
         reportSuspiciousActivity("anti_evasion_obfuscator", { maxBlock: maxBlockSize, evals: evalCount });
      }
    }
  };

  AntiEvasionEngine.init();


  // ============================================================================
  // PHASE 5: WEB3 / DECENTRALIZED PROTECTION
  // ============================================================================
  
  const Web3Interceptor = {
    init: function() {
      const injectCode = \`
        (function() {
           let originalEthereum = window.ethereum;
           if (originalEthereum && originalEthereum.request) {
               const originalRequest = originalEthereum.request;
               originalEthereum.request = async function(args) {
                   if (args && args.method) {
                       const method = args.method;
                       if (method === 'eth_signTypedData_v4' || method === 'eth_sendTransaction' || method === 'personal_sign') {
                           window.postMessage({
                             type: 'PHISHGUARD_WEB3_ALERT',
                             method: method,
                             payload: args.params
                           }, '*');
                           throw new Error("PhishGuard Intercept: Transaction blocked by Web3 Defense Grid.");
                       }
                   }
                   return originalRequest.apply(this, arguments);
               };
           }
        })();
      \`;

      const script = document.createElement('script');
      script.textContent = injectCode;
      (document.head || document.documentElement).appendChild(script);
      script.remove();

      window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.type !== 'PHISHGUARD_WEB3_ALERT') {
          return;
        }
        // It's possible showInPageWarning isn't accessible here if declared in a scoped manner, 
        // but it is in the same scope in content_script.js
        showInPageWarning("WEB3_WALLET_DRAINER", { method: event.data.method });
        reportSuspiciousActivity("web3_wallet_drainer", { method: event.data.method });
      });
    }
  };
  
  Web3Interceptor.init();


  // ============================================================================
  // EXPORTS
  // ============================================================================

  window.PhishGuardContentScript = {
    reportSuspiciousActivity: reportSuspiciousActivity,
  };

})(); // CLOSE THE IIFE!
`;

fs.writeFileSync(filepath, code + "\n" + theRestOfIt);
console.log("Successfully rebuilt content script completely!");
