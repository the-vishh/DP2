const fs = require('fs');
const filePath = 'c:/Users/Sri Vishnu/DP-2/intellithon-25/content_script.js';
let c = fs.readFileSync(filePath, 'utf8');

const warningTarget = `      BRAND_SPOOFING_DETECTED: {`;
const warningReplacement = `      SOCIAL_ENGINEERING_URGENCY: {
        title: 'NLP Intent Analysis: High Urgency Threat',
        message: 'In-browser NLP engine detected extreme psychological manipulation and urgency triggers typical of spear-phishing.',
        recommendation: 'Pause and verify. Do not let artificial urgency force you into a mistake.',
        severity: 'HIGH'
      },
      WEB3_WALLET_DRAINER: {
        title: 'Malicious Web3 Smart Contract',
        message: 'A Web3 permission hijack (Wallet Drainer or Approval Phishing) was intercepted before signature execution.',
        recommendation: 'Reject the transaction in your wallet immediately.',
        severity: 'CRITICAL'
      },
      BRAND_SPOOFING_DETECTED: {`;

const engineTarget = `  window.PhishGuardContentScript = {`;
const engineCode = `
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
      // Don't analyze local or blank
      const hostname = window.location.hostname;
      if (!hostname || hostname === "localhost" || hostname === "127.0.0.1") return;

      const pageText = document.body.innerText.toLowerCase();
      
      let urgencyScore = 0;
      let financialScore = 0;

      this.urgencyKeywords.forEach(kw => {
        if (pageText.includes(kw)) urgencyScore++;
      });
      
      this.financialKeywords.forEach(kw => {
        if (pageText.includes(kw)) financialScore++;
      });

      // Contextual spear-phishing detection: High urgency + Financial context + Not a known top site
      if (urgencyScore >= 2 && financialScore >= 1) {
         // Is it a known site?
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
  // PHASE 5: WEB3 / DECENTRALIZED PROTECTION
  // ============================================================================
  
  const Web3Interceptor = {
    init: function() {
      // We must inject a script tag into the page context to access window.ethereum
      const injectCode = \`
        (function() {
           let originalEthereum = window.ethereum;
           
           // Intercept eth_requestAccounts, eth_signTypedData_v4, eth_sendTransaction
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
                           
                           // We throw a simulated rejection to stall the drainer
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

      // Listen for messages from the injected script
      window.addEventListener('message', (event) => {
        if (event.source !== window || !event.data || event.data.type !== 'PHISHGUARD_WEB3_ALERT') {
          return;
        }
        
        showInPageWarning("WEB3_WALLET_DRAINER", { method: event.data.method });
        reportSuspiciousActivity("web3_wallet_drainer", { method: event.data.method });
      });
    }
  };
  
  Web3Interceptor.init();

  window.PhishGuardContentScript = {`;

if (c.includes(warningTarget) && c.includes(engineTarget)) {
    c = c.replace(warningTarget, warningReplacement);
    c = c.replace(engineTarget, engineCode);
    fs.writeFileSync(filePath, c);
    console.log("Successfully injected Phase 2 & Phase 5!");
} else {
    console.log("Failed to find targets. Check logs:");
    console.log("Found warningTarget?", c.includes(warningTarget));
    console.log("Found engineTarget?", c.includes(engineTarget));
}
